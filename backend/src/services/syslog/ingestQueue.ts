/**
 * Bounded work queue for log ingestion.
 *
 * Before this, every incoming datagram / TCP chunk started its own un-capped
 * async chain: under load (or whenever the database slowed down) thousands of
 * handlers piled up in memory, each racing a 2 s connection timeout, and the
 * ones that lost were silently dropped -- with no accounting and unbounded
 * memory growth in the meantime.
 *
 * This replaces that with explicit, observable overload behaviour:
 *
 *   - at most `concurrency` messages are processed at once;
 *   - up to `maxQueued` more wait in memory (FIFO);
 *   - UDP uses trySubmit(): when full the message is dropped AND COUNTED --
 *     UDP has no backpressure channel, so the honest options are a bounded
 *     buffer or an unbounded one;
 *   - TCP / HTTP use admit()/submit(): they WAIT for room (strictly FIFO), so
 *     the caller can pause its socket and let TCP flow control slow the sender
 *     down -- nothing is lost.
 *
 * Invariant (tested): every task handed to trySubmit() is either run to
 * completion or counted in `dropped`. Task failures never kill a worker.
 *
 * This sits on the per-message hot path, so it is deliberately allocation-lean:
 * no per-task promise unless the caller asked to wait for completion, and an
 * O(1) deque instead of Array#shift (which is O(n) on a large backlog).
 */

export type IngestTask = () => Promise<void> | void;

export interface IngestQueueOptions {
  /** Max tasks running at once. */
  concurrency: number;
  /** Max tasks waiting beyond the running ones. */
  maxQueued: number;
  /** Safety net: tasks are expected to handle their own errors; this sees any that escape. */
  onTaskError?: (err: unknown) => void;
}

export interface IngestQueueStats {
  /** Tasks running right now. */
  active: number;
  /** Tasks accepted and waiting for a worker. */
  queued: number;
  /** Callers of admit()/submit() still waiting for room (not yet accepted). */
  blocked: number;
  /** Tasks refused by trySubmit() because the queue was full. */
  dropped: number;
  /** Tasks that ran to completion (success or failure). */
  processed: number;
  /** Of those, how many threw/rejected. */
  failed: number;
}

interface Entry {
  task: IngestTask;
  /** Only set when a caller asked to wait for completion (submit()). */
  done?: () => void;
}

interface Waiter {
  entry: Entry;
  /** Called once the entry has been ACCEPTED. */
  accepted: () => void;
}

/** FIFO with O(1) push/shift: a head index over an array, compacted once the dead prefix dominates. */
class Deque<T> {
  private buf: Array<T | undefined> = [];
  private head = 0;

  get length(): number {
    return this.buf.length - this.head;
  }

  push(value: T): void {
    this.buf.push(value);
  }

  shift(): T | undefined {
    if (this.head >= this.buf.length) return undefined;
    const value = this.buf[this.head];
    this.buf[this.head++] = undefined; // don't pin the task's closure
    if (this.head === this.buf.length) {
      this.buf.length = 0;
      this.head = 0;
    } else if (this.head >= 1024 && this.head * 2 >= this.buf.length) {
      this.buf = this.buf.slice(this.head);
      this.head = 0;
    }
    return value;
  }
}

const ACCEPTED: Promise<void> = Promise.resolve();

export class IngestQueue {
  private active = 0;
  private readonly backlog = new Deque<Entry>();
  private readonly waiting = new Deque<Waiter>();
  private readonly idleWaiters: Array<() => void> = [];
  private dropped = 0;
  private processed = 0;
  private failed = 0;

  constructor(private readonly opts: IngestQueueOptions) {
    if (!Number.isInteger(opts.concurrency) || opts.concurrency < 1) {
      throw new RangeError('IngestQueue concurrency must be a positive integer');
    }
    if (!Number.isInteger(opts.maxQueued) || opts.maxQueued < 0) {
      throw new RangeError('IngestQueue maxQueued must be a non-negative integer');
    }
  }

  private isFull(): boolean {
    // While a worker is free the backlog is necessarily empty and a new task
    // starts at once, so "full" only ever means: every worker busy AND the
    // backlog at its cap.
    return this.active >= this.opts.concurrency && this.backlog.length >= this.opts.maxQueued;
  }

  /** Room for one more right now, with nobody ahead of the caller. */
  private hasRoom(): boolean {
    return this.waiting.length === 0 && !this.isFull();
  }

  /**
   * Accept without waiting. Returns false -- and counts the drop -- if the
   * queue is full. For UDP-style sources that cannot be slowed down.
   */
  trySubmit(task: IngestTask): boolean {
    if (!this.hasRoom()) {
      this.dropped++;
      return false;
    }
    this.accept({ task });
    return true;
  }

  /**
   * Wait for room, then accept the task. Resolves as soon as the task is
   * ACCEPTED (queued or started), not when it finishes. Callers are admitted
   * strictly in call order. For sources that can be backpressured: pause the
   * socket until this resolves.
   */
  admit(task: IngestTask): Promise<void> {
    if (this.hasRoom()) {
      this.accept({ task });
      return ACCEPTED;
    }
    return new Promise<void>((accepted) => this.waiting.push({ entry: { task }, accepted }));
  }

  /** Like admit(), but resolves when the task has FINISHED. */
  submit(task: IngestTask): Promise<void> {
    return new Promise<void>((done) => {
      const entry: Entry = { task, done };
      if (this.hasRoom()) this.accept(entry);
      else this.waiting.push({ entry, accepted: () => undefined });
    });
  }

  private accept(entry: Entry): void {
    this.backlog.push(entry);
    this.schedule();
  }

  /**
   * Move work forward until nothing more can move: start queued tasks on free
   * workers, then admit blocked callers into whatever room that opened up.
   * Iterative on purpose -- a task that re-enters the queue mid-loop is safe
   * because every step below is a complete state transition.
   */
  private schedule(): void {
    for (;;) {
      while (this.active < this.opts.concurrency && this.backlog.length > 0) {
        this.start(this.backlog.shift()!);
      }
      if (this.waiting.length > 0 && !this.isFull()) {
        const waiter = this.waiting.shift()!;
        this.backlog.push(waiter.entry);
        waiter.accepted();
        continue;
      }
      return;
    }
  }

  private start(entry: Entry): void {
    this.active++;
    let result: Promise<void> | undefined;
    try {
      result = entry.task() as Promise<void> | undefined;
    } catch (err) {
      // A task that throws synchronously. Settle on a fresh microtask so a long
      // run of failing synchronous tasks can't recurse through schedule().
      Promise.reject(err).then(undefined, (e) => this.finish(entry, e, true));
      return;
    }
    if (result && typeof result.then === 'function') {
      result.then(
        () => this.finish(entry),
        (err) => this.finish(entry, err, true)
      );
    } else {
      ACCEPTED.then(() => this.finish(entry));
    }
  }

  private finish(entry: Entry, err?: unknown, failed = false): void {
    if (failed) {
      this.failed++;
      try {
        this.opts.onTaskError?.(err);
      } catch {
        /* an error handler must never take a worker down */
      }
    }
    this.active--;
    this.processed++;
    entry.done?.();
    this.schedule();
    this.notifyIdle();
  }

  private isIdle(): boolean {
    return this.active === 0 && this.backlog.length === 0 && this.waiting.length === 0;
  }

  private notifyIdle(): void {
    if (this.idleWaiters.length === 0 || !this.isIdle()) return;
    for (const wake of this.idleWaiters.splice(0)) wake();
  }

  /**
   * Resolves true once nothing is running, waiting, or waiting to be accepted;
   * false if `timeoutMs` elapses first.
   */
  drain(timeoutMs: number): Promise<boolean> {
    if (this.isIdle()) return Promise.resolve(true);
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        const i = this.idleWaiters.indexOf(wake);
        if (i >= 0) this.idleWaiters.splice(i, 1);
        resolve(false);
      }, timeoutMs);
      const wake = () => {
        clearTimeout(timer);
        resolve(true);
      };
      this.idleWaiters.push(wake);
    });
  }

  stats(): IngestQueueStats {
    return {
      active: this.active,
      queued: this.backlog.length,
      blocked: this.waiting.length,
      dropped: this.dropped,
      processed: this.processed,
      failed: this.failed,
    };
  }
}
