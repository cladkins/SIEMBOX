/**
 * A small, reusable pool of worker threads with a hard wall-clock timeout per
 * task — the bound for work SIEMBox cannot bound any other way.
 *
 * JavaScript regexes backtrack, and V8 offers no time limit on a match: a
 * pattern like ^(a+)+$ against 'a'.repeat(40) + '!' runs for longer than anyone
 * will wait, and while it runs nothing else on that thread does. On the main
 * thread that is the API, syslog ingestion, shipper pushes and every job. So a
 * regex the caller supplies (or one saved before the write-time gate existed)
 * is only ever executed here: when a task outlives its budget the worker is
 * terminated — the one thing that does stop a running match — and replaced,
 * and the caller gets a RegexTimeoutError instead of a stalled process.
 *
 * Workers are created lazily (a pool that is never used costs nothing), handle
 * one task at a time, and are unref'd while idle so they never keep the process
 * alive. Two queues (high before low) let a user's request overtake background
 * work such as the startup scan; a task that waits too long in the queue, or
 * arrives when the queue is full, is refused with RegexPoolBusyError rather than
 * waiting behind work that may itself run to the timeout.
 */
import { Worker, type ResourceLimits } from 'worker_threads';
import * as path from 'path';

/** A task outlived its budget; the worker that ran it was terminated and replaced. */
export class RegexTimeoutError extends Error {
  constructor(
    readonly timeoutMs: number,
    readonly op: string
  ) {
    super(`${op} did not finish within ${timeoutMs} ms and was stopped`);
    this.name = 'RegexTimeoutError';
  }
}

/** The pool is saturated: the queue is full, or the task waited too long for a worker. */
export class RegexPoolBusyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RegexPoolBusyError';
  }
}

/** The operation threw inside the worker, or the worker died under it. */
export class RegexWorkerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RegexWorkerError';
  }
}

export interface PoolOptions {
  /** For log lines and error messages. */
  name: string;
  /** Maximum number of worker threads. */
  size: number;
  /** Default wall-clock budget per task, measured from the moment a worker picks it up. */
  timeoutMs: number;
  /** High-priority tasks allowed to wait for a worker. */
  maxQueue: number;
  /** Background (low-priority) tasks allowed to wait. Default 500. */
  maxLowQueue?: number;
  /** How long a task may wait for a worker before it is refused as busy. */
  maxQueueWaitMs: number;
  /** Worker entry file. Defaults to regexWorker next to this module (.ts under tsx, .js when built). */
  workerFile?: string;
  resourceLimits?: ResourceLimits;
}

export interface RunOptions {
  /** Override the pool's per-task budget. */
  timeoutMs?: number;
  /** 'high' (a person is waiting) runs before 'low' (background work). Default 'high'. */
  priority?: 'high' | 'low';
}

interface Task {
  id: number;
  op: string;
  payload: unknown;
  timeoutMs: number;
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  queueTimer: NodeJS.Timeout | null;
}

interface Slot {
  worker: Worker;
  task: Task | null;
  timer: NodeJS.Timeout | null;
  /** Set once the slot has been removed from the pool (terminated or crashed). */
  dead: boolean;
}

export interface PoolStats {
  workers: number;
  busy: number;
  queued: number;
  completed: number;
  timedOut: number;
  /** Workers terminated and replaced (timeouts and crashes). */
  replaced: number;
}

export function defaultWorkerFile(): string {
  // Under tsx (tests, `npm run dev`) this module is a .ts file and so is the
  // worker. Built, both are .js.
  return path.join(__dirname, `regexWorker${path.extname(__filename) || '.js'}`);
}

/**
 * Start a worker on `file`. A built .js entry is loaded directly. A .ts entry
 * (only under tsx: tests and `npm run dev`) is loaded through a two-line CommonJS
 * bootstrap that registers tsx's require hook first: the ESM loader a worker
 * inherits does not resolve the extensionless imports the backend uses.
 */
function startWorker(file: string, resourceLimits?: ResourceLimits): Worker {
  if (!file.endsWith('.ts')) return new Worker(file, { resourceLimits });
  const bootstrap = `require(${JSON.stringify(require.resolve('tsx/cjs'))}); require(${JSON.stringify(file)});`;
  return new Worker(bootstrap, { eval: true, resourceLimits });
}

export class RegexWorkerPool {
  private readonly slots: Slot[] = [];
  private readonly high: Task[] = [];
  private readonly low: Task[] = [];
  private nextId = 1;
  private closed = false;
  private readonly counters = { completed: 0, timedOut: 0, replaced: 0 };

  constructor(private readonly opts: PoolOptions) {}

  get options(): Readonly<PoolOptions> {
    return this.opts;
  }

  run<T>(op: string, payload: unknown, runOpts: RunOptions = {}): Promise<T> {
    if (this.closed) return Promise.reject(new RegexPoolBusyError(`${this.opts.name} is shut down`));
    const low = runOpts.priority === 'low';
    const cap = low ? (this.opts.maxLowQueue ?? 500) : this.opts.maxQueue;
    if ((low ? this.low : this.high).length >= cap) {
      return Promise.reject(
        new RegexPoolBusyError(`${this.opts.name} is busy (${cap} tasks already waiting); try again shortly`)
      );
    }
    return new Promise<T>((resolve, reject) => {
      const task: Task = {
        id: this.nextId++,
        op,
        payload,
        timeoutMs: runOpts.timeoutMs ?? this.opts.timeoutMs,
        resolve,
        reject,
        queueTimer: null,
      };
      const queue = runOpts.priority === 'low' ? this.low : this.high;
      queue.push(task);
      // Background (low) work may wait as long as it needs; a person's request may not.
      if (runOpts.priority !== 'low') {
        task.queueTimer = setTimeout(() => {
          const i = queue.indexOf(task);
          if (i === -1) return;
          queue.splice(i, 1);
          reject(
            new RegexPoolBusyError(
              `${this.opts.name} is busy (waited ${this.opts.maxQueueWaitMs} ms for a free worker); try again shortly`
            )
          );
        }, this.opts.maxQueueWaitMs);
        task.queueTimer.unref();
      }
      this.dispatch();
    });
  }

  stats(): PoolStats {
    return {
      workers: this.slots.length,
      busy: this.slots.filter((s) => s.task).length,
      queued: this.high.length + this.low.length,
      ...this.counters,
    };
  }

  /** Thread ids of the live workers (tests use this to see a worker replaced). */
  threadIds(): number[] {
    return this.slots.map((s) => s.worker.threadId);
  }

  /** Terminate every worker; queued and running tasks are rejected. */
  async close(): Promise<void> {
    this.closed = true;
    for (const task of [...this.high.splice(0), ...this.low.splice(0)]) {
      if (task.queueTimer) clearTimeout(task.queueTimer);
      task.reject(new RegexPoolBusyError(`${this.opts.name} is shut down`));
    }
    const slots = this.slots.splice(0);
    await Promise.all(
      slots.map(async (slot) => {
        slot.dead = true;
        if (slot.timer) clearTimeout(slot.timer);
        if (slot.task) slot.task.reject(new RegexPoolBusyError(`${this.opts.name} is shut down`));
        slot.task = null;
        await slot.worker.terminate().catch(() => undefined);
      })
    );
  }

  private nextTask(): Task | undefined {
    return this.high.shift() ?? this.low.shift();
  }

  private dispatch(): void {
    if (this.closed) return;
    while (this.high.length + this.low.length > 0) {
      let slot = this.slots.find((s) => !s.task && !s.dead);
      if (!slot) {
        if (this.slots.length >= this.opts.size) return;
        slot = this.spawn();
      }
      const task = this.nextTask()!;
      if (task.queueTimer) clearTimeout(task.queueTimer);
      this.start(slot, task);
    }
  }

  private spawn(): Slot {
    const worker = startWorker(this.opts.workerFile ?? defaultWorkerFile(), this.opts.resourceLimits);
    const slot: Slot = { worker, task: null, timer: null, dead: false };
    worker.unref();
    worker.on('message', (msg: { id: number; ok: boolean; result?: unknown; error?: string }) => {
      const task = slot.task;
      if (!task || msg?.id !== task.id) return;
      this.release(slot);
      this.counters.completed++;
      if (msg.ok) task.resolve(msg.result);
      else task.reject(new RegexWorkerError(msg.error || `${task.op} failed`));
      this.dispatch();
    });
    const died = (reason: string) => {
      if (slot.dead) return;
      const task = slot.task;
      this.remove(slot);
      this.counters.replaced++;
      if (task) task.reject(new RegexWorkerError(`${this.opts.name} worker stopped while running ${task.op}: ${reason}`));
      this.dispatch();
    };
    worker.on('error', (err) => died(err instanceof Error ? err.message : String(err)));
    worker.on('exit', (code) => died(`exited with code ${code}`));
    this.slots.push(slot);
    return slot;
  }

  private start(slot: Slot, task: Task): void {
    slot.task = task;
    // While a task runs, the worker (and the timer) keep the process alive: an
    // awaited result must not be lost to an idle-looking event loop.
    slot.worker.ref();
    slot.timer = setTimeout(() => this.timeout(slot, task), task.timeoutMs);
    slot.worker.postMessage({ id: task.id, op: task.op, payload: task.payload });
  }

  private release(slot: Slot): void {
    if (slot.timer) clearTimeout(slot.timer);
    slot.timer = null;
    slot.task = null;
    slot.worker.unref();
  }

  private timeout(slot: Slot, task: Task): void {
    if (slot.task !== task || slot.dead) return;
    // A running regex cannot be interrupted from outside; terminating the
    // thread is what stops it. A fresh worker takes the slot's place.
    this.remove(slot);
    this.counters.timedOut++;
    this.counters.replaced++;
    task.reject(new RegexTimeoutError(task.timeoutMs, task.op));
    if (!this.closed && this.slots.length < this.opts.size) this.spawn();
    this.dispatch();
  }

  private remove(slot: Slot): void {
    slot.dead = true;
    if (slot.timer) clearTimeout(slot.timer);
    slot.timer = null;
    slot.task = null;
    const i = this.slots.indexOf(slot);
    if (i !== -1) this.slots.splice(i, 1);
    slot.worker.removeAllListeners('message');
    void slot.worker.terminate().catch(() => undefined);
  }
}
