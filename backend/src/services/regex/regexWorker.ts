/**
 * Worker-thread entry for RegexWorkerPool (services/regex/workerPool.ts).
 *
 * Runs the operations that execute a regex SIEMBox has not vetted, or analyze
 * one, off the main thread: if a match backtracks for minutes, only this thread
 * is stuck, and the pool terminates it. Everything imported here is DB-free and
 * pure (the same modules the catalog CLI validators run), so a worker starts in
 * a few tens of milliseconds and never touches the database.
 *
 * Protocol: { id, op, payload } in, { id, ok: true, result } or
 * { id, ok: false, error } out. One task at a time per worker.
 */
import { parentPort } from 'worker_threads';
import { runParser } from '../parser/runParser';
import { runSelfTests } from '../parser/parserPortable';
import { recommendParsers } from '../parser/parserRecommendations';
import { recommendRules } from '../rules/detectionRecommendations';
import { countSigmaMatches } from '../sigma/sigmaCompat';
import { checkSignature } from '../applications/signatureCheck';
import { analysisFlags, needsFuzzPass, recheckParams, verdictFromDiagnostics, type RegexVerdict } from '../parser/redos';

type Handler = (payload: any) => unknown | Promise<unknown>;

let recheckCheck: ((source: string, flags: string, params?: Record<string, unknown>) => Promise<any>) | null | undefined;

/** recheck's async check, loaded on the first scan (most workers never scan). */
function getRecheck(): typeof recheckCheck {
  if (recheckCheck === undefined) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports -- lazy, optional load: only scan tasks need it
      const mod = require('recheck');
      recheckCheck = typeof mod.check === 'function' ? mod.check : null;
    } catch {
      recheckCheck = null;
    }
  }
  return recheckCheck;
}

async function scan(payload: { source: string; flags: string; timeoutMs: number }): Promise<RegexVerdict> {
  const check = getRecheck();
  if (!check) return { status: 'unknown', detail: 'the recheck analyzer is not installed' };
  try {
    // The CLI's analysis (parser/redos.ts RECHECK_ANALYSIS: 'auto', then the
    // fuzz pass when the automaton said safe) and parameters, each pass with
    // recheck's own time budget; the pool's hard timeout is the backstop.
    const flags = analysisFlags(payload.flags);
    let result = await check(payload.source, flags, recheckParams('auto', payload.timeoutMs));
    if (needsFuzzPass(result)) result = await check(payload.source, flags, recheckParams('fuzz', payload.timeoutMs));
    return verdictFromDiagnostics(result);
  } catch (e) {
    return { status: 'unknown', detail: e instanceof Error ? e.message : String(e) };
  }
}

const handlers: Record<string, Handler> = {
  runParser: (p) => runParser(p.parser, p.message, p.ctx ?? {}),
  selfTest: (p) => runSelfTests(p.parser),
  recommendParsers: (p) => recommendParsers(p.samples, p.candidates),
  recommendRules: (p) => recommendRules(p.sources, p.candidates),
  sigmaMatches: (p) => countSigmaMatches(p.sources, p.work),
  // An application signature a caller wrote: validated, compiled and tested here (Sets travel as arrays).
  checkSignature: (p) =>
    checkSignature(p.doc, {
      ...p.ctx,
      parserNames: p.ctx.parserNames ? new Set(p.ctx.parserNames) : null,
      skipRegex: new Set(p.ctx.skipRegex ?? []),
    }),
  scan,
};

parentPort?.on('message', async (msg: { id: number; op: string; payload: unknown }) => {
  const handler = handlers[msg?.op];
  try {
    if (!handler) throw new Error(`unknown operation "${msg?.op}"`);
    const result = await handler(msg.payload);
    parentPort!.postMessage({ id: msg.id, ok: true, result });
  } catch (e) {
    parentPort!.postMessage({ id: msg.id, ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});
