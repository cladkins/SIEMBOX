// SIEMBox shipper-side log-discovery agent.
//
// This is bundled (by build-discovery-agent.mjs, via esbuild) into the single
// standalone file ../discovery-agent.js, which the managed shipper runs with
// Node (see shipper-managed.sh's run_discovery_job). It reads ONE discovery job
// as JSON on stdin:
//
//   { "mode": "passive|active|full", "cidrs": ["192.168.1.0/24", ...],
//     "probePlan": { "ports": [...], "httpPaths": [...], "mdnsServices": [...] } }
//
// runs the EXACT same plan-driven probe pipeline the backend uses
// (backend/src/services/logDiscovery/probePipeline.ts), and prints the observed
// per-host signals as a JSON array on stdout. It does no fingerprint matching
// and touches no database -- the backend matches the signals it returns. Pure
// Node stdlib (the winston logger is shimmed at bundle time), so the bundle runs
// on a stock Node with nothing to install.
import { gatherSignals } from '../../backend/src/services/logDiscovery/probePipeline';

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

async function main(): Promise<void> {
  const raw = (await readStdin()).trim();
  if (!raw) throw new Error('no job on stdin');
  const job = JSON.parse(raw);

  const mode = job.mode === 'passive' || job.mode === 'active' || job.mode === 'full' ? job.mode : 'full';
  const cidrs = asStringArray(job.cidrs);
  const plan = {
    ports: Array.isArray(job?.probePlan?.ports)
      ? job.probePlan.ports.filter((n: unknown): n is number => Number.isInteger(n))
      : [],
    httpPaths: asStringArray(job?.probePlan?.httpPaths),
    mdnsServices: asStringArray(job?.probePlan?.mdnsServices),
  };

  const signals = await gatherSignals({
    mode,
    cidrs,
    plan,
    log: (level, message) => process.stderr.write(`[discovery-agent] ${level}: ${message}\n`),
  });

  process.stdout.write(JSON.stringify(signals));
}

main().catch((err) => {
  process.stderr.write(`[discovery-agent] fatal: ${err?.message || err}\n`);
  process.exit(1);
});
