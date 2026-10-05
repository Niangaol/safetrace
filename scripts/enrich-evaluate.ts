/** Import-safe CLI: nothing runs and nothing is written when imported. */
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadEvaluationReference, runEnrichmentEvaluation } from "../src/enrich/src/evaluation.js";

export async function main(args: string[] = process.argv.slice(2)): Promise<void> {
  // Install the repository transport guard even if the caller omitted --import.
  const guardUrl = new URL("./test-network-guard.mjs", import.meta.url).href;
  await import(guardUrl);
  if (args.length > 2 || (args.length > 0 && (args[0] !== "--reference" || !args[1]))) {
    throw new Error("Usage: node --import tsx scripts/enrich-evaluate.ts [--reference reference.json]");
  }
  const reference = await loadEvaluationReference(args[1] ? resolve(args[1]) : undefined);
  const report = await runEnrichmentEvaluation(reference);
  // stdout only. No output path, production write switch, model provider or collector.
  process.stdout.write(JSON.stringify(report, null, 2) + "\n");
}
const invoked = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (invoked) main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
