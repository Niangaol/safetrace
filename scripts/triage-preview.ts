import { buildTriageReport, triageDigest } from "../src/enrich/src/triage.js";
async function main(){
  const limit=Number(process.argv.find(a=>a.startsWith("--limit="))?.slice("--limit=".length)??50);
  const report=buildTriageReport(process.env.SQLITE_PATH??"./var/safetrace.sqlite",{...(Number.isSafeInteger(limit)?{limit}:{})});
  console.log(JSON.stringify({mode:"readonly-triage",...report,digest:triageDigest(report),
    by_tier:report.entries.reduce<Record<string,number>>((m,e)=>{m[e.tier]=(m[e.tier]??0)+1;return m},{})},null,2));
}
void main().catch(e=>{console.error(e);process.exitCode=1;});