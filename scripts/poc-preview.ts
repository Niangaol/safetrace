import { readPocCandidates } from "../src/enrich/src/poc-extension.js";
async function main(){
  const ids=(process.argv.find(a=>a.startsWith("--ids="))?.slice("--ids=".length)??"").split(",").filter(Boolean);
  if(!ids.length||ids.some(id=>!/^intel_[A-Za-z0-9_-]+$/.test(id)))throw new Error("Provide --ids=<intel-id>[,<intel-id>]");
  const out=[];
  for(const intelId of ids){
    const r=await readPocCandidates({sqlitePath:process.env.SQLITE_PATH??"./var/safetrace.sqlite",intelId});
    const by:Record<string,number>={};for(const a of r.receipt?.advisories??[])by[a.choice]=(by[a.choice]??0)+1;
    out.push({intel_id:intelId,status:r.status,receipt_id:r.receipt?.receipt_id??null,candidates:r.receipt?.artifacts.length??0,advisory_choices:by,
      candidates_detail:(r.receipt?.artifacts??[]).map(a=>({candidate_id:a.candidate_id,cve_id:a.cve_id,reference_url:a.reference_url,tags:a.reference_tags,evidence_kind:a.evidence_kind}))});
  }
  console.log(JSON.stringify({mode:"readonly-poc-candidates",business_writes:0,network_calls:0,model_calls:0,
    validation:"Advisory-tagged references only; nothing fetched or executed; model advice never confirms exploitability",results:out},null,2));
}
void main().catch(e=>{console.error(e);process.exitCode=1;});