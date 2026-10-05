import { readKnowledgeProjection } from "../src/qa/src/knowledge-reader.js";
import { MemoryIndex } from "../src/qa/src/q2-retrieval.js";
import { classifyIntent } from "../src/qa/src/q1-intent.js";
import { buildRetrievalRequest } from "../src/qa/src/cli.js";
import { synthesizeAnswer } from "../src/qa/src/q4-answer.js";

async function main():Promise<void>{
  const preview=await readKnowledgeProjection({sqlitePath:process.env.SQLITE_PATH??"./var/safetrace.sqlite"});
  const kinds:Record<string,number>={};for(const e of preview.evidence)kinds[e.kind]=(kinds[e.kind]??0)+1;
  const reasons:Record<string,number>={};for(const r of preview.rejected)reasons[r.reason]=(reasons[r.reason]??0)+1;
  console.log(JSON.stringify({mode:"readonly-knowledge-preview",chunks:preview.chunks.length,by_kind:kinds,rejected:preview.rejected.length,rejection_reasons:reasons,
    event_watermark:preview.watermark,fingerprint:preview.fingerprint,model_calls:0,business_writes:0,vector_writes:0},null,2));
  if(process.argv.includes("--ask")){
    const question=process.argv.slice(process.argv.indexOf("--ask")+1).join(" ");if(!question.trim())throw new Error("--ask requires a question");
    const index=new MemoryIndex();await index.upsert(preview.chunks);
    const plan=classifyIntent({session_id:"preview",turn_id:"preview",text:question});
    const evidence=await index.search(buildRetrievalRequest(question,plan,"tr_knowledge_preview"));
    const answer=await synthesizeAnswer(question,plan,evidence);
    console.log(JSON.stringify({mode:"template-only",answer,citation_count:answer.citations.length},null,2));
  }
}
main().catch(error=>{console.error("knowledge preview failed: "+(error instanceof Error?error.message:String(error)));process.exitCode=1;});
