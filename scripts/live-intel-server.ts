import { allowedLocalHost } from "./local-api-security.js";
import { ModelSettingsController } from "./model-settings-controller.js";
import { RuntimeSettingsStore } from "../src/gateway/src/runtime-settings-store.js";
import { LocalModelRuntime } from "../src/gateway/src/local-model-runtime.js";
import { ActivityStream } from "./activity-stream.js";
import { resolve, dirname } from "node:path";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { readLiveKnowledgeView, liveIntelItem, liveEvidenceView } from "../src/qa/src/live-knowledge-view.js";
import { readRemediationEvidence } from "../src/qa/src/remediation-reader.js";
import { loadBaselineIndex, baselineForItem, baselineNarrative, type BaselineIndex } from "../src/qa/src/baseline-reader.js";
import { naturalConclusion } from "./natural-answer.js";
import { knowledgeGeneration } from "../src/qa/src/knowledge-generation.js";
import type { LiveKnowledgeView } from "../src/qa/src/live-knowledge-view.js";
import { MemoryIndex } from "../src/qa/src/q2-retrieval.js";
import { classifyIntent } from "../src/qa/src/q1-intent.js";
import { buildRetrievalRequest } from "../src/qa/src/cli.js";
import { synthesizeAnswer } from "../src/qa/src/q4-answer.js";
import { nextId } from "@safetrace/shared";
import { readIngestDiagnostics } from "./ingest-diagnostics.js";

function json(res:ServerResponse,status:number,body:unknown){res.writeHead(status,{"content-type":"application/json; charset=utf-8","cache-control":"no-store"});res.end(JSON.stringify(body));}
function event(res:ServerResponse,data:unknown){if(!res.destroyed)res.write("data: "+JSON.stringify(data)+"\n\n");}
async function question(req:IncomingMessage):Promise<string>{
  if(!(req.headers["content-type"]??"").startsWith("application/json"))throw new Error("JSON question required");let bytes=0;const chunks:Buffer[]=[];
  for await(const chunk of req){const b=Buffer.from(chunk);bytes+=b.length;if(bytes>16384)throw new Error("question body exceeds 16KiB");chunks.push(b);}
  const body=JSON.parse(Buffer.concat(chunks).toString("utf8")) as {question?:unknown};if(typeof body.question!=="string"||!body.question.trim()||body.question.length>2000)throw new Error("question must be 1–2000 characters");return body.question.trim();
}
function localOrigin(req:IncomingMessage):boolean {
  if(!allowedLocalHost(req))return false;
  const origin=req.headers.origin;if(!origin)return req.headers["sec-fetch-site"]!=="cross-site";
  try{return ["127.0.0.1","localhost","[::1]"].includes(new URL(origin).hostname);}catch{return false;}
}
export function createLiveIntelServer(options:{sqlitePath:string;payloadRoots?:readonly string[];readView?:()=>Promise<LiveKnowledgeView>;modelSettings?:ModelSettingsController}):Server{
  let qaCount=0;
  const activity=new ActivityStream(options.sqlitePath),settings=options.modelSettings;
  let cached: { key:string; view:LiveKnowledgeView } | undefined;
  let baselineCache: { key:string; index:BaselineIndex } | undefined;
  const readBaseline=async():Promise<BaselineIndex>=>{const key=await knowledgeGeneration(options);if(baselineCache?.key===key)return baselineCache.index;const index=await loadBaselineIndex({sqlitePath:options.sqlitePath,payloadRoots:options.payloadRoots});baselineCache={key,index};return index;};
  let building: { key:string; promise:Promise<LiveKnowledgeView> } | undefined;
  const read=options.readView??(async()=>{
    const key=await knowledgeGeneration(options);
    if(cached?.key===key)return cached.view;
    if(building?.key===key)return building.promise;
    const promise=readLiveKnowledgeView(options).then(async view=>{if(await knowledgeGeneration(options)!==key)throw new Error("knowledge changed while constructing cached snapshot; retry");cached={key,view};return view;}).finally(()=>{if(building?.promise===promise)building=undefined;});
    building={key,promise};return promise;
  });
  const server=createServer(async(req,res)=>{
    if(!localOrigin(req)){json(res,403,{error:{message:"only local UI origins may access the readonly intelligence API"},data_mode:"live"});return;}
    const url=new URL(req.url??"/","http://127.0.0.1"),path=url.pathname;
    try{
      if(settings && await settings.handle(req,res,url))return;
      if(req.method==="GET"&&path==="/api/v1/activity/stream"){activity.attach(req,res,url);return;}
      const isChat=req.method==="POST"&&path==="/api/v1/qa/chat";
      let q: string | undefined;
      if(isChat) { try { q=await question(req); } catch { json(res,400,{error:{message:"invalid JSON question or size"},data_mode:"live"}); return; } }
      if(req.method!=="GET"&&!isChat){json(res,405,{error:{message:"readonly API"},data_mode:"live"});return;}
      const view=await read();
      if(path==="/api/v1/health") {json(res,200,{status:"ok",data_mode:"live",read_only:true,automatic_ingestion:false,model_calls_enabled:settings?.mode()!==undefined&&settings.mode()!=="template",qa_mode:settings?.mode()??"template",retrieval_mode:"bm25",intel_count:view.intel.length,source_count:new Set(view.raw.map(r=>r.source_id)).size,chunk_count:view.projection.chunks.length,verified_artifact_count:view.projection.evidence.filter(e=>e.kind!=="source").length,historical_enrichment_records:view.recorded.size,snapshot_seq:view.projection.watermark});return;}
      if(path==="/api/v1/ingest/diagnostics"){json(res,200,readIngestDiagnostics(options.sqlitePath));return;}
      if(path==="/api/v1/metrics/overview"){
        const paper=[...view.verified.values()].filter(r=>r.artifacts.papers?.length).length,cvss=[...view.verified.values()].filter(r=>r.artifacts.score_assessment).length;
        json(res,200,{data_mode:"live",read_only:true,qa_mode:settings?.mode()??"template",collect:{raw_items:view.raw.length,vulns:view.intel.length,merge_ratio:null,sources:new Set(view.raw.map(r=>r.source_id)).size},latency:{p50_seconds:null,p95_seconds:null,sla_6h_ratio:null},
          enrich:{coverage_ratio:view.intel.length?view.verified.size/view.intel.length:0,records:view.verified.size,recorded_unverified:view.recorded.size-view.verified.size,dimensions:2,degraded_ratio:null,per_dimension:{paper:{records:paper,coverage_ratio:view.intel.length?paper/view.intel.length:0,confidence_avg:null,degraded_ratio:null,mock_ratio:null},cvss:{records:cvss,coverage_ratio:view.intel.length?cvss/view.intel.length:0,confidence_avg:null,degraded_ratio:null,mock_ratio:null}}},knowledge:{chunks:view.projection.chunks.length},agents:{runs:qaCount,failed:null},cost:{total_cny:null,daily_budget_cny:null,degraded:true,breakdown:{}},snapshot_seq:view.projection.watermark});return;
      }
      if(path==="/api/v1/collect/status") {json(res,200,{data_mode:"live",read_only:true,queue_depth:null,watermarks:[],note:"archive snapshot, not collector health or realtime SLA"});return;}
      if(path==="/api/v1/vulns"){
        const page=Number(url.searchParams.get("page")??"1"),size=Number(url.searchParams.get("page_size")??"20"),needle=(url.searchParams.get("q")??"").toLowerCase(),severity=url.searchParams.get("severity")??"",poc=url.searchParams.get("has_poc")??"",sort=url.searchParams.get("sort")??"published_at";
        if(!Number.isSafeInteger(page)||page<1||!Number.isSafeInteger(size)||size<1||size>100||!["","true","false"].includes(poc)||!["published_at","fetched_at","cvss_score"].includes(sort)){json(res,400,{error:{message:"invalid filters"},data_mode:"live"});return;}
        const rows=view.intel.map(i=>liveIntelItem(view,i)).filter(i=>(!needle||[i.title,i.description,i.cve_id].some(s=>s.toLowerCase().includes(needle)))&&(!severity||i.severity===severity)&&poc!=="true");
        rows.sort((a,b)=>sort==="cvss_score"?(b.cvss_score??-1)-(a.cvss_score??-1):String(b[sort as "published_at"|"fetched_at"]??"").localeCompare(String(a[sort as "published_at"|"fetched_at"]??"")));
        json(res,200,{items:rows.slice((page-1)*size,page*size),total:rows.length,page,page_size:size,data_mode:"live",read_only:true});return;
      }
      const itemRoute=/^\/api\/v1\/vulns\/([^/]+)(\/evidence)?$/.exec(path);
      if(itemRoute){
        const item=view.intel.find(i=>i.intel_id===decodeURIComponent(itemRoute[1]!));
        if(!item){json(res,404,{error:{message:"intelligence absent or latest DQ not released"},data_mode:"live"});return;}
        if(!itemRoute[2]){const index=await readBaseline();const baseline=baselineForItem(index,item,view.verified.has(item.intel_id),view.states.filter(state=>state.intel_id===item.intel_id).map(state=>({dimension:state.dimension,status:state.status})));json(res,200,{...liveIntelItem(view,item),baseline:baseline.facts,gaps:baseline.gaps});return;}
        const base=liveEvidenceView(view,item),guidance=await readRemediationEvidence({...options,intelIds:[item.intel_id],limit:1});
        const extra=guidance.evidence.length?[{dimension:"remediation",value:{guidance:guidance.evidence.map(e=>e.artifact)},source:[...new Set(guidance.evidence.map(e=>e.artifact.source_id))],
          evidence:guidance.evidence.map(e=>({evidence_id:e.chunk.chunk_id,source:e.artifact.source_id,url:e.artifact.source_url,snippet:e.chunk.text,artifact_sha256:e.chunk.provenance.sha256,original_sha256:e.artifact.source_sha256,parent_lineage_ids:e.parent_lineage_ids})),
          confidence:null,model:"rule",agent:"f5",version:1,mock:false,degraded_to:null,storage:"readonly-source-derived; not frozen EnrichmentResult",validation:"vendor/agency statement, not verified fix",created_at:null}]:[];
        json(res,200,{...base,enrichments:[...base.enrichments,...extra],derived_guidance_count:guidance.evidence.length});return;
      }
      if(isChat&&q!==undefined){
        res.writeHead(200,{"content-type":"text/event-stream; charset=utf-8","cache-control":"no-cache, no-transform","x-accel-buffering":"no"});
        const trace=nextId("tr");const index=new MemoryIndex();
        activity.publish({trace_id:trace,intel_id:null,stage:"answer",status:"running",at:new Date().toISOString(),label:"qa.question_received",details:{reason:"问题已接收；不展示问题正文"}});
        if(res.destroyed)return;
        const plan=classifyIntent({text:q,session_id:nextId("sess"),turn_id:nextId("turn")});
        const selectedIds=plan.intents.includes("remediation")?view.intel.filter(item=>item.cve_ids.some(cve=>plan.slots.cve_ids.includes(cve))).slice(0,5).map(item=>item.intel_id):[];
        const guidance=selectedIds.length?await readRemediationEvidence({...options,intelIds:selectedIds,limit:5}):undefined;
        await index.upsert([...(guidance?.chunks??[]),...view.projection.chunks]);
        event(res,{event:"stage",stage:"plan",intent:plan.intents[0]??null,data_mode:"live"});
        const retrievalRequest=buildRetrievalRequest(q,plan,trace);
        if(plan.intents.includes("paper_related"))retrievalRequest.doc_types=["paper"];
        const evidence=await index.search(retrievalRequest);event(res,{event:"stage",stage:"retrieve",hit:evidence.chunks.length});
        activity.publish({trace_id:trace,intel_id:null,stage:"knowledge",status:"success",at:new Date().toISOString(),label:"qa.retrieval",details:{artifact_count:evidence.chunks.length}});
        event(res,{event:"stage",stage:"generate",answer_mode:settings?.mode()??"template"});
        const baselineIndex=await readBaseline().catch(()=>undefined);
        const provenCves=new Set(view.intel.filter(i=>view.verified.has(i.intel_id)).flatMap(i=>i.cve_ids));
        const gapLine=(()=>{
          if(!baselineIndex||!plan.slots.cve_ids.length)return null;
          try{
            const item={cve_ids:plan.slots.cve_ids,source_ids:[]} as any;
            const {gaps}=baselineForItem(baselineIndex,item,plan.slots.cve_ids.some(cve=>provenCves.has(cve)),view.states.filter(state=>plan.slots.cve_ids.includes((view.intel.find(i=>i.intel_id===state.intel_id)?.cve_ids??[])[0]??"")).map(state=>({dimension:state.dimension,status:state.status})));
            const missing=gaps.filter(g=>g.status==="missing");
            if(!missing.length)return null;
            return "维度缺口：" + missing.map(g=>{const label=({cvss_v31:"CVSS v3.1 官方评分",paper:"论文关联",epss:"EPSS 利用概率",remediation:"修复版本"} as Record<string,string>)[g.dimension]??g.dimension;return label+"（"+g.reason+"）";}).join("；") + "。以上缺口不代表无风险，也不按 0 分处理。";
          }catch{return null;}
        })();
        const natural=naturalConclusion({cve_id:plan.slots.cve_ids[0]??null,chunks:evidence.chunks,remediation:(guidance?.evidence??[]).map(item=>item.artifact),askRemediation:plan.intents.includes("remediation")});
                let finalReview:import("./final-answer-review.js").FinalReview={status:"skipped",reason:"模板模式、拒答或安全门禁回退未执行模型复核"};
        let modelUiPlan:import("./intelligent-ui.js").UiPlan|null=null;
        let answerMode="template",answerModel="q4-template-v1",modelFallback=false,modelAttempts=0;let answer;
        try{const selected=settings?await settings.synthesizer(()=>{modelAttempts++;},review=>{finalReview=review;},()=>event(res,{event:"stage",stage:"check"}),ui=>{modelUiPlan=ui;}):undefined;
          const modelEvidence=selected?.synth?settings!.modelEvidence(evidence,[...view.projection.chunks,...(guidance?.chunks??[])]):evidence;
          answer=await synthesizeAnswer(q,plan,modelEvidence,selected?.synth?{synth:selected.synth,synthesizer:{provider:selected.provider,model_id:selected.model_id,model_version:"runtime-settings"}}:{});
          if(selected?.synth && !answer.abstained && !answer.degraded_to){answerMode=selected.mode;answerModel=selected.model_id;if(gapLine)answer={...answer,text_md:answer.text_md+"\n\n"+gapLine};}else if(selected?.synth&&!answer.abstained){answerMode="template_fallback";modelFallback=true;}
        }catch{answer=await synthesizeAnswer(q,plan,evidence);answerMode="template_fallback";modelFallback=true;}
        // 红线：拒答就是拒答。自然语言结论只能加成在“作答”的答案上；
        // abstained 时再叠加一段自信结论会自相矛盾（实测出现过），也让“证据不足”的提示失效。
        if(!answer.abstained && !answer.text_md.includes("## 结论（自然语言）")){
          const extra=baselineIndex?baselineNarrative(baselineForItem(baselineIndex,{cve_ids:plan.slots.cve_ids,source_ids:[]} as any,false).facts):null;
          let lead=[natural,natural&&extra&&!/修复版本/.test(natural)?extra:null].filter(Boolean).join("\n\n")||(extra&&!/修复版本/.test(extra)?extra:null);
          if(gapLine)lead=[lead,gapLine].filter(Boolean).join("\n\n");
          if(lead)answer={...answer,text_md:"## 结论（自然语言）\n\n"+lead+"\n\n"+answer.text_md};
        }
        activity.publish({trace_id:trace,intel_id:null,stage:modelFallback?"fallback":"answer",status:modelFallback?"degraded":answer.abstained?"rejected":"success",at:new Date().toISOString(),label:"qa.answer_completed",details:{artifact_count:answer.citations.length,reason:modelFallback?"已回退规则模板；无其它云端自动降级":answer.abstained?"证据不足或保护门禁拒答":"引用已绑定检索证据"}});
        if(res.destroyed)return;
        event(res,{event:"stage",stage:"check"});
        for(const cite of answer.citations){const chunk=evidence.chunks.find(c=>c.chunk_id===cite.chunk_id);event(res,{event:"citation",id:cite.chunk_id,title:chunk?.doc_type??"evidence",url:cite.url,score:chunk?.score_sparse??chunk?.score_dense??0});}
        let uiStatus:import("./intelligent-ui.js").UiStatus={status:"skipped",reason:"拒答或安全筛查未通过，不生成交互组件"};
        if(!answer.abstained&&!(answer.injection_guard?.flags?.length)){
          const {compileUi,ruleUiPlan}=await import("./intelligent-ui.js");
          const useModel=!!modelUiPlan&&!modelFallback;
          let document=useModel?compileUi(modelUiPlan!,evidence,"model"):null;
          const accepted=!!document;
          if(!document)document=compileUi(ruleUiPlan(q,evidence),evidence,"rules");
          // 模型返回空计划 = 本轮用文字回答更合适，状态如实记为 skipped，不当成 accepted
          uiStatus=accepted&&document?.blocks.length?{status:"accepted",reason:"模型只编排白名单组件；显示内容由服务端绑定检索原文"}:accepted?{status:"skipped",reason:"模型未选择交互组件，保持文字回答"}:{status:"fallback",reason:"未取得合法模型组件计划；使用规则布局或文字回答"};
          if(document?.blocks.length)event(res,{event:"ui",document});
        }
        event(res,{event:"token",text:answer.text_md});qaCount++;
        event(res,{event:"done",ui_status:uiStatus,final_review:finalReview,abstained:answer.abstained,confidence:answer.confidence,confidence_kind:"heuristic",degraded:modelFallback,degraded_to:answer.degraded_to??null,data_mode:"live",read_only:true,answer_mode:answerMode,answer_model_id:answerModel,retrieval_mode:"bm25",trace_id:trace,cost_cny:modelAttempts===0?0:null,model_calls:modelAttempts,model_attempts:modelAttempts,snapshot_seq:view.projection.watermark,stale_warning:answer.stale_warning??null});res.end();return;
      }
      json(res,404,{error:{message:"not found"},data_mode:"live"});
    }catch(error){if(res.headersSent){event(res,{event:"error",message:"readonly knowledge snapshot failed; no fixture fallback"});res.end();}else json(res,503,{error:{message:error instanceof Error?error.message:"readonly knowledge unavailable"},data_mode:"live"});}
  });
  server.on("close",()=>{activity.dispose();void settings?.dispose();});
  return server;
}
export async function startLiveIntelServer():Promise<Server>{
  const sqlitePath=process.env.SQLITE_PATH??"./var/safetrace.sqlite";
  const port=Number(process.env.PORT??8000);if(!Number.isSafeInteger(port)||port<1||port>65535)throw new Error("PORT invalid");
  const root=resolve("."),runtime=new LocalModelRuntime({modelsRoots:[process.env.SAFETRACE_MODELS_DIR??resolve(dirname(root),"safetrace-models"),resolve(root,"local-models")],executableCandidates:[process.env.SAFETRACE_LLAMA_SERVER??resolve(root,"third_party/llamacpp/llama-server.exe"),resolve(root,"third_party/llama.cpp/llama-server.exe"),resolve(process.env.LOCALAPPDATA??".","Microsoft/WinGet/Packages/ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe/llama-server.exe")]});
  const settings=new ModelSettingsController({store:new RuntimeSettingsStore(resolve(root,"var/runtime-settings")),runtime});
  const server=createLiveIntelServer({sqlitePath,modelSettings:settings});await new Promise<void>((resolve,reject)=>{server.once("error",reject);server.listen(port,"127.0.0.1",resolve);});
  console.log("SafeTrace readonly intelligence API http://127.0.0.1:"+port+" (business archive readonly; BM25; configured template/cloud/local answers; no automatic collector tasks)");return server;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)void startLiveIntelServer().catch(error=>{console.error(error.message);process.exitCode=1;});
