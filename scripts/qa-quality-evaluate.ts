/** Offline quality probe. No server, gateway, embeddings or business-store writers. */
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { Answer, EvidenceChunk, RetrievalResponse } from '@safetrace/shared';
import { MemoryIndex } from '../src/qa/src/q2-retrieval.js';
import { classifyIntent } from '../src/qa/src/q1-intent.js';
import { buildRetrievalRequest } from '../src/qa/src/cli.js';
import { synthesizeAnswer } from '../src/qa/src/q4-answer.js';
import { naturalConclusion } from './natural-answer.js';
export interface Fact { id:string; description:string; pattern:string; sources:string[] }
export interface QualityCase { id:string; category:string; question:string; expected:{abstain:boolean;facts:Fact[];stale_warning?:boolean;conflict_disclosure?:boolean;forbidden_patterns?:string[]} }
export interface Reference { mode:string; evaluation_now:string; provenance:string; chunks:EvidenceChunk[]; cases:QualityCase[] }
const hash=(text:string | Uint8Array)=>createHash('sha256').update(text).digest('hex');
export function scoreQuestion(item:QualityCase,answer:Answer,evidence:RetrievalResponse) {
 // Remove exact echoed question: query text is not evidence or an actual answer.
 const actual=answer.text_md.split(item.question).join('');
 const checks:Array<{dimension:string;pass:boolean;reason:string}>=[{dimension:'abstention',pass:answer.abstained===item.expected.abstain,reason:item.expected.abstain?'Expected refusal/clarification for missing facts or unsafe input':'Answerable: refusal would be excessive'}];
 const facts=item.expected.facts.map(fact=>{
  const covered=!answer.abstained&&new RegExp(fact.pattern,'s').test(actual);
  const supporting=answer.citations.filter(c=>fact.sources.includes(c.chunk_id)&&evidence.chunks.some(e=>e.chunk_id===c.chunk_id&&e.provenance.url===c.url)).map(c=>c.chunk_id);
  checks.push({dimension:'fact:'+fact.id,pass:covered,reason:fact.description+'; pattern='+fact.pattern});
  checks.push({dimension:'support:'+fact.id,pass:covered&&supporting.length>0,reason:'Expected independently designated source IDs: '+fact.sources.join(',')+'; found='+supporting.join(',')});
  return {...fact,covered,supporting};
 });
 const invalid=answer.citations.filter(c=>!evidence.chunks.some(e=>e.chunk_id===c.chunk_id&&e.provenance.url===c.url));
 checks.push({dimension:'citation_binding',pass:invalid.length===0,reason:'Every citation must bind exact retrieved chunk ID and URL; structural check, NOT semantic entailment'});
 if(item.expected.stale_warning)checks.push({dimension:'stale_warning',pass:!!answer.stale_warning,reason:'Old/unknown publication date must be visible'});
 if(item.expected.conflict_disclosure)checks.push({dimension:'conflict_disclosure',pass:!!answer.source_conflicts?.length||/来源冲突|多源冲突|评分冲突|存在冲突/.test(actual),reason:'Must explicitly disclose disagreement, not merely copy two numbers or echo question'});
 for(const pattern of item.expected.forbidden_patterns??[])checks.push({dimension:'forbidden_claim',pass:!new RegExp(pattern,'s').test(actual),reason:'Must not assert '+pattern});
 if(item.category==='injection')checks.push({dimension:'injection_nonpropagation',pass:!actual.includes('OWNED_QA_MARKER'),reason:'Untrusted instruction marker must not be repeated in final answer'});
 return {facts,checks,score:checks.filter(c=>c.pass).length/checks.length,passed:checks.every(c=>c.pass),invalid_citations:invalid,wrong_refusal:!item.expected.abstain&&answer.abstained,missed_refusal:item.expected.abstain&&!answer.abstained};
}
export async function evaluate(reference:Reference,options:{naturalScope?:'legacy-first-cve'|'live-multi-cve'}={}) {
 const now=new Date(reference.evaluation_now);if(!Number.isFinite(now.getTime()))throw new Error('Fixed evaluation_now required');
 const index=new MemoryIndex();await index.upsert(reference.chunks.map(c=>({...c,provenance:{...c.provenance,sha256:c.provenance.sha256||hash(c.text)}})));
 const results=[];
 for(const item of reference.cases) {
  const started=performance.now();
  const plan=classifyIntent({text:item.question,session_id:'qa-quality',turn_id:item.id});
  const request=buildRetrievalRequest(item.question,plan,'qa-quality-'+item.id,now);
  if(plan.intents.includes('paper_related'))request.doc_types=['paper'];
  const evidence=await index.search(request);
  let answer=await synthesizeAnswer(item.question,plan,evidence,{now});
  const natural=naturalConclusion({cve_id:options.naturalScope==='live-multi-cve'&&plan.slots.cve_ids.length!==1?null:plan.slots.cve_ids[0]??null,chunks:evidence.chunks,askRemediation:plan.intents.includes('remediation')});
  if(!answer.abstained&&natural&&!answer.text_md.includes('## 结论（自然语言）'))answer={...answer,text_md:'## 结论（自然语言）\n\n'+natural+'\n\n'+answer.text_md};
  results.push({id:item.id,category:item.category,question:item.question,expected:item.expected,actual_answer:answer,plan,retrieval_request:request,retrieved_chunks:evidence.chunks,latency_ms:performance.now()-started,...scoreQuestion(item,answer,evidence)});
 }
 const latencies=results.map(r=>r.latency_ms).sort((a,b)=>a-b), percentile=(p:number)=>latencies[Math.max(0,Math.ceil(latencies.length*p)-1)]??0;
 const facts=results.flatMap(r=>r.facts);
 return {metadata:{mode:reference.mode,runner_wiring:options.naturalScope??'legacy-first-cve',answer_mode:'template',retrieval_mode:'bm25-lite-v1',evaluation_now:reference.evaluation_now,model_calls:0,business_writes:0,vector_writes:0,network_calls:0,scope:'Direct production Q1/MemoryIndex/Q4/naturalConclusion functions; NOT HTTP/live-reader/guidance/baseline enrichment end-to-end. No runtime checkpoint test.',provenance:reference.provenance,limitations:['Synthetic contract probe, NOT competition accuracy','Fact regex coverage may be verbatim evidence copying, not reasoning quality','Per-fact source binding is a checkable proxy; full semantic citation entailment needs human review','No human-annotated paper relevance pool: paper recall not measured','Single warm process latency, no HTTP/model/Qdrant/end-to-end SLA measurement','BM25 max-normalized score is not calibrated relevance']},aggregate:{questions:results.length,fully_passing:results.filter(r=>r.passed).length,mean_check_score:results.reduce((s,r)=>s+r.score,0)/results.length,facts_expected:facts.length,facts_covered:facts.filter(f=>f.covered).length,facts_with_expected_source:facts.filter(f=>f.covered&&f.supporting.length).length,wrong_refusals:results.filter(r=>r.wrong_refusal).length,missed_refusals:results.filter(r=>r.missed_refusal).length,latency_ms:{p50:percentile(.5),p95:percentile(.95),max:latencies.at(-1)??0}},results};
}
export function markdown(report:Awaited<ReturnType<typeof evaluate>>) {
 const lines=['# QA quality contract probe','','NOT competition accuracy; NOT a paper recall metric.','',JSON.stringify(report.metadata,null,2),'','## Aggregate','',JSON.stringify(report.aggregate,null,2)];
 for(const row of report.results)lines.push('','## '+row.id+' — '+row.category,'',row.question,'','Expected: '+JSON.stringify(row.expected),'','Score '+row.score.toFixed(3)+'; pass='+row.passed+'; latency_ms='+row.latency_ms.toFixed(3),'','### Checks','',...row.checks.map(c=>'- '+(c.pass?'PASS':'FAIL')+' '+c.dimension+': '+c.reason),'','### Citations','',JSON.stringify(row.actual_answer.citations,null,2),'','### Actual answer','',row.actual_answer.text_md);
 return lines.join('\n')+'\n';
}
async function main() {
 const args=process.argv.slice(2),value=(flag:string,fallback:string)=>args.includes(flag)?args[args.indexOf(flag)+1]??fallback:fallback;
 if(args.includes('--capture-sqlite')) {
  const sqlitePath=resolve(value('--capture-sqlite','var/safetrace.sqlite'));
  const output=resolve(value('--output','docs/evidence/qa-quality/readonly-snapshot'));
  const beforeHash=hash(await readFile(sqlitePath));
  const { readKnowledgeProjection }=await import('../src/qa/src/knowledge-reader.js');
  const capturedAt=new Date().toISOString();
  const projection=await readKnowledgeProjection({sqlitePath,...(args.includes('--payload-root')?{payloadRoots:[resolve(value('--payload-root','tmp/ingest-cache'))]}:{})});
  const afterHash=hash(await readFile(sqlitePath));
  const snapshot={mode:'readonly-captured-projection',captured_at:capturedAt,source_sqlite:sqlitePath,read_only:true,model_calls:0,network_calls:0,business_writes:0,vector_writes:0,event_watermark:projection.watermark,projection_fingerprint:projection.fingerprint,db_bytes_unchanged:beforeHash===afterHash,db_sha256_before:beforeHash,db_sha256_after:afterHash,corpus_sha256:hash(JSON.stringify(projection.chunks)),chunks:projection.chunks,rejected:projection.rejected,limitations:'Corpus capture only. No automatically generated gold answers and no factual score for real corpus until independent human labels are authored. Snapshot DB byte equality is a before/after observation, not concurrent write proof.'};
  await mkdir(dirname(output),{recursive:true});await writeFile(output+'.json',JSON.stringify(snapshot,null,2)+'\n');
  const rejectionReasons:Record<string,number>={};
  for(const rejected of projection.rejected) {
   // Static projection failures are safe; filesystem/adapter exception details are redacted.
   const reason=/^[A-Za-z][A-Za-z0-9 _/;,().-]{0,180}$/.test(rejected.reason)&&!/(?:[A-Za-z]:|https?:|[\\]|[.][.])/.test(rejected.reason)?rejected.reason:'other_redacted_'+hash(rejected.reason).slice(0,12);
   rejectionReasons[reason]=(rejectionReasons[reason]??0)+1;
  }
  const compact={mode:snapshot.mode,captured_at:capturedAt,read_only:true,event_watermark:projection.watermark,projection_fingerprint:projection.fingerprint,corpus_sha256:snapshot.corpus_sha256,chunk_count:projection.chunks.length,rejected_count:projection.rejected.length,rejection_reasons:rejectionReasons,db_sha256_before:beforeHash,db_sha256_after:afterHash,db_bytes_unchanged:beforeHash===afterHash,model_calls:0,network_calls:0,business_writes:0,vector_writes:0,limitations:snapshot.limitations};
  await writeFile(output+'.metadata.json',JSON.stringify(compact,null,2)+'\n');
  console.log(JSON.stringify(compact,null,2));return;
 }
 const referencePath=resolve(value('--reference','fixtures/qa-quality/reference.v1.json'));
 const raw=await readFile(referencePath,'utf8'),reference=JSON.parse(raw) as Reference;
 const report={reference_sha256:hash(raw),...(await evaluate(reference,{naturalScope:args.includes('--live-natural-scope')?'live-multi-cve':'legacy-first-cve'}))};
 const output=resolve(value('--output','docs/evidence/qa-quality/latest'));
 await mkdir(dirname(output),{recursive:true});
 await writeFile(output+'.json',JSON.stringify(report,null,2)+'\n');await writeFile(output+'.md',markdown(report));
 console.log(JSON.stringify({output,reference_sha256:report.reference_sha256,aggregate:report.aggregate},null,2));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)main().catch(error=>{console.error(error);process.exitCode=1;});
