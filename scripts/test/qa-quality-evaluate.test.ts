import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import type { Answer, RetrievalResponse } from '@safetrace/shared';
import { evaluate, scoreQuestion, markdown, type Reference, type QualityCase } from '../qa-quality-evaluate.js';
const raw=await readFile(new URL('../../fixtures/qa-quality/reference.v1.json',import.meta.url),'utf8');
const reference=JSON.parse(raw) as Reference;
const question:QualityCase={id:'test',category:'fact',question:'What is expected?',expected:{abstain:false,facts:[{id:'fact',description:'known independently authored fact',pattern:'EXPECTED_FACT',sources:['known']}]}};
const evidence:RetrievalResponse={query_id:'test',trace_id:'test',embedder_model_id:'bm25-lite-v1',schema_version:'1.0',retrieval_ms:0,chunks:[{chunk_id:'known',doc_type:'vuln_advisory',text:'EXPECTED_FACT',trust:'trusted',provenance:{url:'https://qa.invalid/known',section:'test',sha256:'0'.repeat(64)}}]};
const answer=(text:string,citations:Answer['citations']=[],abstained=false):Answer=>({session_id:'test',turn_id:'test',text_md:text,citations,reasoning_chain:[],confidence:abstained?0:.8,abstained});
test('24 independent questions remain frozen across production fixes',()=>{
 assert.equal(createHash('sha256').update(raw).digest('hex'),'1e9f07cef10e032cb1ba4270ecc7bfa0c74a2cd60b79c4e083e1d63358febec2');
 assert.equal(reference.cases.length,24);assert.equal(new Set(reference.cases.map(c=>c.id)).size,24);
 for(const item of reference.cases)for(const fact of item.expected.facts){assert.ok(fact.sources.length);for(const source of fact.sources)assert.ok(reference.chunks.some(c=>c.chunk_id===source));new RegExp(fact.pattern);}
});
test('covered facts without independent source citation fail',()=>{
 const score=scoreQuestion(question,answer('EXPECTED_FACT'),evidence);assert.equal(score.facts[0]!.covered,true);assert.equal(score.passed,false);
});
test('exact expected source binding permits fact check',()=>{
 assert.equal(scoreQuestion(question,answer('EXPECTED_FACT',[{chunk_id:'known',url:'https://qa.invalid/known'}]),evidence).passed,true);
});
test('wrong URL or nonexistent citation never supports fact',()=>{
 for(const cite of [{chunk_id:'known',url:'https://qa.invalid/wrong'},{chunk_id:'invented',url:'https://qa.invalid/known'}]){const score=scoreQuestion(question,answer('EXPECTED_FACT',[cite]),evidence);assert.equal(score.passed,false);assert.equal(score.invalid_citations.length,1);}
});
test('echoed query is not scored as actual factual answer',()=>{
 const item={...question,question:'EXPECTED_FACT'};assert.equal(scoreQuestion(item,answer('针对EXPECTED_FACT未解释'),evidence).facts[0]!.covered,false);
});
test('refusal evidence snippets never count as answered facts',()=>{
 const result=scoreQuestion(question,answer('EXPECTED_FACT',[],true),evidence);assert.equal(result.facts[0]!.covered,false);assert.equal(result.wrong_refusal,true);
 const refusal={...question,expected:{abstain:true,facts:[]}};assert.equal(scoreQuestion(refusal,answer('nothing'),evidence).missed_refusal,true);
});
test('injection marker propagation and forbidden cross-CVE claim fail',()=>{
 const item={...question,category:'injection',expected:{abstain:true,facts:[],forbidden_patterns:['wrong CVE score']}};
 assert.equal(scoreQuestion(item,answer('OWNED_QA_MARKER wrong CVE score',[],true),evidence).passed,false);
});
test('end-to-end offline function probe outputs all actual answers and bounded metrics',async()=>{
 const report=await evaluate(reference);assert.equal(report.results.length,24);assert.equal(report.metadata.model_calls,0);assert.equal(report.metadata.network_calls,0);
 assert.ok(report.aggregate.mean_check_score>=0&&report.aggregate.mean_check_score<=1);assert.ok(report.aggregate.latency_ms.p95>=report.aggregate.latency_ms.p50);
 for(const row of report.results){assert.ok(row.actual_answer.text_md);assert.ok(row.checks.length>=2);assert.ok(row.latency_ms>=0);}
 assert.ok(markdown(report).includes('### Actual answer'));assert.ok(report.metadata.limitations.some(x=>x.includes('paper recall not measured')));
});
