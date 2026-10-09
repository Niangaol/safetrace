/** Live, read-only GPU sanity/A-B runner. Intentionally excluded from npm test network calls. */
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { createJevPaperReviewer, parseJevChoiceAnswer } from "../src/enrich/src/jev-paper-review.js";
import type { PaperReviewRequest } from "../src/enrich/src/stepfun-paper-review.js";

async function main() {
  const fixturePath = process.argv.find(arg => arg.startsWith("--fixture="))?.slice("--fixture=".length) ?? "fixtures/jev-paper-ab.v1.json";
  const fixture = JSON.parse(await readFile(fixturePath, "utf8"));
  const manifest = JSON.parse(await readFile("third_party/open-jev-models/manifest.json", "utf8"));
  const baseUrl = process.env.JEV_BASE_URL ?? "http://127.0.0.1:8791";
  const endpoint = new URL(baseUrl);
  if (!['127.0.0.1','localhost','[::1]'].includes(endpoint.hostname) || endpoint.protocol !== 'http:') throw new Error('GPU evaluator only accepts loopback HTTP');
  const health = await fetch(baseUrl + "/health", { signal: AbortSignal.timeout(10000) }).then(r => {if(!r.ok)throw new Error('Jev health failed');return r.json()}) as {status:string;model:string;method:string};
  if (health.status !== 'ready' || health.method !== 'lora_decision_head') throw new Error('Real trained decision head is not ready');
  const rows: unknown[] = [];
  for (const c of fixture.cases) {
    for (const variant of ['normal','candidate-order-reversed','state-blind']) {
      const request: PaperReviewRequest = {trace_id:'tr_jev_ab', intel_id:c.id, query:variant === 'state-blind' ? 'No vulnerability report is provided.' : c.query,
        papers:[{paper_id:'ab:'+c.id,source:'arxiv',title:c.title,relevance_score:0.5,confidence:0.5}], paper_summaries:{['ab:'+c.id]:c.summary}};
      let raw: unknown;
      const fetcher: typeof fetch = async (input, init) => {
        if (String(input) !== baseUrl + '/v1/systemone') throw new Error('Unexpected inference URL');
        let body = JSON.parse(String(init?.body));
        if (variant === 'candidate-order-reversed') body.questions.relevance.criteria = Object.fromEntries(Object.entries(body.questions.relevance.criteria).reverse());
        const res = await fetch(input,{...init,body:JSON.stringify(body),redirect:'error'});
        if (!res.ok) throw new Error('Jev inference HTTP '+res.status);
        raw = await res.json();
        const r = raw as {model:string;metadata:Record<string,unknown>};
        if (r.model !== health.model || r.metadata.method !== 'lora_decision_head' || r.metadata.checkpoint_sha256 !== manifest.checkpoint_sha256 || r.metadata.base_revision !== manifest.base_revision || r.metadata.code_commit !== manifest.code_revision || r.metadata.device !== 'cuda:0') throw new Error('GPU/model provenance mismatch');
        return Response.json(raw);
      };
      const start = performance.now();
      const outcome = await createJevPaperReviewer({baseUrl,modelId:'Open-Jev-2B@'+manifest.model_revision,timeoutMs:120000,fetchImpl:fetcher})(request);
      const parsed = parseJevChoiceAnswer(raw,{questionId:"relevance",keys:["related","unrelated","uncertain"]});
      rows.push({id:c.id,label:c.label,variant,outcome,answer:parsed,response:raw,elapsed_ms:Math.round(performance.now()-start)});
      console.log(JSON.stringify({id:c.id,variant,label:c.label,choice:parsed.choice,p_related:parsed.probabilities.related,status:outcome.status}));
    }
  }
  const report = {at:new Date().toISOString(),evaluation_kind:fixture.evidence_kind,note:fixture.note,health,manifest,business_writes:0,rows};
  const out = resolve(process.argv.find(arg => arg.startsWith('--output='))?.slice('--output='.length) ?? 'tmp/jev-paper-ab-result.json');
  await mkdir(dirname(out),{recursive:true}); await writeFile(out,JSON.stringify(report,null,2));
  console.log(JSON.stringify({report:out,cases:fixture.cases.length,requests:rows.length,business_writes:0}));
}
void main().catch(error=>{console.error(error);process.exitCode=1});
