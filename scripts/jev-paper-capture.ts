/** Capture a bounded set of real arXiv candidates for read-only Jev comparison. */
import { mkdir, writeFile } from "node:fs/promises";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { searchPapers, anchoredPapers, buildPaperQuery } from "../src/enrich/src/f1-papers.js";

async function main() {
  const snapshot = readIntelIndexSnapshot(process.env.SQLITE_PATH ?? './var/safetrace.sqlite');
  const selected = ['log4j','langflow','chromium'].map(product => [...snapshot.accepted.values()].find(e => buildPaperQuery(e.item) === product)).filter(e => !!e);
  const cases: unknown[] = [];
  await mkdir('tmp/jev-paper-capture', {recursive:true});
  for (const entry of selected) {
    const item = entry!.item;
    const query = buildPaperQuery(item);
    const context = [item.title,item.entities.product ?? '',item.cve_ids.join(' ')].join(' ');
    const result = await searchPapers(query,{offline:false,relevanceContext:context,traceId:'tr_jev_capture'});
    if (result.degraded_to || !result.source_evidence) throw new Error('arXiv probe degraded; no fixture results accepted');
    const accepted = new Set(anchoredPapers(item,result.papers,result.paper_records).map(p=>p.paper_id));
    await writeFile('tmp/jev-paper-capture/'+item.intel_id+'.xml',result.source_evidence.text);
    for (const p of result.papers.slice(0,3)) {
      const record = result.paper_records?.[p.paper_id];
      if (!record || record.title !== p.title) continue;
      cases.push({id:item.intel_id+':'+p.paper_id,label:'unlabeled',query:context,title:p.title,summary:record.summary,
        arxiv_id:p.paper_id,source_url:record.url,receipt_sha256:result.source_evidence.sha256,
        captured_at:new Date().toISOString(),intel_event_id:entry!.intel_event.event_id,
        rule_kept:accepted.has(p.paper_id),rule_relevance:p.relevance_score});
    }
  }
  if (!cases.length) throw new Error('No real metadata candidates captured');
  await writeFile('tmp/jev-paper-capture/candidates.json',JSON.stringify({version:'1.0',evidence_kind:'live-arxiv-unlabeled',note:'Captured raw arXiv metadata and current DQ-released intel. No human ground truth; compare suggestions only, not accuracy.',cases},null,2));
  console.log(JSON.stringify({cases:cases.length,products:selected.length,business_writes:0,output:'tmp/jev-paper-capture/candidates.json'}));
}
void main().catch(error=>{console.error(error);process.exitCode=1});
