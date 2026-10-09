import { sha256, sha256Json, enrichmentInputHash } from "@safetrace/shared";
import type { EnrichmentResult, EvidenceChunk, IntelItem, LineageRecord, RawDoc, StoredPageSnapshot } from "@safetrace/shared";
import { latestIntelSnapshot } from "./intel-index-plan.js";
import type { IntelIndexEvent } from "./intel-index-plan.js";

export interface KnowledgeEvent extends Omit<IntelIndexEvent, "topic"> {
  topic: IntelIndexEvent["topic"] | "enrich.items";
}
/** QA-owned boundary, deliberately independent of the mutable enrichment sidecar API. */
export interface ArtifactEvidence {
  key: string; // paper:<paper_id> or cvss
  artifactHash: string;
  url: string;
  published_at: string;
  trust: EvidenceChunk["trust"];
  /** Required for authoritative CVSS; identifies the raw record, not the merged intel. */
  raw_ref?: string;
  cve_id?: string;
}
export interface KnowledgeEnrichmentState {
  intel_id: string;
  mode: "live" | "fixture" | "unknown";
  status: "success" | "failed" | "review" | "quarantine";
  inputHash: string;
  inputHashMode?: "full" | "facts";
  resultHash: string;
  enrich_event_id: string;
  lineage_ids: string[];
  artifacts: ArtifactEvidence[];
}
export interface KnowledgeProjectionInput {
  events: readonly KnowledgeEvent[];
  lineage: readonly LineageRecord[];
  enrichment_states: readonly KnowledgeEnrichmentState[];
  /** No filesystem or network implicit reads: caller controls permitted raw references. */
  read_raw_payload: (raw: RawDoc) => Promise<Uint8Array>;
  read_page_snapshot: (hash: string) => Promise<StoredPageSnapshot | undefined>;
  /** Explicit policy applied only after origin/hash proof; default remains untrusted. */
  source_trust?: (raw: RawDoc) => EvidenceChunk["trust"];
}
export interface ProjectedEvidence {
  chunk: EvidenceChunk;
  intel_id: string;
  intel_event_id: string;
  enrich_event_id?: string;
  input_sha256?: string;
  result_sha256?: string;
  kind: "source" | "paper" | "cvss";
  raw_ref?: string;
  original_sha256?: string;
  artifact_sha256?: string;
  text_sha256: string;
  parent_lineage_ids: string[];
}
export interface KnowledgeProjection {
  chunks: EvidenceChunk[];
  evidence: ProjectedEvidence[];
  rejected: Array<{ intel_id: string; scope: string; reason: string }>;
  watermark: number;
  fingerprint: string;
}
function object(v: unknown): Record<string, any> {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("invalid metadata object");
  return v as Record<string, any>;
}
function unit(v: unknown): boolean { return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1; }
function validDq(value: unknown): boolean {
  const d = object(value), scores = object(d.dimension_scores);
  return unit(d.quality_score) && ["structure", "completeness", "consistency", "timeliness", "sourcing"].every(k => unit(scores[k]))
    && Array.isArray(d.flags) && d.flags.every((f: unknown) => typeof f === "string") && typeof d.gate_version === "string" && !!d.gate_version.trim();
}
function stamp(s: string): boolean { return typeof s === "string" && /T.*(?:Z|[+-]\d{2}:\d{2})$/.test(s) && Number.isFinite(Date.parse(s)); }
function publicUrl(s: string): boolean {
  try { const u = new URL(s); return u.protocol === "https:" && !u.username && !u.password && !/^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[|.*\.local$)/i.test(u.hostname); } catch { return false; }
}
function safeLineage(r: LineageRecord): boolean {
  return r.status === "success" && !r.decision?.fallback_to && !r.decision?.review_required && !r.execution?.cached
    && !/fixture|cache|offline/i.test(r.execution?.provider ?? "");
}
function refMatches(refs: LineageRecord["input_refs"], id: string, hash: string): boolean { return refs.some(r => r.id === id && r.sha256 === hash); }
/** Only supported per-record payloads are projected. Unknown adapters fail closed. */
export interface RawKnowledgeRecord { id: string; aliases?: string[]; text: string; published_at: string; metrics: any[] }
function sourceDate(value: unknown): string {
  if (typeof value !== "string" || !value.trim()) return "";
  const normalized = /T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value) ? value : /^\d{4}-\d{2}-\d{2}$/.test(value) ? value + "T00:00:00Z" : value + "Z";
  return Number.isFinite(Date.parse(normalized)) ? new Date(normalized).toISOString() : "";
}
/** Parse each original record, not a merged summary. Unrelated rejected records cannot poison an entire batch. */
export function rawKnowledgeRecords(raw: RawDoc, bytes: Uint8Array): RawKnowledgeRecord[] {
  const data = object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
  if (raw.source_type === "nvd_cve") return (data.vulnerabilities ?? []).flatMap((entry: any) => {
    const c = object(entry.cve); if (/REJECT|RESERVED|DISPUTED/i.test(c.vulnStatus ?? "")) return [];
    return [{ id: c.id, text: (c.descriptions ?? []).filter((d: any) => d.lang === "en").map((d: any) => d.value).join("\n"), published_at: sourceDate(c.published), metrics: Object.values(c.metrics ?? {}).flat().map((m: any) => ({ ...m.cvssData, source_of_score: String(m.source ?? "").toLowerCase() === "nvd@nist.gov" ? "nvd" : m.source && String(m.source).toLowerCase() === String(c.sourceIdentifier ?? "").toLowerCase() ? "cna" : undefined })) }];
  });
  if (raw.source_type === "kev") return (data.vulnerabilities ?? []).map((v: any) => ({ id: v.cveID,
    text: [v.vulnerabilityName, v.shortDescription, v.requiredAction].filter(Boolean).join("\n"), published_at: sourceDate(v.dateAdded), metrics: [] }));
  if (raw.source_type === "vendor_advisory" && raw.source_id === "ubuntu_usn") return (data.notices ?? []).filter((n: any) => !n.is_hidden).map((n: any) => ({
    id: n.id, aliases: Array.isArray(n.cves_ids) ? n.cves_ids : [], text: [n.title,n.summary,n.description,n.instructions].filter(Boolean).join("\n"), published_at: sourceDate(n.published), metrics: [] }));
  if (raw.source_type === "osv") return (typeof data.id === "string" ? [data] : (data.results ?? []).flatMap((r: any) => r.vulns ?? [])).map((v: any) => ({ id: v.id, aliases: v.aliases ?? [], text: [v.summary, v.details].filter(Boolean).join("\n"), published_at: sourceDate(v.published), metrics: [] }));
  if (raw.source_type === "cve_org") {
    if (/REJECT|RESERVED|DISPUTED/i.test(data.cveMetadata?.state ?? "")) return [];
    const c = object(data.containers?.cna); return [{ id: data.cveMetadata?.cveId, text: (c.descriptions ?? []).map((d: any) => d.value).join("\n"), published_at: sourceDate(data.cveMetadata?.datePublished), metrics: (c.metrics ?? []).map((m: any) => ({ ...(m.cvssV3_1 ?? m.cvssV3_0), source_of_score: "cna" })) }];
  }
  throw new Error("unsupported raw source adapter; no merged-summary fallback");
}
const records = rawKnowledgeRecords;

/** Pure snapshot projection. Caller must replace/reconcile indexes, not merely upsert revoked versions. */
export async function projectKnowledgeEvidence(input: KnowledgeProjectionInput): Promise<KnowledgeProjection> {
  let previous = 0;
  const ids = new Set<string>();
  for (const e of input.events) { if (e.seq <= previous || !Number.isSafeInteger(e.seq) || ids.has(e.event_id)) throw new Error("events must have unique identities and strictly ordered positive seq"); previous = e.seq; ids.add(e.event_id); }
  const snapshot = latestIntelSnapshot(input.events.filter((e): e is IntelIndexEvent => e.topic !== "enrich.items" && !(e.topic === "dq.verdicts" && object(e.payload).item_kind === "enriched")));
  const rejected = [...snapshot.rejected].map(([intel_id, reason]) => ({ intel_id, scope: "intel", reason }));
  const evidence: ProjectedEvidence[] = [];
  const byLineage = new Map(input.lineage.map(r => [r.lineage_id, r]));
  const rawRecordCache = new Map<string, { hash: string; parsed: RawKnowledgeRecord[]; byIdentity: Map<string,RawKnowledgeRecord[]> }>();
  const causeRows = new Map<string,LineageRecord[]>(), sourceRows = new Map<string,LineageRecord[]>();
  const rawRows = new Map<string,KnowledgeEvent[]>(), enrichRows = new Map<string,KnowledgeEvent>(), enrichedDqRows = new Map<string,KnowledgeEvent>();
  const stateRows = new Map<string,KnowledgeEnrichmentState[]>(), proofCache = new Map<string,LineageRecord[]>();
  const sourceKey = (trace:string,id:string,type:string,url:string) => JSON.stringify([trace,id,type,url]);
  for (const row of input.lineage) {
    if(row.causation_id) { const group=causeRows.get(row.causation_id)??[];group.push(row);causeRows.set(row.causation_id,group); }
    if(row.source?.source_id && row.source.source_type && row.source.url) {const key=sourceKey(row.trace_id,row.source.source_id,row.source.source_type,row.source.url),group=sourceRows.get(key)??[];group.push(row);sourceRows.set(key,group);}
  }
  for (const event of input.events) {
    if(event.topic === "raw.docs") {const ref=String(object(event.payload).payload_ref),group=rawRows.get(ref)??[];group.push(event);rawRows.set(ref,group);}
    else if(event.topic === "enrich.items") enrichRows.set(String(object(event.payload).intel_id),event);
    else if(event.topic === "dq.verdicts" && object(event.payload).item_kind === "enriched") enrichedDqRows.set(String(object(event.payload).item_id),event);
  }
  for(const state of input.enrichment_states) {const group=stateRows.get(state.intel_id)??[];group.push(state);stateRows.set(state.intel_id,group); }
  if (byLineage.size !== input.lineage.length) throw new Error("duplicate lineage identities");
  const add = (item: IntelItem, event: KnowledgeEvent, kind: ProjectedEvidence["kind"], text: string, url: string, date: string, trust: EvidenceChunk["trust"], hash: string, parents: string[], extra: Partial<ProjectedEvidence> = {}) => {
    const textHash = sha256(text);
    const chunk: EvidenceChunk = { chunk_id: "chunk_" + sha256Json({ event: event.event_id, kind, url, hash, textHash }).slice(0, 40), doc_type: kind === "paper" ? "paper" : kind === "cvss" ? "enrichment" : "vuln_advisory", text, published_at: date, trust, quality_score: snapshot.accepted.get(item.intel_id)!.verdict.quality_score, provenance: { url, section: kind === "source" ? "raw:record" : "artifact:" + kind, sha256: hash } };
    evidence.push({ chunk, intel_id: item.intel_id, intel_event_id: event.event_id, kind, text_sha256: textHash, parent_lineage_ids: [...new Set(parents)], ...extra });
  };
  for (const { item, intel_event, verdict_event } of snapshot.accepted.values()) {
    const fail = (scope: string, error: unknown) => rejected.push({ intel_id: item.intel_id, scope, reason: error instanceof Error ? error.message : String(error) });
    const dqParents = (causeRows.get(verdict_event.event_id) ?? []).filter(r => r.trace_id === verdict_event.trace_id && (safeLineage(r) || (r.status === "degraded" && snapshot.accepted.get(item.intel_id)!.verdict.verdict === "degrade" && !r.decision?.fallback_to && !r.decision?.review_required)) && r.causation_id === verdict_event.event_id && (refMatches(r.input_refs, item.intel_id, sha256Json(item)) || r.output_refs.some(ref => ref.kind === "ReleasedIntelItem" && ref.id === item.intel_id && ref.sha256 === sha256Json(item))) && (refMatches(r.output_refs, item.intel_id, sha256Json(snapshot.accepted.get(item.intel_id)!.verdict)) || refMatches(r.output_refs, "dq:" + item.intel_id, sha256Json(snapshot.accepted.get(item.intel_id)!.verdict)))).map(r => r.lineage_id);
    if (!dqParents.length) { fail("intel", "DQ lineage proof missing"); continue; }
    const sourceRecords = new Map<string, ReturnType<typeof records>>();
    const sourceParents = new Map<string, string[]>();
    for (const raw_ref of new Set(item.raw_refs)) {
      try {
        const candidates = (rawRows.get(raw_ref) ?? []).filter(e => e.seq < intel_event.seq);
        if (candidates.length !== 1) throw new Error("raw reference absent or ambiguous");
        const raw = candidates[0]!.payload as RawDoc;
        if (!item.source_ids.includes(raw.source_id) || !publicUrl(raw.url) || !stamp(raw.fetched_at) || /(?:^|[\/\\])fixtures?(?:[\/\\]|$)/i.test(raw_ref)) throw new Error("raw source identity, URL, timestamp or live reference failed");
        let hash: string, parsed: ReturnType<typeof records>;
        if (raw_ref.startsWith("sqlite-page:")) {
          hash = raw_ref.slice(12); const page = await input.read_page_snapshot(hash);
          if (!/^[a-f0-9]{64}$/.test(hash) || !page || page.content_sha256 !== hash || sha256(page.text) !== hash || page.final_url !== raw.url || !publicUrl(page.source_url) || new URL(page.source_url).host !== new URL(raw.url).host || !page.lineage_ids.length || !stamp(page.fetched_at) || raw.external_id !== hash) throw new Error("page Snapshot hash/URL proof failed");
          if (!item.cve_ids.length || item.cve_ids.some(c => !page.text.includes(c))) throw new Error("page Snapshot CVE mismatch");
          parsed = [{ id: raw.external_id, text: page.text, published_at: item.published_at, metrics: [] }];
        } else {
          const cacheKey = candidates[0]!.event_id;
          let cached = rawRecordCache.get(cacheKey);
          if (!cached) {
            const bytes = await input.read_raw_payload(raw), parsedRecords = records(raw, bytes), byIdentity = new Map<string,RawKnowledgeRecord[]>();
            for(const record of parsedRecords) for(const key of new Set([record.id,...(record.aliases??[])])) { if(typeof key!=="string")continue;const group=byIdentity.get(key)??[];group.push(record);byIdentity.set(key,group); }
            cached = { hash: sha256(bytes), parsed: parsedRecords, byIdentity }; rawRecordCache.set(cacheKey, cached);
          }
          hash = cached.hash; parsed = [...new Set([...item.cve_ids,...(item.osv_ids??[]),...(item.ghsa_ids??[]),...(item.aliases??[])].flatMap(key=>cached!.byIdentity.get(key)??[]))];
        }
        const proofKey = candidates[0]!.event_id + ":" + hash;
        let proof = proofCache.get(proofKey);
        if (!proof) {
        const rawId = "raw:" + raw.source_id + ":" + raw.external_id;
        const { parse_warnings, ...fetchedMetadata } = raw;
        void parse_warnings; // legacy producer hashed metadata before adding parser warnings
        proof = (sourceRows.get(sourceKey(candidates[0]!.trace_id,raw.source_id,raw.source_type,raw.url)) ?? []).filter(r => safeLineage(r) && r.source?.source_id === raw.source_id && r.source?.url === raw.url && r.source?.source_type === raw.source_type && r.trace_id === candidates[0]!.trace_id && [...r.input_refs, ...r.output_refs].some(ref => (ref.id === raw_ref || (ref.id === "payload:" + rawId && (refMatches(r.output_refs, rawId, sha256Json(raw)) || refMatches(r.output_refs, rawId, sha256Json(fetchedMetadata))))) && ref.sha256 === hash));
        if (raw_ref.startsWith("sqlite-page:")) {
          const rawPublish = (causeRows.get(candidates[0]!.event_id) ?? []).filter(r => safeLineage(r) && r.trace_id === candidates[0]!.trace_id && r.stage === "ingest.page_raw_publish" && r.causation_id === candidates[0]!.event_id && refMatches(r.input_refs, raw_ref, hash) && refMatches(r.output_refs, candidates[0]!.event_id, sha256Json(raw)));
          for (const r of rawPublish) {
            const saved = r.parent_lineage_ids.map(id => byLineage.get(id)).filter((p): p is LineageRecord => !!p && safeLineage(p) && p.stage === "ingest.page_snapshot" && refMatches(p.output_refs, raw_ref, hash));
            if (saved.length) proof = [...proof, r, ...saved];
          }
        }
        proofCache.set(proofKey,proof);
        }
        if (!proof.length || !parsed.length) throw new Error("raw SHA/source/URL lineage or per-record identity proof missing");
        if (parsed.some(r => !r.text?.trim() || !stamp(r.published_at))) throw new Error("source record text/date invalid");
        sourceRecords.set(raw_ref, parsed); sourceParents.set(raw_ref, proof.map(r => r.lineage_id));
        for (const r of parsed) { const text = raw_ref.startsWith("sqlite-page:") ? r.text : r.id + "\n" + r.text;
          add(item, intel_event, "source", text, raw.url, r.published_at, input.source_trust?.(raw) ?? "untrusted", hash, [...dqParents, ...proof.map(r => r.lineage_id)], { raw_ref, original_sha256: hash });
          if (raw.source_type === "vendor_advisory") evidence.at(-1)!.chunk.doc_type = "vendor_advisory";
        }
      } catch (error) { fail(raw_ref, error); }
    }
    const latest = enrichRows.get(item.intel_id);
    if (!latest) continue;
    try {
      const states = stateRows.get(item.intel_id) ?? [];
      if (states.length !== 1) throw new Error("enrichment state missing or ambiguous");
      const state = states[0]!, result = latest.payload as EnrichmentResult;
      const enrichedDq = enrichedDqRows.get(item.intel_id);
      if (enrichedDq && (!validDq(enrichedDq.payload) || ! ["pass", "degrade"].includes(object(enrichedDq.payload).verdict) || enrichedDq.causation_id !== latest.event_id || enrichedDq.seq <= latest.seq)) throw new Error("latest enriched DQ not released/bound");
      if (state.mode !== "live" || state.status !== "success" || state.enrich_event_id !== latest.event_id || latest.seq <= intel_event.seq || latest.causation_id !== intel_event.event_id || state.inputHash !== (state.inputHashMode === "facts" ? enrichmentInputHash(item) : sha256Json(item)) || state.resultHash !== sha256Json(result) || !stamp(result.completed_at) || result.schema_version !== "1.0" || !unit(result.enrichment_score) || !Array.isArray(result.dimensions_completed) || !Array.isArray(result.dimensions_failed)) throw new Error("enrichment live/input/result/event binding failed");
      const parents = state.lineage_ids.map(id => byLineage.get(id));
      if (!parents.length || parents.some(r => !r || !safeLineage(r) || r.trace_id !== latest.trace_id || r.causation_id !== latest.event_id || !refMatches(r.input_refs, item.intel_id, sha256Json(item)) || !refMatches(r.output_refs, item.intel_id, state.resultHash))) throw new Error("enrichment lineage proof failed");
      if (!sourceRecords.size) throw new Error("no verified live source evidence");
      const artifacts = [ ...(result.artifacts.papers ?? []).map(p => ({ key: "paper:" + p.paper_id, kind: "paper" as const, value: p })), ...(result.artifacts.score_assessment ? [{ key: "cvss", kind: "cvss" as const, value: result.artifacts.score_assessment }] : []) ];
      for (const artifact of artifacts) {
        try {
          const metadata = state.artifacts.filter(a => a.key === artifact.key);
          if (metadata.length !== 1) throw new Error("artifact metadata missing/ambiguous");
          const m = metadata[0]!, hash = sha256Json(artifact.value);
          if (m.artifactHash !== hash || !publicUrl(m.url) || !stamp(m.published_at) || !["trusted", "untrusted"].includes(m.trust ?? "")) throw new Error("artifact SHA/URL/date/trust invalid");
          const dimension = artifact.kind === "paper" ? "paper" : "cvss";
          if (!result.dimensions_completed.includes(dimension) || result.dimensions_failed.includes(dimension)) throw new Error("artifact dimension not successfully completed");
          let text: string;
          if (artifact.kind === "paper") {
            const p = artifact.value as NonNullable<EnrichmentResult["artifacts"]["papers"]>[number];
            const expected = p.source === "arxiv" ? "https://arxiv.org/abs/" + p.paper_id.replace(/^arxiv:/i, "") : p.source === "s2" ? "https://www.semanticscholar.org/paper/" + p.paper_id : "";
            if (!p.title?.trim() || m.url !== expected || !unit(p.confidence) || !unit(p.relevance_score)) throw new Error("paper identity/title/confidence failed");
            text = "Paper: " + p.title + "\n" + item.cve_ids.join(", ") + "\n" + JSON.stringify(p);
          } else {
            const score = artifact.value as NonNullable<EnrichmentResult["artifacts"]["score_assessment"]>;
            const rows = m.raw_ref ? sourceRecords.get(m.raw_ref) : undefined;
            const row = rows?.find(r => r.id === m.cve_id);
            const raw = input.events.find(e => e.topic === "raw.docs" && object(e.payload).payload_ref === m.raw_ref)?.payload as RawDoc | undefined;
            // 来源判据以"原始报文里逐字存在该 metric"为主：source_of_score/vector/base 全部
            // 对上才放行。source_type 配对只排除明显不可能的容器组合（如 kev 报文证明评分）；
            // nvd_cve 报文里由 CNA（sourceIdentifier）提交的评分是 NVD bulk 的原文内容，
            // 旧规则把这类有原始证据的评分整体误拒（2026-10-09 实测误拒 1908 条）。
            if (!m.cve_id || !item.cve_ids.includes(m.cve_id) || !raw || raw.url !== m.url || !row || !((raw.source_type === "nvd_cve" && (score.source_of_score === "nvd" || score.source_of_score === "cna")) || (raw.source_type === "cve_org" && score.source_of_score === "cna")) || !row.metrics.some(v => v?.source_of_score === score.source_of_score && v?.vectorString === score.cvss_v3_vector && v?.baseScore === score.cvss_v3_base)) throw new Error("CVSS score/CVE/source does not match actual raw payload");
            const core = { ...score };
            // Auxiliary EPSS provenance is separate; do not publish fixture/unknown EPSS as a CVSS fact.
            delete core.epss_score; delete core.epss_percentile;
            text = m.cve_id + " CVSS v3 base score: " + score.cvss_v3_base + "\n" + JSON.stringify(core);
          }
          add(item, intel_event, artifact.kind, text, m.url, m.published_at, m.trust, hash, [...dqParents, ...state.lineage_ids, ...(sourceParents.get(m.raw_ref ?? "") ?? [])], { artifact_sha256: hash, enrich_event_id: latest.event_id, input_sha256: state.inputHash, result_sha256: state.resultHash, ...(m.raw_ref ? { raw_ref: m.raw_ref } : {}) });
        } catch (error) { fail(artifact.key, error); }
      }
    } catch (error) { fail("enrichment", error); }
  }
  return { chunks: evidence.map(e => e.chunk), evidence, rejected, watermark: previous, fingerprint: sha256Json({ events: input.events, states: input.enrichment_states, evidence }) };
}
