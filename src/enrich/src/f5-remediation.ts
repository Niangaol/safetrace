/** F5: deterministic provenance projection, not a patch/PoC validator.
 * Caller supplies persisted bytes and a trusted ingestion receipt. A hash proves
 * byte identity, NOT the authenticity of an arbitrary caller's claimed origin.
 * No IO, clock, network, model, asset scan, execution, or frozen-schema changes.
 */
import { sha256 } from "@safetrace/shared";
import type { IntelItem, RawDoc } from "@safetrace/shared";

export interface RemediationSourceInput {
  raw: RawDoc;
  payload_bytes: Uint8Array;
  /** Ingestion provenance only; never inferred from payload prose. */
  proof: {
    source_id: string;
    source_url: string;
    raw_ref: string;
    source_sha256: string;
    source_status: "active";
    evidence_kind: "live" | "fixture";
  };
}
export interface RemediationArtifact {
  cve_id: string;
  source_id: "ubuntu_usn" | "cisa_kev";
  source_url: string;
  raw_ref: string;
  source_sha256: string;
  source_record_id: string;
  published_at: string;
  published_at_granularity: "day" | "instant" | "local_datetime";
  actions: string[];
  fixed_packages: { name: string; version: string; release?: string }[];
  limitations: string[];
  validation_level: "vendor_statement" | "agency_guidance";
  evidence_kind: "live" | "fixture";
}
type Obj = Record<string, unknown>;
const CVE = /^CVE-[0-9]{4}-[0-9]{4,}$/;
const USN = /^USN-[0-9]+-[0-9]+$/;
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const object = (v: unknown): Obj | null => v !== null && typeof v === "object" && !Array.isArray(v) ? v as Obj : null;
const text = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0 && v.length <= 16_384 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);

/** Preserve source precision/timezone, including Ubuntu's timezone-less timestamps. */
function date(v: unknown): { value: string; granularity: RemediationArtifact["published_at_granularity"] } | null {
  if (typeof v !== "string") return null;
  const match = /^(\d{4}-\d{2}-\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?)?$/.exec(v);
  if (!match || match[1]!.startsWith("0000")) return null;
  const calendar = new Date(match[1]! + "T00:00:00Z");
  if (!Number.isFinite(calendar.getTime()) || calendar.toISOString().slice(0, 10) !== match[1]) return null;
  if (match[2] !== undefined && (+match[2] > 23 || +match[3]! > 59 || +match[4]! > 59)) return null;
  if (match[5] && match[5] !== "Z") {
    const [hour, minute] = match[5].slice(1).split(":").map(Number);
    if (hour! > 23 || minute! > 59) return null;
  }
  return { value: v, granularity: match[2] === undefined ? "day" : match[5] ? "instant" : "local_datetime" };
}
function safeUrl(value: unknown, source: "ubuntu_usn" | "cisa_kev", noticeId?: string): value is string {
  if (typeof value !== "string" || /[\\\s\u0000-\u001f\u007f%]/.test(value)) return false;
  try {
    const u = new URL(value);
    if (u.protocol !== "https:" || u.username || u.password || u.port || u.hash) return false;
    if (source === "cisa_kev") return value === KEV_URL;
    if (u.origin !== "https://ubuntu.com") return false;
    if (u.pathname === "/security/notices.json") {
      if (value !== "https://ubuntu.com/security/notices.json" + u.search) return false;
      const keys = [...u.searchParams.keys()];
      return keys.every(k => k === "limit" || k === "order") && new Set(keys).size === keys.length
        && (!u.searchParams.has("limit") || /^(?:[1-9][0-9]?|100)$/.test(u.searchParams.get("limit")!))
        && (!u.searchParams.has("order") || u.searchParams.get("order") === "newest");
    }
    return noticeId !== undefined && value === "https://ubuntu.com/security/notices/" + noticeId;
  } catch { return false; }
}
/** Quoted data, never executed. Conservative filter, not a universal semantic
 * prompt-injection detector. Rejected content is retained only in the raw bytes.
 */
function safeAction(v: unknown, source: "ubuntu_usn" | "cisa_kev"): v is string {
  if (!text(v) || /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|system)|system\s*prompt|developer\s*(?:message|instruction)|<\/?(?:script|iframe)|javascript:|data:|file:|powershell|\bcurl\b|\bwget\b|\beval\s*\(|execute\s+(?:this|the)\s+(?:poc|payload)|已验证修复|可用\s*PoC|忽略.{0,8}(?:指令|提示)|(?:guaranteed|verified)\s+(?:fix|patch)|working\s+(?:poc|exploit)/i.test(v)) return false;
  const links = v.match(/[a-z][a-z0-9+.-]*:\/\/[^\s<>"']+/gi) ?? [];
  return links.every(link => {
    try {
      const u = new URL(link.replace(/[.,;)]+$/, ""));
      return u.protocol === "https:" && !u.username && !u.password && !u.port
        && u.hostname === (source === "ubuntu_usn" ? "ubuntu.com" : "www.cisa.gov") && !/[\\%]/.test(link);
    } catch { return false; }
  });
}
function cves(n: Obj): string[] | null {
  const fields = [n.cves_ids, n.CVEs, n.cves].filter(v => v !== undefined);
  if (fields.length === 0) return null;
  const lists: string[][] = [];
  for (const field of fields) {
    if (!Array.isArray(field) || field.length === 0) return null;
    const ids = field.map(v => typeof v === "string" ? v : object(v)?.id);
    if (!ids.every((v): v is string => typeof v === "string" && CVE.test(v))) return null;
    lists.push([...new Set(ids)].sort());
  }
  if (lists.some(v => JSON.stringify(v) !== JSON.stringify(lists[0]))) return null;
  return lists[0]!;
}
function packages(value: unknown): RemediationArtifact["fixed_packages"] | null {
  const releases = object(value);
  if (!releases || Object.keys(releases).length === 0) return null;
  const out: RemediationArtifact["fixed_packages"] = [];
  for (const [release, entries] of Object.entries(releases)) {
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(release) || !Array.isArray(entries) || entries.length === 0) return null;
    for (const entry of entries) {
      const p = object(entry);
      // Debian/Ubuntu versions are opaque strings, not semver or ranges.
      if (!p || typeof p.name !== "string" || !/^[a-z0-9][a-z0-9+.-]{0,127}$/.test(p.name)
        || typeof p.version !== "string" || !/^[0-9A-Za-z][0-9A-Za-z.+:~_-]{0,255}$/.test(p.version)) return null;
      if (p.is_visible !== undefined && typeof p.is_visible !== "boolean") return null;
      if (p.is_visible === false) continue;
      out.push({ name: p.name, version: p.version, release });
    }
  }
  return out.length ? out : null;
}

/** Fail closed rather than fabricate generic advice. Output does not establish
 * applicability, installation success, exploit availability, or verified repair.
 */
export function enrichRemediation(item: IntelItem, sources: readonly RemediationSourceInput[]): RemediationArtifact[] {
  if (!item || !Array.isArray(item.cve_ids) || !item.cve_ids.length || !item.cve_ids.every(v => typeof v === "string" && CVE.test(v))
    || !Array.isArray(item.source_ids) || !Array.isArray(item.raw_refs) || !Array.isArray(sources)) return [];
  const targets = [...new Set(item.cve_ids)];
  const out: RemediationArtifact[] = [];
  for (const input of sources) {
    const raw = input?.raw, proof = input?.proof;
    if (!raw || !proof || !(input.payload_bytes instanceof Uint8Array) || input.payload_bytes.length === 0
      || input.payload_bytes.length > 8 * 1024 * 1024 || raw.content_type !== "json"
      || !text(raw.external_id) || !date(raw.fetched_at) || !text(raw.payload_ref)
      || !item.source_ids.includes(raw.source_id) || !item.raw_refs.includes(raw.payload_ref)
      || proof.source_id !== raw.source_id || proof.raw_ref !== raw.payload_ref || proof.source_url !== raw.url
      || proof.source_status !== "active" || !["live", "fixture"].includes(proof.evidence_kind)
      || typeof proof.source_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(proof.source_sha256)
      || sha256(input.payload_bytes) !== proof.source_sha256) continue;
    const source = raw.source_id;
    if ((source !== "ubuntu_usn" && source !== "cisa_kev")
      || raw.source_type !== (source === "ubuntu_usn" ? "vendor_advisory" : "kev")) continue;
    let payload: Obj | null;
    try { payload = object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input.payload_bytes))); }
    catch { continue; }
    if (!payload) continue;
    const base = { source_id: source, raw_ref: raw.payload_ref, source_sha256: proof.source_sha256, evidence_kind: proof.evidence_kind };
    if (source === "ubuntu_usn") {
      // No recursive search of prose, related_notices, or other records' packages.
      const records = Array.isArray(payload.notices) ? payload.notices : [payload];
      const ids = records.map(v => object(v)?.id);
      for (const entry of records) {
        const n = object(entry);
        if (!n || typeof n.id !== "string" || !USN.test(n.id) || ids.filter(id => id === n.id).length !== 1
          || n.is_hidden !== false || (n.type !== undefined && n.type !== "USN")
          || !safeUrl(raw.url, source, n.id) || !safeAction(n.instructions, source)) continue;
        if (n.vendor !== undefined && n.vendor !== "Ubuntu" && n.vendor !== "Canonical") continue;
        if (n.status !== undefined && n.status !== "published") continue;
        const idsForNotice = cves(n), pub = date(n.published), fixed = packages(n.release_packages);
        if (!idsForNotice || !pub || !fixed) continue;
        if (n.url !== undefined && n.url !== "https://ubuntu.com/security/notices/" + n.id) continue;
        for (const cve of targets.filter(v => idsForNotice.includes(v))) out.push({ ...base,
          source_url: "https://ubuntu.com/security/notices/" + n.id, source_record_id: n.id, cve_id: cve,
          published_at: pub.value, published_at_granularity: pub.granularity, actions: [n.instructions], fixed_packages: fixed.map(p => ({ ...p })),
          validation_level: "vendor_statement", limitations: ["Ubuntu vendor statement only; not a verified fix.",
            "Packages apply only to the stated Ubuntu release; not upstream or another distribution.",
            "No asset applicability check, installation, scan, or PoC execution performed.",
            ...(pub.granularity === "local_datetime" ? ["Source timestamp has no timezone; no UTC instant inferred."] : []),
            ...(proof.evidence_kind === "fixture" ? ["Fixture replay, not live evidence."] : [])] });
      }
    } else {
      // Membership in the official KEV vulnerabilities array establishes listed
      // status; no fabricated status field is required in CISA's actual schema.
      if (!safeUrl(raw.url, source) || !text(payload.catalogVersion) || !date(payload.dateReleased)
        || !Array.isArray(payload.vulnerabilities)) continue;
      const records = payload.vulnerabilities;
      for (const entry of records) {
        const n = object(entry);
        if (!n || typeof n.cveID !== "string" || !targets.includes(n.cveID)
          || records.filter(v => object(v)?.cveID === n.cveID).length !== 1
          || !text(n.vendorProject) || !text(n.product) || !safeAction(n.requiredAction, source)) continue;
        if (n.status !== undefined && n.status !== "listed") continue;
        if (n.is_hidden !== undefined && n.is_hidden !== false) continue;
        const vendor = item.entities?.vendor;
        if (vendor && vendor.toLowerCase() !== n.vendorProject.toLowerCase()) continue;
        const pub = date(n.dateAdded);
        if (!pub || pub.granularity !== "day") continue;
        out.push({ ...base, cve_id: n.cveID, source_url: KEV_URL, source_record_id: n.cveID,
          published_at: pub.value, published_at_granularity: pub.granularity, actions: [n.requiredAction], fixed_packages: [],
          validation_level: "agency_guidance", limitations: ["CISA KEV listed-record guidance only; not a vendor-confirmed fixed version or verified fix.",
            "dateAdded is the KEV listing date (day granularity), not the vulnerability publication instant.",
            "KEV inclusion does not establish availability of a usable PoC.",
            "No asset applicability check, installation, scan, or PoC execution performed.",
            ...(proof.evidence_kind === "fixture" ? ["Fixture replay, not live evidence."] : [])] });
      }
    }
  }
  return [...new Map(out.map(a => [JSON.stringify(a), a])).values()];
}
