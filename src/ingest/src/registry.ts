/**
 * 源登记表（Y1 契约：每个源声明 poll_interval_s / rate_per_min / requires_api_key / status）。
 * 接入新源只允许追加，source_id 一经发布不得复用；planned 源先登记不采集。
 */
import type { SourceType } from "@safetrace/shared";

export type SourceStatus = "active" | "planned";

export interface SourceEntry {
  source_id: string;
  source_type: SourceType;
  url: string;
  poll_interval_s: number;
  rate_per_min: number;
  requires_api_key: boolean;
  status: SourceStatus;
}

export const SOURCES: readonly SourceEntry[] = [
  {
    source_id: "cisa_kev",
    source_type: "kev",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    poll_interval_s: 3600,
    rate_per_min: 60,
    requires_api_key: false,
    status: "active",
  },
  {
    source_id: "nvd_cve",
    source_type: "nvd_cve",
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0",
    poll_interval_s: 7200,
    // 无 key 时 5req/30s≈10/min（见 sources/nvd.ts 令牌桶）；有 NVD_API_KEY 时放宽到 50req/30s
    rate_per_min: 10,
    requires_api_key: false,
    status: "active",
  },
  {
    source_id: "osv",
    source_type: "osv",
    url: "https://api.osv.dev/v1/querybatch",
    poll_interval_s: 1800,
    rate_per_min: 60,
    requires_api_key: false,
    status: "active",
  },
  {
    source_id: "cve_org",
    source_type: "cve_org",
    url: "https://cveawg.mitre.org/api/cve/",
    poll_interval_s: 1800,
    rate_per_min: 60,
    requires_api_key: false,
    status: "active",
  },
  {
    source_id: "ghsa",
    source_type: "ghsa",
    url: "https://api.github.com/advisories",
    poll_interval_s: 1800,
    rate_per_min: 30,
    // 全局通告批量拉取需 token；未到位前保持 planned，不参与采集
    requires_api_key: true,
    status: "planned",
  },
  {
    source_id: "arxiv",
    source_type: "paper",
    url: "http://export.arxiv.org/api/query",
    poll_interval_s: 21600,
    rate_per_min: 20,
    requires_api_key: false,
    status: "planned",
  },
];

export function getSource(sourceId: string): SourceEntry | undefined {
  return SOURCES.find((s) => s.source_id === sourceId);
}

/** 状态为 active 的源（含采集器未就绪的，由 pipeline 按 FETCHERS 过滤）。 */
export function activeSources(): SourceEntry[] {
  return SOURCES.filter((s) => s.status === "active");
}

export function activeSourceIds(): string[] {
  return activeSources().map((s) => s.source_id);
}
