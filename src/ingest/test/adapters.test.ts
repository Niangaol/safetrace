/** Y2 适配器单测：四个源 fixture 全解析 + 缺字段 warning 场景。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { RawDoc } from "@safetrace/shared";
import { parseKev } from "../src/adapters/kev.js";
import { parseNvd } from "../src/adapters/nvd.js";
import { parseOsv } from "../src/adapters/osv.js";
import { parseCveOrg } from "../src/adapters/cveorg.js";

const fixture = (name: string): string =>
  fileURLToPath(new URL("../../../fixtures/sources/" + name, import.meta.url));

function rawDocFor(ref: string, sourceId: string, sourceType: RawDoc["source_type"]): RawDoc {
  return {
    source_id: sourceId,
    source_type: sourceType,
    external_id: "CVE-2021-44228",
    url: "https://example.invalid/fixture",
    fetched_at: new Date().toISOString(),
    content_type: "json",
    payload_ref: ref,
  };
}

/** ISO-8601 UTC 带 Z（适配器必须把上游脏时间归一化到该口径）。 */
const ISO_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const INTEL_ID = /^intel_[0-9A-Za-z_-]+$/;

test("adapters：KEV fixture 全解析且关键字段非空", async () => {
  const ref = fixture("kev.sample.json");
  const { items, warnings } = await parseKev(rawDocFor(ref, "cisa_kev", "kev"));
  assert.equal(items.length, 1);
  const it = items[0]!;
  assert.match(it.intel_id, INTEL_ID);
  assert.deepEqual(it.cve_ids, ["CVE-2021-44228"]);
  assert.equal(it.title, "Apache Log4j2 Remote Code Execution Vulnerability");
  assert.ok((it.summary ?? "").length > 0);
  assert.match(it.published_at, ISO_Z); // dateAdded 纯日期已归一化为带 Z
  assert.match(it.first_seen_at, ISO_Z);
  assert.equal(it.entities.product, "Log4j");
  assert.equal(it.entities.vendor, "Apache");
  assert.deepEqual(it.entities.cwe, ["CWE-917", "CWE-502"]);
  assert.ok(it.entities.version_range.length >= 1); // 从 shortDescription 推导
  assert.deepEqual(it.source_ids, ["cisa_kev"]);
  assert.deepEqual(it.raw_refs, [ref]);
  assert.equal(it.source_reliability, 0.9);
  assert.equal(it.schema_version, "1.0");
  assert.ok(warnings.every((w) => w.length > 0));
});

test("adapters：NVD fixture 全解析（descriptions/weaknesses → 字段）", async () => {
  const ref = fixture("nvd.sample.json");
  const { items, warnings } = await parseNvd(rawDocFor(ref, "nvd_cve", "nvd_cve"));
  assert.equal(items.length, 1);
  const it = items[0]!;
  assert.match(it.intel_id, INTEL_ID);
  assert.deepEqual(it.cve_ids, ["CVE-2021-44228"]);
  assert.ok(it.title.includes("Log4j2"));
  assert.ok((it.summary ?? "").includes("JNDI"));
  assert.deepEqual(it.entities.cwe, ["CWE-917"]);
  assert.match(it.published_at, ISO_Z); // published 无时区原文已按 UTC 归一化
  assert.match(it.first_seen_at, ISO_Z);
  // 无 configurations + metrics/references 无契约字段可承载 → 非致命告警
  assert.ok(warnings.some((w) => w.includes("configurations")));
  assert.ok(warnings.some((w) => w.includes("metrics")));
  assert.ok(warnings.some((w) => w.includes("references")));
});

test("adapters：NVD cpeMatch 版本边界 → version_range（区间 + 精确版本，非 vulnerable 项剔除）", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-nvd-range-"));
  try {
    const p = path.join(dir, "nvd-ranges.json");
    await writeFile(
      p,
      JSON.stringify({
        vulnerabilities: [
          {
            cve: {
              id: "CVE-2024-12345",
              published: "2024-01-01T00:00:00.000Z",
              descriptions: [{ lang: "en", value: "demo range extraction" }],
              vulnStatus: "Analyzed",
              configurations: [
                {
                  nodes: [
                    {
                      cpeMatch: [
                        { vulnerable: true, criteria: "cpe:2.3:a:vendor:prod:1.0:*:*:*:*:*:*:*", versionStartIncluding: "1.0", versionEndExcluding: "2.0" },
                        { vulnerable: true, criteria: "cpe:2.3:a:vendor:prod:2.5:*:*:*:*:*:*:*", version: "2.5" },
                        { vulnerable: true, criteria: "cpe:2.3:a:vendor:prod:3.0:*:*:*:*:*:*:*", versionStartIncluding: "3.0-beta", versionEndIncluding: "*" },
                        { vulnerable: false, criteria: "cpe:2.3:a:vendor:prod:9.9:*:*:*:*:*:*:*", version: "9.9" },
                      ],
                    },
                  ],
                },
              ],
            },
          },
        ],
      }),
      "utf8",
    );
    const { items, warnings } = await parseNvd(rawDocFor(p, "nvd_cve", "nvd_cve"));
    assert.equal(items.length, 1);
    const it = items[0]!;
    assert.deepEqual(it.entities.version_range, [">=1.0 <2.0", "2.5"], "区间与精确版本都要提；含通配/预发布的边界不猜");
    assert.equal(it.entities.product, "prod");
    assert.equal(it.entities.vendor, "vendor");
    assert.equal(it.entities.cpes.length, 3, "vulnerable=false 的条目不进 cpes");
    assert.ok(!warnings.some((w) => w.includes("configurations")), "有 CPE 不该报无 configurations");
    assert.ok(!warnings.some((w) => w.includes("version_range")), "提得出区间就不该告警");
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("adapters：NVD 有 CPE 但提不出版本边界时置空并留痕", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-nvd-norange-"));
  try {
    const p = path.join(dir, "nvd-norange.json");
    await writeFile(
      p,
      JSON.stringify({
        vulnerabilities: [
          {
            cve: {
              id: "CVE-2024-54321",
              published: "2024-01-01T00:00:00.000Z",
              descriptions: [{ lang: "en", value: "no range" }],
              vulnStatus: "Analyzed",
              configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*" }] }] }],
            },
          },
        ],
      }),
      "utf8",
    );
    const { items, warnings } = await parseNvd(rawDocFor(p, "nvd_cve", "nvd_cve"));
    assert.deepEqual(items[0]!.entities.version_range, []);
    assert.ok(warnings.some((w) => w.includes("CVE-2024-54321") && w.includes("version_range")), warnings.join("；"));
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  }
});

test("adapters：OSV fixture 全解析（aliases 分拣 + ranges → version_range）", async () => {
  const { items, warnings } = await parseOsv(rawDocFor(fixture("osv.sample.json"), "osv", "osv"));
  assert.equal(items.length, 1);
  const it = items[0]!;
  assert.deepEqual(it.cve_ids, ["CVE-2021-44228"]); // 由 aliases 分拣而来
  assert.deepEqual(it.ghsa_ids, ["GHSA-jfh8-c2jp-5v3q"]);
  assert.deepEqual(it.osv_ids, ["GHSA-jfh8-c2jp-5v3q"]);
  assert.equal(it.entities.product, "org.apache.logging.log4j:log4j-core");
  assert.deepEqual(it.entities.version_range, [">=2.0-beta9 <2.15.0"]);
  assert.ok((it.summary ?? "").includes("Log4j2"));
  assert.match(it.published_at, ISO_Z);
  assert.match(it.first_seen_at, ISO_Z);
  assert.ok(warnings.some((w) => w.includes("vendor")));
});

test("adapters：cve.org fixture 全解析（containers.cna → 字段）", async () => {
  const { items } = await parseCveOrg(rawDocFor(fixture("cveorg.sample.json"), "cve_org", "cve_org"));
  assert.equal(items.length, 1);
  const it = items[0]!;
  assert.match(it.intel_id, INTEL_ID);
  assert.deepEqual(it.cve_ids, ["CVE-2021-44228"]);
  assert.equal(it.title, "Remote code execution in Log4j2");
  assert.ok((it.summary ?? "").length > 0);
  assert.equal(it.entities.vendor, "Apache");
  assert.equal(it.entities.product, "Log4j");
  assert.deepEqual(it.entities.version_range, ["<=2.14.1"]);
  assert.match(it.published_at, ISO_Z);
  assert.match(it.first_seen_at, ISO_Z);
  assert.deepEqual(it.source_ids, ["cve_org"]);
});

test("adapters：缺字段只置空并记 warning（不猜），支持绝对路径 payload_ref", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "safetrace-kev-"));
  try {
    const p = path.join(dir, "kev-broken.json");
    await writeFile(
      p,
      JSON.stringify({
        title: "CISA KEV",
        catalogVersion: "2026.01.01",
        vulnerabilities: [
          { cveID: "CVE-2022-0001", vulnerabilityName: "Broken sample", shortDescription: "no version info", dateAdded: "2022-01-02" },
        ],
      }),
      "utf8",
    );
    const { items, warnings } = await parseKev(rawDocFor(p, "cisa_kev", "kev"));
    assert.equal(items.length, 1);
    const it = items[0]!;
    assert.equal(it.entities.vendor, null); // 缺 vendorProject → 置空
    assert.equal(it.entities.product, null); // 缺 product → 置空
    assert.deepEqual(it.entities.version_range, []); // 提不出版本约束 → 置空
    assert.deepEqual(it.raw_refs, [p]); // 绝对路径 payload_ref 原样透传
    assert.ok(warnings.some((w) => w.includes("vendorProject")));
    assert.ok(warnings.some((w) => w.includes("product")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
