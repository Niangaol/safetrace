/** 源登记表（Y1）单测。 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { SOURCES, activeSourceIds, activeSources, getSource } from "../src/registry.js";

test("registry：7 个源登记齐全（5 active + 2 planned，E-01 第 7 源为 ubuntu_usn）", () => {
  assert.equal(SOURCES.length, 7);
  assert.deepEqual(
    SOURCES.map((s) => s.source_id),
    ["cisa_kev", "nvd_cve", "osv", "cve_org", "ubuntu_usn", "ghsa", "arxiv"],
  );
  assert.deepEqual(activeSourceIds(), ["cisa_kev", "nvd_cve", "osv", "cve_org", "ubuntu_usn"]);
  assert.equal(activeSources().length, 5);
  assert.equal(getSource("ghsa")?.status, "planned");
  assert.equal(getSource("arxiv")?.status, "planned");
});

test("registry：五个 active 源的 URL 与 source_type 对齐契约", () => {
  assert.equal(getSource("cisa_kev")?.source_type, "kev");
  assert.equal(
    getSource("cisa_kev")?.url,
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  );
  assert.equal(getSource("nvd_cve")?.source_type, "nvd_cve");
  assert.equal(getSource("nvd_cve")?.url, "https://services.nvd.nist.gov/rest/json/cves/2.0");
  assert.equal(getSource("osv")?.source_type, "osv");
  assert.equal(getSource("osv")?.url, "https://api.osv.dev/v1/querybatch");
  assert.equal(getSource("cve_org")?.source_type, "cve_org");
  assert.equal(getSource("cve_org")?.url, "https://cveawg.mitre.org/api/cve/");
  // 第 7 源走契约里已存在的 vendor_advisory 枚举，未新增枚举值（不改契约）
  assert.equal(getSource("ubuntu_usn")?.source_type, "vendor_advisory");
  assert.equal(getSource("ubuntu_usn")?.url, "https://ubuntu.com/security/notices.json");
  assert.equal(getSource("ghsa")?.source_type, "ghsa");
  assert.equal(getSource("arxiv")?.source_type, "paper");
});

test("registry：采集参数合法，KEV 免 key、GHSA 需 key、未登记源返回 undefined", () => {
  for (const s of SOURCES) {
    assert.ok(s.url.startsWith("http"), s.source_id + " url 非法");
    assert.ok(Number.isInteger(s.poll_interval_s) && s.poll_interval_s > 0, s.source_id + " poll_interval_s 非法");
    assert.ok(s.rate_per_min > 0, s.source_id + " rate_per_min 非法");
    assert.equal(typeof s.requires_api_key, "boolean", s.source_id + " requires_api_key 应为布尔");
    assert.ok(s.status === "active" || s.status === "planned", s.source_id + " status 非法");
  }
  assert.equal(getSource("cisa_kev")?.requires_api_key, false);
  assert.equal(getSource("nvd_cve")?.requires_api_key, false); // key 可选
  assert.equal(getSource("ubuntu_usn")?.requires_api_key, false);
  assert.equal(getSource("ubuntu_usn")?.status, "active");
  assert.equal(getSource("ghsa")?.requires_api_key, true);
  assert.equal(getSource("no_such_source"), undefined);
});
