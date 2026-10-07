import { test } from "node:test";
import assert from "node:assert/strict";
import { buildPaperQuery, isDistinctiveAnchor, anchoredPapers, parseArxivAtom, arxivPaperRecords, DESCRIPTIVE_PRODUCT_TERMS } from "../src/f1-papers.js";
import type { IntelItem } from "@safetrace/shared";

const item = (product: string | null, title = "Some Vulnerability Title", cve = "CVE-2026-12345"): IntelItem => ({ intel_id: "i", cve_ids: [cve], ghsa_ids: [], osv_ids: [], aliases: [], title, summary: "", entities: { product, vendor: null, version_range: [], cwe: [], cpes: [] }, source_ids: ["s"], published_at: "2026-01-01T00:00:00.000Z", raw_refs: [], schema_version: "1.0" } as unknown as IntelItem);

test("描述性产品词不能当检索锚点", () => {
  assert.equal(isDistinctiveAnchor("multiple"), false);
  assert.equal(isDistinctiveAnchor("core"), false);
  assert.equal(isDistinctiveAnchor("commerce"), false);
  assert.equal(isDistinctiveAnchor("switches"), false);
  assert.equal(isDistinctiveAnchor("secure"), false, "secure 也是描述词，不是产品身份");
  assert.equal(isDistinctiveAnchor("netscaler"), true, "真产品名要保留");
  assert.equal(isDistinctiveAnchor("screenconnect"), true);
  assert.equal(isDistinctiveAnchor("log4j"), true);
  assert.equal(isDistinctiveAnchor("av"), false, "太短的词没有区分度");
  assert.equal(isDistinctiveAnchor("out-of-bounds"), false, "连字符机制词整体不是身份");
  assert.equal(isDistinctiveAnchor("write"), false, "机制词不是身份");
});

test("查询构造：产品名可用时取产品名，只有描述词时返回空", () => {
  assert.equal(buildPaperQuery(item("NetScaler")), "netscaler");
  assert.equal(buildPaperQuery(item("Multiple Products")), "", "全是描述词就不该发检索，宁可不召回");
  assert.equal(buildPaperQuery(item(null, "ImageMagick Out-of-Bounds Write Vulnerability")), "imagemagick", "无产品时用标题里区分度高的词");
});

const entry = (id: string, title: string, summary: string) => "<feed><entry><id>http://arxiv.org/abs/" + id + "</id><title>" + title + "</title><summary>" + summary + "</summary><published>2024-05-01T00:00:00Z</published></entry></feed>";

test("锚定：只共用描述词的论文一律判不相关", () => {
  const multipleXml = entry("1701.02303", "A study of multiple products", "We discuss many products.");
  const papers = parseArxivAtom(multipleXml, "multiple");
  assert.equal(papers.length, 1);
  assert.equal(anchoredPapers(item("Multiple Products"), papers, arxivPaperRecords(multipleXml)).length, 0, "共用 multiple 不算相关");
});

test("锚定：论文真的提到该 CVE 才算相关", () => {
  const cveXml = entry("2405.14987", "Attack on a gateway", "We analyse CVE-2026-12345 exploitation.");
  const papers = parseArxivAtom(cveXml, "identity");
  const anchored = anchoredPapers(item("Identity Services Engine", "Identity Services Engine Vulnerability"), papers, arxivPaperRecords(cveXml));
  assert.equal(anchored.length, 1, "正文出现 CVE 编号必须判相关");
});

test("锚定：产品短语完整出现算相关，单词+漏洞类词才算相关", () => {
  const phraseXml = entry("2405.14987", "ScreenConnect Gateway flaw", "A vulnerability in the product.");
  const phrase = parseArxivAtom(phraseXml, "screenconnect");
  assert.equal(anchoredPapers(item("ScreenConnect Gateway"), phrase, arxivPaperRecords(phraseXml)).length, 1, "多词产品名全部出现");
  const singleXml = entry("2405.14987", "ScreenConnect study", "A vulnerability analysis.");
  const singlePlusVuln = parseArxivAtom(singleXml, "screenconnect");
  assert.equal(anchoredPapers(item("ScreenConnect"), singlePlusVuln, arxivPaperRecords(singleXml)).length, 1, "产品词 + 漏洞类词");
  const unrelatedXml = entry("2405.14987", "Network routing paper", "We study routing protocols.");
  const unrelatedOnly = parseArxivAtom(unrelatedXml, "screenconnect");
  assert.equal(anchoredPapers(item("ScreenConnect"), unrelatedOnly, arxivPaperRecords(unrelatedXml)).length, 0, "只有产品词、无漏洞语境 → 不相关");
});

test("描述词表自身不自相矛盾", () => {
  for (const term of ["netscaler", "screenconnect", "log4j", "sharepoint", "routeros"]) assert.equal(DESCRIPTIVE_PRODUCT_TERMS.has(term), false, term + " 不应被当描述词");
});
