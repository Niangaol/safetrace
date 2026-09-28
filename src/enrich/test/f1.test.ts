import { test } from "node:test";
import assert from "node:assert/strict";
import {
  arxivPaperId,
  buildArxivUrl,
  confidenceFor,
  parseArxivAtom,
  relevanceOf,
  searchPapers,
  type HttpFetcher,
} from "../src/f1-papers.js";

const QUERY = "Log4Shell JNDI remote code execution";

/** 与 fixtures/enrich/arxiv.sample.xml 同形的两条 entry Atom（在线 mock 用）。 */
const ATOM_TWO = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<feed xmlns="http://www.w3.org/2005/Atom">',
  '  <title type="html">ArXiv Query</title>',
  '  <entry>',
  '    <id>http://arxiv.org/abs/2112.00507v1</id>',
  '    <published>2021-12-06T00:00:00Z</published>',
  '    <title>Log4Shell: A Large-Scale Analysis of the Vulnerability and Its Exploitation</title>',
  '    <summary>  The Log4Shell vulnerability (CVE-2021-44228) in Apache Log4j2 allows',
  '  remote code execution through attacker controlled JNDI lookups. We analyze',
  '  exploitation traffic and mitigation at Internet scale.',
  '</summary>',
  '    <link href="http://arxiv.org/abs/2112.00507v1" rel="alternate" type="text/html"/>',
  '  </entry>',
  '  <entry>',
  '    <id>http://arxiv.org/abs/2301.12345v2</id>',
  '    <published>2023-01-30T00:00:00Z</published>',
  '    <title>Deserialization Vulnerabilities in Java: A Survey of Mitigations</title>',
  '    <summary>  We survey code injection and unsafe deserialization flaws in Java',
  '  applications, comparing static analysis and sandboxing mitigations for unsafe',
  '  lookup endpoints such as LDAP during runtime execution and code loading.',
  '</summary>',
  '    <link href="http://arxiv.org/abs/2301.12345v2" rel="alternate" type="text/html"/>',
  '  </entry>',
  '</feed>',
].join("\n");

test("buildArxivUrl：拼接规范要求的检索参数", () => {
  const url = buildArxivUrl(QUERY);
  assert.equal(
    url,
    'https://export.arxiv.org/api/query?search_query=all:%22Log4Shell%20JNDI%20remote%20code%20execution%22&start=0&max_results=5&sortBy=relevance',
  );
});

test("searchPapers：注入 fetchImpl 从 Atom 解析论文（relevance/confidence/证据词）", async () => {
  let requested = "";
  const fetcher: HttpFetcher = (url) => {
    requested = url;
    return Promise.resolve({ ok: true, status: 200, text: async () => ATOM_TWO, json: async () => ({}) });
  };
  const res = await searchPapers(QUERY, { fetchImpl: fetcher });
  assert.equal(res.degraded_to, undefined);
  assert.equal(requested, buildArxivUrl(QUERY));

  assert.equal(res.papers.length, 2);
  const first = res.papers[0];
  const second = res.papers[1];
  assert.ok(first !== undefined && second !== undefined);
  // 相关性降序：entry1 命中 5/5，entry2 只命中 code/execution
  assert.equal(first.paper_id, "arXiv:2112.00507");
  assert.equal(first.title, "Log4Shell: A Large-Scale Analysis of the Vulnerability and Its Exploitation");
  assert.equal(first.source, "arxiv");
  assert.equal(first.year, 2021);
  assert.equal(first.venue, "arXiv");
  assert.equal(first.relevance_score, 1);
  assert.equal(first.confidence, 0.9);
  assert.deepEqual(first.evidence_terms, ["log4shell", "jndi", "remote", "code", "execution"]);

  assert.equal(second.paper_id, "arXiv:2301.12345");
  assert.equal(second.year, 2023);
  assert.equal(second.relevance_score, 0.4);
  assert.equal(second.confidence, 0.6);
  assert.deepEqual(second.evidence_terms, ["code", "execution"]);
});

test("searchPapers：offline 读 fixtures/enrich/arxiv.sample.xml 回放并降级", async () => {
  const events: string[] = [];
  const res = await searchPapers(QUERY, {
    offline: true,
    emit: async (e) => {
      events.push(e.degraded_of);
    },
  });
  assert.equal(res.degraded_to, "fixture");
  assert.deepEqual(events, ["fixture"]);
  assert.equal(res.papers.length, 2);
  const first = res.papers[0];
  assert.ok(first !== undefined);
  assert.equal(first.paper_id, "arXiv:2112.00507");
  assert.equal(first.relevance_score, 1);
});

test("searchPapers：HTTP 503 → fixture 回放（禁止静默兜底）", async () => {
  const fetcher: HttpFetcher = async () => ({ ok: false, status: 503, text: async () => "", json: async () => ({}) });
  const res = await searchPapers(QUERY, { fetchImpl: fetcher });
  assert.equal(res.degraded_to, "fixture");
  assert.equal(res.papers.length, 2);
});

test("searchPapers：fetch 抛错 → fixture 回放", async () => {
  const fetcher: HttpFetcher = async () => {
    throw new Error("dns fail");
  };
  const res = await searchPapers(QUERY, { fetchImpl: fetcher });
  assert.equal(res.degraded_to, "fixture");
  assert.ok(res.papers.length > 0);
});

test("searchPapers：OFFLINE_FIXTURES=true 环境变量触发离线回放", async () => {
  const prev = process.env.OFFLINE_FIXTURES;
  process.env.OFFLINE_FIXTURES = "true";
  try {
    const res = await searchPapers(QUERY, {
      fetchImpl: async () => {
        throw new Error("offline 模式下不应发起请求");
      },
    });
    assert.equal(res.degraded_to, "fixture");
  } finally {
    if (prev === undefined) delete process.env.OFFLINE_FIXTURES;
    else process.env.OFFLINE_FIXTURES = prev;
  }
});

test("parseArxivAtom：超过 5 条截断；脏 entry（无标题/id）跳过", () => {
  const many = Array.from({ length: 6 }, (_, i) => [
    "  <entry>",
    '    <id>http://arxiv.org/abs/2401.0000' + i + 'v1</id>',
    '    <published>2024-01-0' + (i + 1) + 'T00:00:00Z</published>',
    '    <title>Title number ' + i + ' about Log4Shell JNDI</title>',
    '    <summary>Log4Shell JNDI remote code execution</summary>',
    '  </entry>',
  ].join("\n")).join("\n");
  const papers = parseArxivAtom("<feed>" + many + "</feed>", QUERY);
  assert.equal(papers.length, 5);
  const withDirty = [
    "  <entry>",
    '    <id>http://arxiv.org/abs/2402.0001v1</id>',
    '    <published>2024-02-01T00:00:00Z</published>',
    '    <summary>Log4Shell JNDI remote code execution</summary>',
    '  </entry>',
  ].join("\n");
  assert.equal(parseArxivAtom("<feed>" + withDirty + "</feed>", QUERY).length, 0);
});

test("PaperLink 不含 undefined 值键（契约 additionalProperties:false）", () => {
  const papers = parseArxivAtom(ATOM_TWO, QUERY);
  for (const p of papers) {
    for (const [k, v] of Object.entries(p)) {
      assert.notEqual(v, undefined, "键 " + k + " 不应为 undefined");
    }
  }
});

test("relevanceOf：词级精确匹配（防子串误判）", () => {
  const hit = relevanceOf("Log4Shell JNDI", "log4shell jndi lookup");
  assert.equal(hit.score, 1);
  assert.deepEqual(hit.terms, ["log4shell", "jndi"]);
  const partial = relevanceOf("Log4Shell JNDI", "log4shell only");
  assert.equal(partial.score, 0.5);
  // rce 是 execution 的子串但不成词：不应误判命中
  const substring = relevanceOf("rce", "remote code execution");
  assert.equal(substring.score, 0);
  assert.deepEqual(substring.terms, []);
});

test("confidenceFor：按分数分档", () => {
  assert.equal(confidenceFor(1), 0.9);
  assert.equal(confidenceFor(0.6), 0.8);
  assert.equal(confidenceFor(0.3), 0.6);
  assert.equal(confidenceFor(0.1), 0.4);
  assert.equal(confidenceFor(0), 0.25);
});

test("arxivPaperId：abs URL 去版本号；非 arXiv 形态原样返回", () => {
  assert.equal(arxivPaperId("http://arxiv.org/abs/2112.00507v3"), "arXiv:2112.00507");
  assert.equal(arxivPaperId("https://doi.org/10.1145/1"), "https://doi.org/10.1145/1");
});

test("searchPapers：空 query 直接抛错", async () => {
  await assert.rejects(() => searchPapers("   "), /query 不能为空/);
});
