/**
 * NVD 采集器（翻页 + lastMod/pubDate 双窗口）单测。
 * 全部用 globalThis.fetch 打桩：不碰真实外网；多数用例给一个假 API key，
 * 免得 5req/30s 令牌桶把单测拖成几十秒（令牌桶本身另有一条离线用例覆盖）。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import type { FallbackEvent, RawDoc } from "@safetrace/shared";
import { fetchNvd, splitNvdWindow } from "../src/sources/nvd.js";
import { parseNvd } from "../src/adapters/nvd.js";
import { readJsonFile } from "../src/common.js";

type Resp = { status: number; body: unknown };

function cve(id: string): Record<string, unknown> {
  return { cve: { id, published: "2026-10-01T00:00:00Z", descriptions: [{ lang: "en", value: "desc of " + id }], vulnStatus: "Analyzed" } };
}

function page(total: number, ids: string[]): Record<string, unknown> {
  return { resultsPerPage: 2000, startIndex: 0, timestamp: "2026-10-01T10:00:00Z", totalResults: total, vulnerabilities: ids.map(cve) };
}

/** 用桩 fetch 跑一次，并回收被请求的 URL 列表。 */
async function withFetch(route: (url: string) => Resp, run: () => Promise<RawDoc | null>): Promise<{ raw: RawDoc | null; urls: string[] }> {
  const original = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = (async (input: URL | Request) => {
    const url = String(input);
    urls.push(url);
    const r = route(url);
    return new Response(JSON.stringify(r.body), { status: r.status });
  }) as typeof globalThis.fetch;
  try {
    return { raw: await run(), urls };
  } finally {
    globalThis.fetch = original;
  }
}

async function withKey<T>(run: () => Promise<T>): Promise<T> {
  const prev = process.env.NVD_API_KEY;
  process.env.NVD_API_KEY = "test-key-not-real";
  try {
    return await run();
  } finally {
    if (prev === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = prev;
  }
}

async function payloadOf(raw: RawDoc): Promise<Record<string, unknown>> {
  return (await readJsonFile(raw.payload_ref)) as Record<string, unknown>;
}

function windowsOf(p: Record<string, unknown>): Record<string, unknown>[] {
  return p.windows as Record<string, unknown>[];
}

test("NVD：lastMod 超过一页时按 startIndex 翻完，不再只拿首页 2000 条", async () => {
  const ids = Array.from({ length: 2500 }, (_, i) => "CVE-2026-" + String(10000 + i));
  await withKey(async () => {
    const { raw, urls } = await withFetch(
      (url) => {
        const u = new URL(url);
        const start = Number(u.searchParams.get("startIndex") ?? "0");
        return { status: 200, body: page(2500, ids.slice(start, start + 2000)) };
      },
      () => fetchNvd({ traceId: "tr_t", skipPubWindow: true }),
    );
    assert.ok(raw !== null);
    const p = await payloadOf(raw);
    assert.equal((p.vulnerabilities as unknown[]).length, 2500, "原实现只有 2000 条");
    assert.equal(windowsOf(p)[0]!.pages_fetched, 2);
    assert.match(raw.external_id, /items=2500/);
    assert.equal(urls.length, 2, "最后一页拿到 500 条即停，不多打");
  });
});

test("NVD：默认再跑一条 pubDate 新发布窗口；只用官方参数，不自造 query", async () => {
  await withKey(async () => {
    const { raw, urls } = await withFetch(
      (url) => {
        const u = new URL(url);
        if (u.searchParams.has("pubStartDate")) return { status: 200, body: page(3, ["CVE-2026-90001", "CVE-2026-90002", "CVE-2026-90003"]) };
        return { status: 200, body: page(1, ["CVE-2026-11111"]) };
      },
      () => fetchNvd({ traceId: "tr_t" }),
    );
    assert.ok(raw !== null);
    const p = await payloadOf(raw);
    assert.deepEqual(windowsOf(p).map((w) => w.kind), ["lastMod", "pubDate"]);
    assert.equal((p.vulnerabilities as unknown[]).length, 4);
    assert.ok(urls.every((u) => !/[?&](window|_t|note|tag)=/.test(u)), "不许塞自定义参数（NVD 可能判 400）");
    assert.ok(urls.every((u) => u.includes("resultsPerPage=2000")));
    assert.ok(urls.some((u) => u.includes("pubStartDate=") && u.includes("pubEndDate=")));
    assert.ok(urls.some((u) => u.includes("lastModStartDate=") && u.includes("lastModEndDate=")));
  });
});

test("NVD：两窗口重叠的同一 CVE 只留一条，去重数进 payload 与告警", async () => {
  await withKey(async () => {
    const { raw } = await withFetch(
      (url) => {
        const u = new URL(url);
        if (Number(u.searchParams.get("startIndex") ?? "0") > 0) return { status: 200, body: page(1, []) };
        return { status: 200, body: page(1, ["CVE-2026-77777"]) };
      },
      () => fetchNvd({ traceId: "tr_t" }),
    );
    assert.ok(raw !== null);
    const p = await payloadOf(raw);
    assert.equal((p.vulnerabilities as unknown[]).length, 1, "同一条 CVE 不能入库两次");
    assert.equal(p.duplicate_entries_dropped, 1);
    const { warnings } = await parseNvd(raw);
    assert.ok(warnings.some((w) => w.includes("重叠") && w.includes("1 条")), warnings.join("；"));
  });
});

test("NVD：404 是「该窗口无结果」，算空不算错，也不回放样本", async () => {
  await withKey(async () => {
    const events: FallbackEvent[] = [];
    const { raw } = await withFetch(
      (url) => {
        const u = new URL(url);
        if (u.searchParams.has("pubStartDate")) return { status: 404, body: { code: 2002, message: "No results found" } };
        return { status: 200, body: page(1, ["CVE-2026-55555"]) };
      },
      () => fetchNvd({ traceId: "tr_t", emit: (e) => { events.push(e); } }),
    );
    assert.ok(raw !== null);
    assert.ok(!raw.external_id.endsWith("_fixture"), "有真实数据，不该回退样本");
    assert.equal(windowsOf(await payloadOf(raw))[1]!.empty, true);
    assert.equal(events.length, 0, "空窗口不是降级");
  });
});

test("NVD：部分页失败时保留已取到的数据并记 partial，缺口绝不拿样本顶替", async () => {
  await withKey(async () => {
    const events: FallbackEvent[] = [];
    const { raw } = await withFetch(
      (url) => {
        const u = new URL(url);
        if (u.searchParams.has("pubStartDate")) return { status: 200, body: page(0, []) };
        if (Number(u.searchParams.get("startIndex") ?? "0") === 0) return { status: 200, body: page(3000, ["CVE-2026-1000", "CVE-2026-1001"]) };
        return { status: 503, body: { message: "upstream unavailable" } };
      },
      () => fetchNvd({ traceId: "tr_t", emit: (e) => { events.push(e); } }),
    );
    assert.ok(raw !== null);
    const p = await payloadOf(raw);
    assert.equal(p.partial, true);
    assert.equal((p.vulnerabilities as unknown[]).length, 2);
    assert.ok(!raw.external_id.endsWith("_fixture"));
    const kinds = events.map((e) => e.degraded_of);
    assert.ok(kinds.includes("partial"), "缺口要显式登记：" + kinds.join(","));
    assert.ok(!kinds.includes("fixture"), "部分失败不得回退预置样本");
    const { warnings } = await parseNvd(raw);
    assert.ok(warnings.some((w) => w.includes("部分页抓取失败")));
  });
});

test("NVD：翻页触顶要标 truncated，并由适配器变成可见告警", async () => {
  await withKey(async () => {
    const fill = Array.from({ length: 2000 }, (_, i) => "CVE-2026-" + String(200000 + i));
    const { raw, urls } = await withFetch(
      (url) => {
        const u = new URL(url);
        if (u.searchParams.has("pubStartDate")) return { status: 200, body: page(0, []) };
        return { status: 200, body: page(999999, fill) };
      },
      () => fetchNvd({ traceId: "tr_t" }),
    );
    assert.ok(raw !== null);
    const p = await payloadOf(raw);
    assert.equal(p.truncated, true);
    assert.equal(windowsOf(p)[0]!.pages_fetched, 10, "上限 10 页");
    assert.equal(urls.length, 11, "10 页 lastMod + 1 页 pubDate 后停手，不无限翻");
    const { warnings } = await parseNvd(raw);
    assert.ok(warnings.some((w) => w.includes("翻页触顶")), "截断必须可见：" + warnings.join("；"));
  });
});

test("NVD：离线路径不变（回放样本 + external_id 以 _fixture 结尾，供时效看板剔除）", async () => {
  const events: FallbackEvent[] = [];
  const raw = await fetchNvd({ offline: true, traceId: "tr_t", emit: (e) => { events.push(e); } });
  assert.ok(raw !== null);
  assert.equal(raw.external_id, "nvd_cve_fixture");
  assert.equal(raw.payload_ref, "fixtures/sources/nvd.sample.json");
  assert.equal(events[0]!.degraded_of, "fixture");
  const { items, warnings } = await parseNvd(raw);
  assert.equal(items.length, 1);
  assert.ok(warnings.every((w) => w.length > 0));
});

test("NVD: downtime windows split at official 120-day limit for BOTH modified and published dates", async () => {
  await withKey(async () => {
    const start = "2025-01-01T00:00:00Z", end = "2025-09-08T00:00:00Z";
    const { raw, urls } = await withFetch(() => ({ status: 200, body: page(1, ["CVE-2025-12345"]) }),
      () => fetchNvd({ window: { start, end }, pubWindow: { start, end } }));
    assert.ok(raw);
    assert.equal(urls.length, 6);
    const windows = windowsOf(await payloadOf(raw));
    for (const kind of ["lastMod", "pubDate"]) {
      const selected = windows.filter(w => w.kind === kind);
      assert.equal(selected[0]?.start, start);
      assert.equal(selected.at(-1)?.end, end);
      for (let i = 0; i < selected.length; i++) {
        const window = selected[i]!;
        assert.ok(Date.parse(String(window.end)) - Date.parse(String(window.start)) <= 120 * 86400_000);
        if (i) assert.equal(selected[i-1]?.end, window.start, "no downtime coverage gap");
      }
    }
    assert.equal((await payloadOf(raw)).coverage_complete, true);
  });
});

test("NVD: official empty dual windows remain live no_data with positive complete-coverage proof", async () => {
  await withKey(async () => {
    const events: FallbackEvent[] = [];
    const { raw } = await withFetch(() => ({ status: 404, body: { message: "No results found" } }),
      () => fetchNvd({ emit: e => { events.push(e); } }));
    assert.ok(raw); assert.ok(!raw.external_id.endsWith("_fixture"));
    assert.equal((await payloadOf(raw)).coverage_complete, true);
    assert.equal((await parseNvd(raw)).items.length, 0);
    assert.deepEqual(events, []);
  });
});

test("NVD: malformed successful response never masquerades as complete/no-results", async () => {
  await withKey(async () => {
    const { raw } = await withFetch(() => ({ status: 200, body: { totalResults: 0 } }), () => fetchNvd({ skipPubWindow: true }));
    assert.ok(raw);
    const payload = await payloadOf(raw);
    assert.equal(payload.partial, true);
    assert.equal(payload.coverage_complete, false);
    assert.ok(!raw.external_id.endsWith("_fixture"));
  });
});

test("NVD: empty/404 second page before reported total is explicit truncation", async () => {
  await withKey(async () => {
    const { raw } = await withFetch(url => Number(new URL(url).searchParams.get("startIndex")) === 0
      ? { status: 200, body: page(3000, ["CVE-2026-12345"]) } : { status: 404, body: {} }, () => fetchNvd({ skipPubWindow: true }));
    assert.ok(raw);
    const payload = await payloadOf(raw);
    assert.equal(payload.truncated, true);
    assert.equal(payload.coverage_complete, false);
  });
});

test("NVD: invalid/reversed second window is rejected before any network request", async () => {
  let calls = 0;
  await withKey(async () => {
    await assert.rejects(withFetch(() => { calls++; return { status: 200, body: page(0, []) }; }, () => fetchNvd({
      window: { start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z" },
      pubWindow: { start: "2026-02-01T00:00:00Z", end: "2026-01-01T00:00:00Z" },
    })), /Invalid NVD window/);
    assert.equal(calls, 0);
    assert.throws(() => splitNvdWindow("invalid", "2026-01-01T00:00:00Z"), /Invalid/);
  });
});

test("NVD: bounded multi-year catch-up explicitly records unqueried tail", async () => {
  // Advance the mocked clock between HTTP responses, not the production rate limiter.
  const realNow = Date.now;
  let clock = realNow() + 60_000;
  Date.now = () => clock;
  try {
    await withKey(async () => {
      const { raw, urls } = await withFetch(() => { clock += 31_000; return { status: 200, body: page(1, ["CVE-2020-12345"]) }; },
        () => fetchNvd({ skipPubWindow: true, window: { start: "2000-01-01T00:00:00Z", end: "2026-01-01T00:00:00Z" } }));
      assert.ok(raw);
      const payload = await payloadOf(raw);
      assert.equal(urls.length, 16);
      assert.equal(payload.unqueried_tail, true);
      assert.equal(payload.truncated, true);
      assert.equal(payload.coverage_complete, false);
    });
  } finally { Date.now = realNow; }
});
