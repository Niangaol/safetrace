/**
 * A-02 验收（HTTP）：/v1/decide 已挂接四层兜底阶梯。
 * 断言：
 *  1. 未注入 decideHandler 时明确 501（不假装能决策）；
 *  2. 注入后经 HTTP 返回契约形状的 DecisionReply（跑真实 schema 校验）；
 *  3. 下坠路径经 HTTP 仍同步留 FallbackEvent + decide.ladder lineage（可溯源）；
 *  4. 全链未决时 HTTP 同样返回 abstain 挂起，不伪造 choice。
 * 说明：handler 由问答线编排层注入，本测试只验路由与阶梯接线，不做任何网络调用。
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { EventBus, MemoryEventStore, validateInstance } from "@safetrace/shared";
import type { DecisionReply, DecisionRequest, FallbackEvent } from "@safetrace/shared";
import { createGatewayServer } from "@safetrace/gateway";
import { runDecisionLadder } from "../src/ladder/decision-ladder.js";

const ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const REPLY_SCHEMA = JSON.parse(
  readFileSync(join(ROOT, "contracts/schemas/DecisionReply.json"), "utf8"),
) as Parameters<typeof validateInstance>[1];

const REQ: DecisionRequest = {
  decision_id: "dec_http",
  kind: "q1_route",
  state: { question: "影响哪些版本？" },
  questions: [{ q_id: "q1", type: "choice", options: ["impact_range", "remediation"] }],
  trace_id: "tr_decide_http",
  schema_version: "1.0",
};

let store: MemoryEventStore;
let bus: EventBus;
let server: Server;
let base: string;

before(async () => {
  store = new MemoryEventStore();
  bus = new EventBus({ store });
  const created = createGatewayServer({
    bus,
    decideHandler: async (raw) => {
      const result = await runDecisionLadder(raw as DecisionRequest, {
        bus,
        rule: async () => ({ choice: "impact_range", score: 0.9 }),
      });
      return result.reply;
    },
  });
  server = created.server;
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

test("POST /v1/decide → 200，DecisionReply 通过冻结契约校验", async () => {
  const res = await fetch(base + "/v1/decide", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(REQ),
  });
  assert.equal(res.status, 200);
  const reply = (await res.json()) as DecisionReply;
  assert.deepEqual(validateInstance(reply, REPLY_SCHEMA), [], "HTTP 返回必须符合 DecisionReply 契约");
  assert.equal(reply.decision_id, "dec_http");
  assert.equal(reply.decided_by, "rule_fallback", "工具层未接入 → 规则层命中，如实记 rule_fallback");
  assert.equal(reply.decision.choice, "impact_range");
  assert.match(reply.fallback_reason ?? "", /tool:tool 层未接入/, "下坠原因必须显式进响应");
});

test("下坠路径经 HTTP 仍落 FallbackEvent 与 decide.ladder lineage", async () => {
  const falls = await store.read<FallbackEvent>("fallback.events");
  assert.ok(falls.some((e) => e.payload.degraded_of === "ladder:tool"), "阶梯下坠必须进总线");
  const lineage = await bus.readLineage("tr_decide_http");
  const ladderRecord = lineage.find((r) => r.stage === "decide.ladder");
  assert.ok(ladderRecord, "阶梯决策必须留 lineage");
  assert.equal(ladderRecord!.status, "degraded", "发生过下坠则 lineage status=degraded");
  assert.ok(ladderRecord!.input_refs.some((r) => r.kind === "DecisionRequest"));
  assert.ok(ladderRecord!.output_refs.some((r) => r.kind === "DecisionReply"));
  assert.ok(!JSON.stringify(lineage).includes("影响哪些版本"), "lineage 只存 hash，不复制决策输入正文");
});

test("全链未决 → 200 且 abstain 挂起，decided_by=human（不伪造 choice）", async () => {
  const localStore = new MemoryEventStore();
  const localBus = new EventBus({ store: localStore });
  const created = createGatewayServer({
    bus: localBus,
    decideHandler: async (raw) => (await runDecisionLadder(raw as DecisionRequest, { bus: localBus })).reply,
  });
  await new Promise<void>((resolve) => created.server.listen(0, "127.0.0.1", resolve));
  const localBase = "http://127.0.0.1:" + (created.server.address() as AddressInfo).port;
  try {
    const res = await fetch(localBase + "/v1/decide", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...REQ, decision_id: "dec_http_unresolved" }),
    });
    assert.equal(res.status, 200);
    const reply = (await res.json()) as DecisionReply;
    assert.deepEqual(validateInstance(reply, REPLY_SCHEMA), []);
    assert.equal(reply.decided_by, "human");
    assert.equal(reply.decision.abstain, true, "未决必须挂起，不得编造 choice");
    assert.equal(reply.decision.choice, undefined);
    const lineage = await localBus.readLineage("tr_decide_http");
    assert.equal(lineage.find((r) => r.stage === "decide.ladder")?.status, "review", "未决 lineage 必须标 review");
  } finally {
    await new Promise<void>((resolve) => created.server.close(() => resolve()));
  }
});

test("未注入 decideHandler → 501，不假装可决策", async () => {
  const created = createGatewayServer({ bus: new EventBus({ store: new MemoryEventStore() }) });
  await new Promise<void>((resolve) => created.server.listen(0, "127.0.0.1", resolve));
  const localBase = "http://127.0.0.1:" + (created.server.address() as AddressInfo).port;
  try {
    const res = await fetch(localBase + "/v1/decide", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(REQ),
    });
    assert.equal(res.status, 501);
    const body = (await res.json()) as { error: string };
    assert.equal(body.error, "not_implemented");
  } finally {
    await new Promise<void>((resolve) => created.server.close(() => resolve()));
  }
});
