import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { EventBus, MemoryEventStore, SqliteEventStore, validateInstance } from "@safetrace/shared";
import type { DecisionReply, DecisionRequest } from "@safetrace/shared";
import { createGatewayServer } from "@safetrace/gateway";
import { createStepPlanDecisionHandler } from "../src/ladder/stepfun-decision.js";
import { claimHumanTicket, resolveHumanTicket } from "../src/ladder/human-queue.js";

const request: DecisionRequest = {
  decision_id: "dec_http_ticket", kind: "q1_route", trace_id: "tr_http_ticket",
  state: { question: "private-request-body-must-not-enter-ticket", tenant_id: "private-tenant" },
  questions: [{ q_id: "q1", type: "choice", options: ["impact_range", "remediation"] }],
  schema_version: "1.1",
};
const options = { provider: "cache", modelId: "cache-planner", apiKeyConfigured: false };

async function serve(store: MemoryEventStore | SqliteEventStore, ticketStore = store) {
  const bus = new EventBus({ store });
  const handler = createStepPlanDecisionHandler({ ...options, bus, ticketStore });
  const app = createGatewayServer({ bus, port: 0, host: "127.0.0.1", decideHandler: handler });
  await app.listen();
  return {
    bus, base: "http://127.0.0.1:" + (app.server.address() as AddressInfo).port,
    close: () => new Promise<void>((resolve, reject) => app.server.close(e => e ? reject(e) : resolve())),
  };
}
async function decide(base: string, body: unknown) {
  return fetch(base + "/v1/decide", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
}

test("A-02 HTTP 实际处理器：未决工单持久化、重复请求不重复入队、重启后可人工决单", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-http-ticket-"));
  const path = join(dir, "tickets.sqlite");
  try {
    const first = new SqliteEventStore(path);
    const app = await serve(first);
    try {
      const response = await decide(app.base, request);
      assert.equal(response.status, 200);
      const reply = await response.json() as DecisionReply;
      const schema = JSON.parse(await readFile(new URL("../../../contracts/schemas/DecisionReply.json", import.meta.url), "utf8"));
      assert.deepEqual(validateInstance(reply, schema), []);
      assert.equal(reply.decided_by, "human");
      assert.equal(reply.decision.abstain, true);
      // HTTP 响应保持冻结的 DecisionReply 形状，不额外注入 ticket_id。
      assert.ok(!("ticket_id" in reply));
      assert.equal((await decide(app.base, request)).status, 200);
      const tickets = await first.listHumanTickets("pending");
      assert.equal(tickets.length, 1);
      assert.equal(tickets[0]!.ticket_id, "ticket_" + request.decision_id);
      assert.deepEqual(tickets[0]!.questions, request.questions);
      assert.ok(!JSON.stringify(tickets).includes("private-request-body"));
      assert.ok(!JSON.stringify(tickets).includes("private-tenant"));
    } finally { await app.close(); first.close(); }

    const second = new SqliteEventStore(path);
    const restarted = await serve(second);
    try {
      const id = "ticket_" + request.decision_id;
      assert.equal((await second.getHumanTicket(id))?.status, "pending");
      await claimHumanTicket(second, id, "local-reviewer");
      const resolved = await resolveHumanTicket({ store: second, bus: restarted.bus,
        ticket_id: id, resolver_id: "local-reviewer", decision: { choice: "remediation" } });
      assert.equal(resolved.ticket.status, "resolved");
      assert.equal(resolved.reply.decided_by, "human");
      const replies = await second.read<DecisionReply>("decision.replies", 0, 100);
      assert.ok(replies.some(e => e.event_id === resolved.ticket.reply_event_id && e.payload.decision.choice === "remediation"));
      // 既有工单不因同一请求重发而被重新打开。
      const replay = await decide(restarted.base, request);
      assert.equal(replay.status, 200);
      assert.deepEqual(await replay.json(), resolved.reply);
      assert.equal((await second.read("decision.replies")).length, 2);
      assert.equal((await decide(restarted.base, { ...request, trace_id: "different-trace" })).status, 503);
      assert.equal((await second.getHumanTicket(id))?.status, "resolved");
      assert.equal((await second.listHumanTickets()).length, 1);
    } finally { await restarted.close(); second.close(); }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("A-02 处理器：规则已决、非法请求不会生成工单", async () => {
  const store = new MemoryEventStore();
  const app = await serve(store);
  try {
    assert.equal((await decide(app.base, { ...request, unexpected: true })).status, 400);
    assert.equal((await store.listHumanTickets()).length, 0);
    const response = await decide(app.base, { ...request, state: {
      public_facts: { rule_candidate: "impact_range" }, calibration_source: "rule",
      calibrated_option_probabilities: { impact_range: 0.9, remediation: 0.1 },
    }});
    assert.equal(response.status, 200);
    assert.equal((await response.json() as DecisionReply).decided_by, "rule_fallback");
    assert.equal((await store.listHumanTickets()).length, 0);
  } finally { await app.close(); store.close(); }
});

test("A-02 处理器：工单落库失败显式失败，不能返回成功冒充已交接", async () => {
  const store = new MemoryEventStore();
  store.enqueueHumanTicketWithReply = async () => { throw new Error("ticket storage unavailable"); };
  const app = await serve(store);
  try {
    const response = await decide(app.base, request);
    assert.equal(response.status, 503);
    assert.equal((await response.json() as { degraded_to: string }).degraded_to, "request_failed");
    assert.equal((await store.listHumanTickets()).length, 0);
    assert.equal((await store.read("decision.replies")).length, 0, "入队失败不得孤立未决event");
  } finally { await app.close(); store.close(); }
});

test("A-02 生产启动脚本注入与事件总线同库的 ticketStore", async () => {
  const source = await readFile(new URL("../../../scripts/qa-decision-server.ts", import.meta.url), "utf8");
  assert.match(source, /ticketStore:\s*store/);
});
