/**
 * A-02 回归：人工工单队列（转人工后有人接）。
 * 口径：全链未决才入队（幂等）；人工决策过同一套契约校验并经 decision.replies
 * （decided_by=human）回流；工单不落私有 state；重复决单/非法形状显式抛错。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus, MemoryEventStore, SqliteEventStore } from "@safetrace/shared";
import type { DecisionReply, DecisionRequest } from "@safetrace/shared";
import { runDecisionLadder } from "../src/ladder/decision-ladder.js";
import { claimHumanTicket, resolveHumanTicket } from "../src/ladder/human-queue.js";

function request(over: Partial<DecisionRequest> = {}): DecisionRequest {
  return {
    decision_id: "dec_hq",
    kind: "q1_route",
    state: { question: "Log4Shell 影响哪些版本？", secret_marker: "private-do-not-store" },
    questions: [{ q_id: "q1", type: "choice", options: ["impact_range", "remediation"] }],
    trace_id: "tr_hq",
    schema_version: "1.1",
    ...over,
  };
}

test("A-02：全链未决入队人工工单（幂等、带 questions、不落私有 state）", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const first = await runDecisionLadder(request(), { bus, ticketStore: store });
  assert.equal(first.reply.decided_by, "human");
  assert.equal(first.reply.decision.abstain, true);
  assert.ok(first.ticket_id, "未决必须带回 ticket_id");
  const ticket = await store.getHumanTicket(first.ticket_id!);
  assert.ok(ticket);
  assert.equal(ticket!.status, "pending");
  assert.equal(ticket!.decision_id, "dec_hq");
  assert.deepEqual(ticket!.questions, request().questions);
  assert.match(ticket!.reason, /tool:unavailable/);
  assert.ok(!JSON.stringify(ticket).includes("private-do-not-store"), "私有 state 不得落工单");
  // 幂等：同一 decision_id 重放不产生第二张工单
  const replay = await runDecisionLadder(request(), { bus, ticketStore: store });
  assert.equal(replay.ticket_id, first.ticket_id);
  assert.equal((await store.listHumanTickets()).length, 1);
  // 人工决策回流后，总线可 replay 到 human 回复
  const replies = await store.read<DecisionReply>("decision.replies");
  assert.equal(replies.length, 1, "重发复用持久未决回执，不重复发布");
});

test("A-02：人工层已决时不入队（有人决策就不派单）", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const res = await runDecisionLadder(request(), {
    bus, ticketStore: store,
    human: async () => ({ choice: "impact_range", score: 0.9 }),
  });
  assert.equal(res.reply.decided_by, "human");
  assert.equal(res.reply.decision.choice, "impact_range");
  assert.equal(res.ticket_id, undefined, "人工层已决不得入队");
  assert.equal((await store.listHumanTickets()).length, 0);
});

test("A-02：未接 ticketStore 时只挂起不派单（显式无队列，不假装有人接）", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const res = await runDecisionLadder(request(), { bus });
  assert.equal(res.ticket_id, undefined);
  assert.equal(res.reply.decided_by, "human");
  const lineage = await store.readLineage("tr_hq");
  assert.ok(lineage.some((r) => /no ticket store attached/.test(r.decision?.reason ?? "")), "lineage 必须显式记录无队列");
});

test("A-02：人工决单——契约校验 + decision.replies 回流 + 销单 + lineage", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const pending = await runDecisionLadder(request(), { bus, ticketStore: store });
  const ticketId = pending.ticket_id!;
  // 接单
  const claimed = await claimHumanTicket(store, ticketId, "reviewer-a");
  assert.equal(claimed.status, "claimed");
  assert.equal(claimed.claimed_by, "reviewer-a");
  // 重复接单 → 抛错（不静默改状态）
  await assert.rejects(claimHumanTicket(store, ticketId, "reviewer-b"), /不能接单/);
  // 决单
  const result = await resolveHumanTicket({ store, bus, ticket_id: ticketId, resolver_id: "reviewer-a", decision: { choice: "remediation" }, rationale: "人工复核：按修复路径处置" });
  assert.equal(result.reply.decided_by, "human");
  assert.equal(result.reply.decision.choice, "remediation");
  assert.equal(result.reply.calibrated_prob, 1, "choice 记 1（与阶梯人工层同口径）");
  assert.equal(result.reply.fallback_reason, "人工复核：按修复路径处置");
  assert.equal(result.ticket.status, "resolved");
  assert.equal(result.ticket.resolved_by, "reviewer-a");
  assert.ok(result.ticket.reply_event_id, "销单必须关联 reply event_id");
  // 总线回放：human 回复在 decision.replies 里
  const replies = await store.read<DecisionReply>("decision.replies");
  const humanReply = replies.find((r) => r.payload.decided_by === "human" && r.payload.decision.choice === "remediation");
  assert.ok(humanReply, "人工决策必须落 decision.replies（可回放）");
  assert.equal(humanReply!.event_id, result.ticket.reply_event_id);
  // lineage：人工决单留痕且不复制私有 state
  const lineage = await store.readLineage("tr_hq");
  const resolveRow = lineage.find((r) => r.stage === "human.ticket_resolve");
  assert.ok(resolveRow && resolveRow.status === "success");
  assert.ok(!JSON.stringify(lineage).includes("private-do-not-store"), "lineage 不复制私有 state");
});

test("A-02：决单 fail-closed——不存在/重复决/形状非法都显式抛错", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  await assert.rejects(resolveHumanTicket({ store, bus, ticket_id: "ticket_missing", resolver_id: "r", decision: { abstain: true } }), /不存在/);
  const pending = await runDecisionLadder(request(), { bus, ticketStore: store });
  const ticketId = pending.ticket_id!;
  // 非法 choice（不在 options）
  await assert.rejects(resolveHumanTicket({ store, bus, ticket_id: ticketId, resolver_id: "r", decision: { choice: "not_an_option" } }), /未通过契约校验/);
  // score 越界
  await assert.rejects(resolveHumanTicket({ store, bus, ticket_id: ticketId, resolver_id: "r", decision: { score: 1.5 } }), /未通过契约校验/);
  // abstain 带 choice
  await assert.rejects(resolveHumanTicket({ store, bus, ticket_id: ticketId, resolver_id: "r", decision: { abstain: true, choice: "impact_range" } }), /未通过契约校验/);
  // 工单仍未决（非法尝试不改变状态）
  assert.equal((await store.getHumanTicket(ticketId))!.status, "pending");
  // 正常决单后重复决 → 抛错
  await resolveHumanTicket({ store, bus, ticket_id: ticketId, resolver_id: "r", decision: { choice: "impact_range" } });
  await assert.rejects(resolveHumanTicket({ store, bus, ticket_id: ticketId, resolver_id: "r2", decision: { choice: "remediation" } }), /不能重复决单/);
});

test("A-02：score/noul 工单的决单口径", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store });
  const scoreReq = request({ decision_id: "dec_score", questions: [{ q_id: "q1", type: "score" }] });
  const pending = await runDecisionLadder(scoreReq, { bus, ticketStore: store });
  const result = await resolveHumanTicket({ store, bus, ticket_id: pending.ticket_id!, resolver_id: "r", decision: { score: 0.42 } });
  assert.equal(result.reply.calibrated_prob, 0.42, "score 取原值");
  // noul：显式 abstain 才合法
  const noulReq = request({ decision_id: "dec_noul", questions: [{ q_id: "q1", type: "noul" }] });
  const noulPending = await runDecisionLadder(noulReq, { bus, ticketStore: store });
  await assert.rejects(resolveHumanTicket({ store, bus, ticket_id: noulPending.ticket_id!, resolver_id: "r", decision: { choice: "x" } }), /未通过契约校验/);
  const noulResolved = await resolveHumanTicket({ store, bus, ticket_id: noulPending.ticket_id!, resolver_id: "r", decision: { abstain: true } });
  assert.equal(noulResolved.reply.calibrated_prob, 0);
});

test("A-02：SQLite 工单跨重启保留（挂起→重开→决单）", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-ticket-"));
  const dbPath = join(dir, "safetrace.sqlite");
  try {
    const first = new SqliteEventStore(dbPath);
    const firstBus = new EventBus({ store: first });
    const pending = await runDecisionLadder(request(), { bus: firstBus, ticketStore: first });
    assert.ok(pending.ticket_id);
    first.close();
    const second = new SqliteEventStore(dbPath);
    const secondBus = new EventBus({ store: second });
    const tickets = await second.listHumanTickets("pending");
    assert.equal(tickets.length, 1);
    assert.equal(tickets[0]!.ticket_id, pending.ticket_id);
    const result = await resolveHumanTicket({ store: second, bus: secondBus, ticket_id: pending.ticket_id!, resolver_id: "reviewer-x", decision: { choice: "impact_range" } });
    assert.equal(result.ticket.status, "resolved");
    assert.equal((await second.listHumanTickets("resolved")).length, 1);
    second.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

for (const backend of ["memory", "sqlite"] as const) {
  test("A-02 原子决单/入队、身份与回执复用：" + backend, async () => {
    const dir = await mkdtemp(join(tmpdir(), "safetrace-atomic-ticket-"));
    const first = backend === "memory" ? new MemoryEventStore() : new SqliteEventStore(join(dir, "tickets.sqlite"));
    const second = backend === "memory" ? first : new SqliteEventStore(join(dir, "tickets.sqlite"));
    const busA = new EventBus({ store: first }), busB = new EventBus({ store: second });
    let delivered = 0;
    busA.subscribe("decision.replies", () => { delivered++; });
    busB.subscribe("decision.replies", () => { delivered++; });
    try {
      const queued = await Promise.all([
        runDecisionLadder(request(), { bus: busA, ticketStore: first }),
        runDecisionLadder(request(), { bus: busB, ticketStore: second }),
      ]);
      assert.equal(queued[0]!.ticket_id, queued[1]!.ticket_id);
      assert.equal((await first.read("decision.replies")).length, 1);
      assert.equal(delivered, 1);
      const id = queued[0]!.ticket_id!;
      const resolutions = await Promise.allSettled([
        resolveHumanTicket({ store: first, bus: busA, ticket_id: id, resolver_id: "a", decision: { choice: "impact_range" } }),
        resolveHumanTicket({ store: second, bus: busB, ticket_id: id, resolver_id: "b", decision: { choice: "remediation" } }),
      ]);
      assert.equal(resolutions.filter(x => x.status === "fulfilled").length, 1);
      const winner = resolutions.find(x => x.status === "fulfilled")!;
      assert.equal(winner.status, "fulfilled");
      if (winner.status !== "fulfilled") throw new Error("no winner");
      assert.equal((await first.read("decision.replies")).length, 2);
      assert.equal(delivered, 2);
      const replay = await runDecisionLadder(request(), { bus: busB, ticketStore: second, tool: async () => { throw new Error("must not run resolver"); } });
      assert.deepEqual(replay.reply, winner.value.reply);
      assert.equal(replay.ticket_id, undefined);
      for (const over of [
        { state: { question: "changed-private-state" } }, { trace_id: "changed-trace" },
        { kind: "q2_rerank" as DecisionRequest["kind"] },
        { questions: [{ q_id: "changed", type: "choice" as const, options: ["impact_range"] }] },
      ]) await assert.rejects(runDecisionLadder(request(over), { bus: busB, ticketStore: second }), /identity conflict/);
      assert.equal((await first.read("decision.replies")).length, 2);
      await assert.rejects(runDecisionLadder(request({ decision_id: "split-store" }), { bus: busA, ticketStore: new MemoryEventStore() }), /bus event store/);
    } finally {
      first.close(); if (second !== first) second.close();
      await rm(dir, { recursive: true, force: true });
    }
  });
}

test("A-02 提交后lineage失败也不丢reply：请求重发复用回执，不能再次执行resolver", async () => {
  const store = new MemoryEventStore(), bus = new EventBus({ store });
  const pending = await runDecisionLadder(request(), { bus, ticketStore: store });
  bus.recordLineage = async () => { throw new Error("audit storage unavailable"); };
  await assert.rejects(resolveHumanTicket({ store, bus, ticket_id: pending.ticket_id!, resolver_id: "r", decision: { choice: "remediation" } }), /audit storage unavailable/);
  assert.equal((await store.getHumanTicket(pending.ticket_id!))?.status, "resolved");
  const replay = await runDecisionLadder(request(), { bus, ticketStore: store, tool: async () => { throw new Error("must not rerun"); } });
  assert.equal(replay.reply.decision.choice, "remediation");
  assert.equal((await store.read("decision.replies")).length, 2);
});

test("A-02 决单过程中同请求已在执行阶梯：原子入队复用winner而非迟到abstain", async () => {
  const store = new MemoryEventStore(), bus = new EventBus({ store });
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const delayed = runDecisionLadder(request(), { bus, ticketStore: store, tool: async () => { entered(); await gate; return null; } });
  await ready;
  const pending = await runDecisionLadder(request(), { bus, ticketStore: store });
  const resolved = await resolveHumanTicket({ store, bus, ticket_id: pending.ticket_id!, resolver_id: "r", decision: { choice: "impact_range" } });
  release();
  const late = await delayed;
  assert.deepEqual(late.reply, resolved.reply);
  assert.equal(late.ticket_id, undefined);
  assert.equal((await store.read("decision.replies")).length, 2);
});
