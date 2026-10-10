import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { spawn } from "node:child_process";
import { MemoryEventStore, SqliteEventStore } from "../src/store.js";
import type { HumanTicket } from "../src/store.js";
import { makeEnvelope } from "../src/envelope.js";
import type { DecisionReply } from "../src/types.js";

const ticket: HumanTicket = { ticket_id: "ticket_dec", decision_id: "dec", trace_id: "tr", kind: "q1_route", questions: [{ q_id: "q", type: "choice", options: ["a", "b"] }], status: "pending", reason: "unresolved", created_at: "2026-01-01" };
const reply: DecisionReply = { decision_id: "dec", kind: "q1_route", decision: { abstain: true }, calibrated_prob: 0, decided_by: "human", schema_version: "1.1" };
const envelope = (payload = reply) => makeEnvelope("decision.replies", payload, { trace_id: "tr" });

test("SQLite atomic ticket failure rolls back event and state at either write boundary", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-ticket-failure-"));
  const path = join(dir, "failure.sqlite");
  const store = new SqliteEventStore(path), faults = new DatabaseSync(path);
  try {
    faults.exec("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'event storage unavailable'); END;");
    await assert.rejects(store.enqueueHumanTicketWithReply(ticket, envelope()), /event storage unavailable/);
    assert.equal(await store.getHumanTicket(ticket.ticket_id), undefined);
    assert.deepEqual(await store.read("decision.replies"), []);
    faults.exec("DROP TRIGGER fail_event");
    await store.enqueueHumanTicketWithReply(ticket, envelope());
    faults.exec("CREATE TRIGGER fail_resolve BEFORE UPDATE ON human_tickets BEGIN SELECT RAISE(ABORT, 'ticket storage unavailable'); END;");
    await assert.rejects(store.resolveHumanTicketWithReply(ticket.ticket_id, "r", "now", envelope({ ...reply, decision: { choice: "a" }, calibrated_prob: 1 })), /ticket storage unavailable/);
    assert.equal((await store.getHumanTicket(ticket.ticket_id))?.status, "pending");
    assert.equal((await store.read("decision.replies")).length, 1, "rolled back reply despite inserting before failing UPDATE");
    faults.exec("DROP TRIGGER fail_resolve");
    assert.equal(await store.resolveHumanTicketWithReply(ticket.ticket_id, "r", "now", envelope({ ...reply, decision: { choice: "b" }, calibrated_prob: 1 })), true);
    assert.equal((await store.getHumanTicketReceipt(ticket.ticket_id))?.payload.decision.choice, "b");
  } finally { faults.close(); store.close(); await rm(dir, { recursive: true, force: true }); }
});

test("Memory fallible clone cannot leave orphan event or resolved state", async () => {
  const store = new MemoryEventStore();
  const badTicket = { ...ticket, questions: [{ ...ticket.questions[0]!, invalidFunction: () => {} }] };
  await assert.rejects(store.enqueueHumanTicketWithReply(badTicket, envelope()));
  assert.equal(await store.getHumanTicket(ticket.ticket_id), undefined);
  assert.deepEqual(await store.read("decision.replies"), []);
  await store.enqueueHumanTicketWithReply(ticket, envelope());
  const badReply = envelope();
  (badReply.payload as unknown as Record<string, unknown>).invalidFunction = () => {};
  await assert.rejects(store.resolveHumanTicketWithReply(ticket.ticket_id, "r", "now", badReply));
  assert.equal((await store.getHumanTicket(ticket.ticket_id))?.status, "pending");
  assert.equal((await store.read("decision.replies")).length, 1);
});

for (const backend of ["memory", "sqlite"] as const) {
  test("legacy human request identity fails closed: " + backend, async () => {
    const store = backend === "memory" ? new MemoryEventStore() : new SqliteEventStore();
    try {
      await store.enqueueHumanTicket(ticket);
      await assert.rejects(store.bindDecisionRequest("dec", "unknown-request-hash"), /legacy.*identity unavailable/);
    } finally { store.close(); }
  });
}

test("SQLite separate OS processes resolve only one winner and one durable reply", async () => {
  const dir = await mkdtemp(join(tmpdir(), "safetrace-ticket-processes-"));
  const path = join(dir, "process.sqlite");
  const store = new SqliteEventStore(path);
  const children: ReturnType<typeof spawn>[] = [];
  try {
    await store.enqueueHumanTicketWithReply(ticket, envelope());
    const source =       'import { SqliteEventStore } from ' + JSON.stringify(new URL("../src/store.ts", import.meta.url).href) + ';' +
      'import { makeEnvelope } from ' + JSON.stringify(new URL("../src/envelope.ts", import.meta.url).href) + ';' +
      'const store = new SqliteEventStore(process.argv[1]); process.send("ready");' +
      'process.once("message", async () => { try { const reply = JSON.parse(process.argv[2]); const env = makeEnvelope("decision.replies", reply, {trace_id:"tr"}); const result = await store.resolveHumanTicketWithReply("ticket_dec", reply.decision.choice, "now", env); process.send(result); store.close(); process.disconnect(); } catch(e) { console.error(e); process.exit(1); } });';
    const runs = ["a", "b"].map(choice => {
      const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", source, path, JSON.stringify({ ...reply, decision: { choice }, calibrated_prob: 1 })], { stdio: ["ignore", "ignore", "pipe", "ipc"] });
      children.push(child);
      let stderr = ""; child.stderr!.on("data", data => { stderr += data; });
      let readyResolve!: () => void, resultResolve!: (value: boolean) => void;
      let readyReject!: (error: Error) => void, resultReject!: (error: Error) => void;
      const ready = new Promise<void>((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
      const result = new Promise<boolean>((resolve, reject) => { resultResolve = resolve; resultReject = reject; });
      let outcome: boolean | undefined;
      child.on("message", message => { if (message === "ready") readyResolve(); else outcome = message as boolean; });
      child.on("error", error => { readyReject(error); resultReject(error); });
      child.on("exit", code => {
        if (code !== 0 || outcome === undefined) { const error = new Error("worker exit " + code + ": " + stderr); readyReject(error); resultReject(error); }
        else resultResolve(outcome);
      });
      return { ready, result, child };
    });
    await Promise.all(runs.map(run => run.ready));
    for (const run of runs) run.child.send("resolve");
    assert.deepEqual((await Promise.all(runs.map(run => run.result))).sort(), [false, true]);
    const replies = await store.read<DecisionReply>("decision.replies");
    assert.equal(replies.length, 2);
    const resolved = await store.getHumanTicket(ticket.ticket_id);
    assert.equal(resolved?.status, "resolved");
    assert.equal(resolved?.reply_event_id, replies[1]!.event_id);
  } finally { for (const child of children) if (child.exitCode === null) child.kill(); store.close(); await rm(dir, { recursive: true, force: true }); }
});
