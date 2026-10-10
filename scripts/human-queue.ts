/**
 * A-02 人工工单队列 CLI（转人工后有人接：list / claim / decide）。
 * 用法：
 *   npm run human:queue -- list [--status pending|claimed|resolved]
 *   npm run human:queue -- claim <ticket_id> <who>
 *   npm run human:queue -- decide <ticket_id> <who> (--choice <opt> | --score <0-1> | --abstain) [--reason <text>]
 * 工单只含 typed questions 与轨迹 id（私有 state 不落库）；人工决策经
 * decision.replies（decided_by=human）回流，可回放。
 */
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, SqliteEventStore } from "@safetrace/shared";
import { claimHumanTicket, resolveHumanTicket } from "../src/qa/src/ladder/human-queue.js";

function arg(name: string): string | undefined {
  const idx = process.argv.indexOf("--" + name);
  if (idx === -1) return undefined;
  return process.argv[idx + 1];
}

async function main(): Promise<void> {
  const command = process.argv[2] ?? "";
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  try {
    if (command === "list") {
      const status = arg("status");
      if (status !== undefined && !["pending", "claimed", "resolved"].includes(status)) throw new Error("status 只能是 pending/claimed/resolved");
      const tickets = await store.listHumanTickets(status as "pending" | undefined);
      console.log(JSON.stringify({
        count: tickets.length,
        tickets: tickets.map((t) => ({
          ticket_id: t.ticket_id,
          decision_id: t.decision_id,
          trace_id: t.trace_id,
          kind: t.kind,
          status: t.status,
          reason: t.reason,
          questions: t.questions,
          created_at: t.created_at,
          ...(t.claimed_by ? { claimed_by: t.claimed_by, claimed_at: t.claimed_at } : {}),
          ...(t.resolved_by ? { resolved_by: t.resolved_by, resolved_at: t.resolved_at, reply_event_id: t.reply_event_id } : {}),
        })),
      }, null, 2));
      return;
    }
    if (command === "claim") {
      const ticketId = process.argv[3] ?? "";
      const who = process.argv[4] ?? "";
      if (!ticketId || !who) throw new Error("用法：claim <ticket_id> <who>");
      const ticket = await claimHumanTicket(store, ticketId, who);
      console.log(JSON.stringify({ ticket_id: ticket.ticket_id, status: ticket.status, claimed_by: ticket.claimed_by, claimed_at: ticket.claimed_at }, null, 2));
      return;
    }
    if (command !== "decide") {
      console.error("用法：npm run human:queue -- list [--status pending]\n      npm run human:queue -- claim <ticket_id> <who>\n      npm run human:queue -- decide <ticket_id> <who> (--choice <opt> | --score <0-1> | --abstain) [--reason <text>]");
      process.exitCode = 2;
      return;
    }
    const ticketId = process.argv[3] ?? "";
    const who = process.argv[4] ?? "";
    if (!ticketId || !who) throw new Error("用法：decide <ticket_id> <who> ...");
    const choice = arg("choice");
    const scoreRaw = arg("score");
    const abstain = process.argv.includes("--abstain");
    const modes = [choice !== undefined, scoreRaw !== undefined, abstain].filter(Boolean).length;
    if (modes !== 1) throw new Error("必须且只能给出一种决策：--choice <opt> / --score <0-1> / --abstain");
    let decision: { choice?: string; score?: number; abstain?: boolean };
    if (abstain) decision = { abstain: true };
    else if (choice !== undefined) decision = { choice };
    else {
      const score = Number(scoreRaw);
      if (!Number.isFinite(score) || score < 0 || score > 1) throw new Error("--score 必须是 0-1 的数");
      decision = { score };
    }
    const result = await resolveHumanTicket({ store, bus, ticket_id: ticketId, resolver_id: who, decision, ...(arg("reason") ? { rationale: arg("reason") } : {}) });
    console.log(JSON.stringify({
      ticket_id: result.ticket.ticket_id,
      status: result.ticket.status,
      resolved_by: result.ticket.resolved_by,
      reply: { decision_id: result.reply.decision_id, decided_by: result.reply.decided_by, decision: result.reply.decision, calibrated_prob: result.reply.calibrated_prob },
    }, null, 2));
  } finally {
    store.close();
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});