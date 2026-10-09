/**
 * A-06 · 自愈演练 CLI（台账验收：ops/scripts/drill.sh 跑通 检测→降级→恢复→重放→验证 全链路）。
 * 全部离线：MemoryEventStore + 内存 Trace 桩（记录外发批次，零真实网络）。
 * 用法：npm run selfheal:drill
 */
import { EventBus, MemoryEventStore, LangfuseTraceSink } from "@safetrace/shared";
import type { DecisionReply, Envelope } from "@safetrace/shared";
import { SelfHealAgent } from "@safetrace/qa";

const failures: string[] = [];
function check(cond: boolean, label: string): void {
  console.log((cond ? "  PASS " : "  FAIL ") + label);
  if (!cond) failures.push(label);
}

async function main(): Promise<number> {
  console.log("== SafeTrace 自愈演练（A-06，离线） ==");

  // 演练独立的 store/bus：maxRetries=1 → 一次消费失败即死信（演示重投路径）
  const store = new MemoryEventStore();
  let agent: SelfHealAgent;
  const bus = new EventBus({
    store,
    maxRetries: 1,
    onDeadLetter: (eventId, reason) => agent?.noteDeadLetter(eventId, reason),
  });

  // Trace 外发桩：已配置（enabled=true）但只记录批次，零网络
  const sentBatches: unknown[] = [];
  const traceSink = new LangfuseTraceSink({
    url: "http://127.0.0.1:3000",
    publicKey: "drill-public",
    secretKey: "drill-secret",
    fetchImpl: (async (_input: string | URL | Request, init?: RequestInit) => {
      sentBatches.push(JSON.parse(String(init?.body ?? "{}")) as unknown);
      return new Response(JSON.stringify({ successes: [] }), { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
  });

  agent = new SelfHealAgent({
    bus,
    store,
    traceSink,
    backoff: { baseMs: 1000, maxMs: 60_000, maxAttempts: 8 },
  });
  agent.subscribeFallbackEvents();

  const replayed: Envelope[] = [];
  const report = await agent.drill({
    breakConsumer: () => bus.subscribe("decision.replies", async () => {
      throw new Error("drill: consumer is broken");
    }),
    fixConsumer: () => bus.subscribe("decision.replies", async (payload, env) => {
      replayed.push(env as Envelope);
      void payload;
    }),
    publishDrillEvent: async () => {
      const reply: DecisionReply = {
        decision_id: "dec_drill",
        kind: "q1_route",
        decision: { choice: "impact_range" },
        calibrated_prob: 0.9,
        decided_by: "rule_fallback",
        schema_version: "1.0",
      };
      return bus.publish("decision.replies", reply, { trace_id: "tr_selfheal_drill_event" });
    },
  });

  for (const step of report.steps) {
    check(step.ok, step.step + "：" + step.detail);
  }
  check(replayed.length === 1, "重放事件被恢复后的消费者实际处理（" + replayed.length + " 条）");
  check(agent.deadLetterNotifications.length >= 1, "总线死信通知到达 selfheal（" + agent.deadLetterNotifications.length + " 条）");
  check(sentBatches.length >= 1 && sentBatches.every((batch) => JSON.stringify(batch).includes("batch")),
    "Trace 外发批次已产生（" + sentBatches.length + " 批，零真实网络）");
  check(traceSink.stats().failed === 0, "Trace 外发零失败");

  console.log("");
  console.log("健康报告：" + JSON.stringify(report.health, null, 2));
  console.log("");
  console.log("== 演练结束 ==");
  if (!report.ok || failures.length > 0) {
    console.log("失败 " + failures.length + " 项：");
    for (const f of failures) console.log("  - " + f);
    return 1;
  }
  console.log("全部通过：检测→降级→重投失败→指数退避→恢复→重放销档→验证 全链路可复现");
  return 0;
}

main()
  .then((code) => { process.exitCode = code; })
  .catch((err: unknown) => {
    console.error("演练异常：" + (err instanceof Error ? err.stack ?? err.message : String(err)));
    process.exitCode = 1;
  });
