/**
 * A-06 常驻自愈守护进程（台账尾项：转人工/自愈不能只在演练里发生）。
 *
 * 用法：npm run selfheal:daemon
 * 环境变量：
 *   SQLITE_PATH           事件/死信/lineage 库（缺省 ./var/safetrace.sqlite）
 *   SELFHEAL_INTERVAL_MS  拍间隔毫秒（缺省 60000，最小 1000）
 *
 * 行为：订阅 fallback.events（登记 + lineage + Trace 外发，兜底透明率 100%）；
 * 每拍 dead_letter_drain（指数退避重投、成功销档）+ healthcheck 聚合；
 * 每拍一行 JSON 摘要到 stdout 并追加 var/selfheal-daemon.log；
 * SIGINT/SIGTERM 优雅停止（退订阅 + 末次 healthcheck + 关库）。
 * 零网络（未配 Trace 就不外发）、零 provider SDK、只监听本机 SQLite。
 */
import { appendFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { EventBus, SqliteEventStore, nowIso } from "@safetrace/shared";
import { SelfHealDaemon } from "@safetrace/qa";

async function main(): Promise<void> {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  const intervalMs = Number(process.env.SELFHEAL_INTERVAL_MS ?? "60000");
  if (!Number.isFinite(intervalMs) || intervalMs < 1000) {
    throw new Error("SELFHEAL_INTERVAL_MS 必须是 >= 1000 的毫秒数（当前：" + String(process.env.SELFHEAL_INTERVAL_MS) + "）");
  }
  const logPath = resolve("var/selfheal-daemon.log");
  await mkdir(resolve("var"), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  let daemon: SelfHealDaemon;
  const bus = new EventBus({
    store,
    // 总线死信通知进自愈 Agent（与 store 死信表双视图）
    onDeadLetter: (eventId, reason) => daemon?.agent.noteDeadLetter(eventId, reason),
  });
  daemon = new SelfHealDaemon({
    bus,
    store,
    intervalMs,
    backoff: { baseMs: 1000, maxMs: 300_000, maxAttempts: 8 },
    onTick: async (report) => {
      const line = JSON.stringify({
        event: "selfheal_tick",
        at: report.at,
        drain: {
          examined: report.drain.examined,
          retried: report.drain.retried,
          recovered: report.drain.recovered,
          deferred: report.drain.deferred,
          still_failed: report.drain.still_failed,
        },
        health: {
          status: report.health.status,
          dead_letters: report.health.dead_letters,
          retry_scheduled: report.health.retry_scheduled,
          fallback_events: report.health.fallback_events.total,
          circuits_observed: report.health.circuits_observed,
          trace: report.health.trace,
        },
      });
      console.log(line);
      await appendFile(logPath, line + "\n", "utf8");
    },
  });
  daemon.start();
  console.log(JSON.stringify({
    event: "selfheal_daemon_started",
    at: nowIso(),
    db_path: dbPath,
    interval_ms: intervalMs,
    log_path: logPath,
    note: "订阅 fallback.events + 周期 drain/healthcheck；SIGINT/SIGTERM 优雅停止",
  }));

  const shutdown = (signal: string): void => {
    console.log(JSON.stringify({ event: "selfheal_daemon_stopping", at: nowIso(), signal }));
    daemon.stop();
    void daemon.agent.healthcheck()
      .then((health) => {
        console.log(JSON.stringify({
          event: "selfheal_daemon_stopped",
          at: nowIso(),
          ticks: daemon.ticks,
          registered_fallbacks: daemon.agent.registeredFallbackEvents.length,
          dead_letters: health.dead_letters,
          retry_scheduled: health.retry_scheduled,
        }));
      })
      .catch((error: unknown) => {
        // 停止路径不因健康检查失败而挂住：显式记录后照样关库退出
        console.error(JSON.stringify({ event: "selfheal_daemon_stop_healthcheck_failed", at: nowIso(), error: error instanceof Error ? error.message : String(error) }));
      })
      .finally(() => {
        store.close();
        process.exit(0);
      });
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});