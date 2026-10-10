import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventBus } from "../src/bus.js";
import { MemoryEventStore, SqliteEventStore } from "../src/store.js";
import { SelfHealDaemon } from "../../qa/src/orchestrator/selfheal-daemon.js";

for (const sqlite of [false, true]) {
  test("A-06 " + (sqlite ? "SQLite" : "Memory") + "：独立总线无消费者不销档，真实消费者恢复后才清除死信", async () => {
    const dir = await mkdtemp(join(tmpdir(), "safetrace-redelivery-"));
    const store = sqlite ? new SqliteEventStore(join(dir, "events.sqlite")) : new MemoryEventStore();
    try {
      const producer = new EventBus({ store, maxRetries: 1 });
      producer.subscribe("decision.replies", () => { throw new Error("broken original consumer"); });
      const envelope = await producer.publish("decision.replies", { decision_id: "test_dl" });
      assert.equal((await store.deadLetters()).length, 1);
      const isolated = new EventBus({ store });
      let now = 1_800_000_000_000;
      const daemon = new SelfHealDaemon({ bus: isolated, store, now: () => now });
      const noConsumer = await daemon.tick();
      assert.equal(noConsumer.drain.recovered, 0);
      assert.equal(noConsumer.health.dead_letters, 1);
      assert.equal(await isolated.redeliver(envelope), false);
      assert.equal((await store.deadLetters()).length, 1);

      const release = isolated.subscribe("decision.replies", () => {});
      release(); // 空 Set 也不是实际消费者。
      assert.equal(await isolated.redeliver(envelope), false);
      assert.equal((await store.deadLetters()).length, 1);
      let delivered = 0;
      isolated.subscribe("decision.replies", () => { delivered++; });
      now += 1500;
      const recovered = await daemon.tick();
      assert.equal(recovered.drain.recovered, 1);
      assert.equal(delivered, 1);
      assert.equal((await store.deadLetters()).length, 0);
      assert.equal((await store.read("decision.replies")).length, 1, "重投不重复 append");
    } finally { store.close(); await rm(dir, { recursive: true, force: true }); }
  });
}

test("A-06：存在失败消费者仍保留死信，所有当前消费者成功才销档", async () => {
  const store = new MemoryEventStore();
  const bus = new EventBus({ store, maxRetries: 1 });
  const failing = bus.subscribe("decision.replies", () => { throw new Error("still broken"); });
  bus.subscribe("decision.replies", () => {});
  const envelope = await bus.publish("decision.replies", { decision_id: "test_all" });
  assert.equal(await bus.redeliver(envelope), false);
  assert.equal((await store.deadLetters()).length, 1);
  failing();
  assert.equal(await bus.redeliver(envelope), true);
  assert.equal((await store.deadLetters()).length, 0);
});
