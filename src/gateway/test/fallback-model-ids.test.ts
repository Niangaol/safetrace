
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadModelsConfig } from "../src/profiles.js";

test("fallback to a real provider must use the declared real model id, not <provider>-fallback", () => {
  // 回归：MG1 曾把 fallback provider 的 model 名硬编码成 "<provider>-fallback"，
  // 云端没有这个模型 → HTTP 400，跨真实 provider 的降级实际不通。
  // 2026-09-30 由"本地模型缺失转云端 Tokendance"首次触发并修复。
  const cfg = loadModelsConfig("config/models.tokendance.yml");
  const embedder = cfg.roles.embedder;
  assert.equal(embedder.provider, "local_embed");
  assert.deepEqual(embedder.fallback_chain, ["tokendance", "cache"]);
  assert.ok(embedder.fallback_model_ids, "embedder 必须声明 fallback_model_ids，否则转云端会用假模型名");
  assert.equal(embedder.fallback_model_ids!.tokendance, "qwen3.7-text-embedding");
  // cache 不需要声明：它不校验模型名
  assert.equal(embedder.fallback_model_ids!.cache, undefined);
});

test("fallback_model_ids absent keeps legacy <provider>-fallback behavior for cache chains", () => {
  // 默认配置只降级到 cache，没有映射时应保持旧行为（不影响 cache）
  const cfg = loadModelsConfig("config/models.yml");
  assert.equal(cfg.roles.embedder.fallback_model_ids, undefined);
});
