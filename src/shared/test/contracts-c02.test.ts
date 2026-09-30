/**
 * C-02 契约回归：RetrievalResponse chunk 追加可选 published_at + trust。
 * 只读契约并校验实例，不改冻结契约语义（纯追加，旧字段与 required 不变）。
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateInstance } from "../src/schema.js";

const ROOT = dirname(dirname(dirname(dirname(fileURLToPath(import.meta.url)))));
const read = (rel: string): string => readFileSync(join(ROOT, rel), "utf8");
const parse = (rel: string): unknown => JSON.parse(read(rel)) as unknown;

test("chunk 追加可选发布/信任字段，required 与既有字段不变", () => {
  const schema = parse("contracts/schemas/RetrievalResponse.json") as {
    properties: { chunks: { items: { required: string[]; properties: Record<string, unknown> } } };
  };
  const chunk = schema.properties.chunks.items;
  assert.deepEqual(chunk.required, ["chunk_id", "doc_type", "text", "provenance", "score_rerank"], "既有必填集合不得改动");
  assert.ok("published_at" in chunk.properties && "trust" in chunk.properties, "两个新字段必须存在");
  assert.ok(!chunk.required.includes("published_at") && !chunk.required.includes("trust"), "新字段必须可选，否则旧生产者直接破坏");
  const top = parse("contracts/schemas/RetrievalResponse.json") as { properties: Record<string, unknown> };
  assert.ok("degraded_to" in top.properties, "既有顶层字段保留");
  const mirror = read("src/shared/src/types.ts");
  assert.match(mirror, /published_at\?: string;/, "TS 镜像需同步 published_at");
  assert.match(mirror, /export type TrustLevel = "trusted" \| "untrusted";/, "TS 镜像需同步 TrustLevel");
});

test("带新字段与不带新字段的实例都通过；未知信任级被拒", () => {
  const schema = parse("contracts/schemas/RetrievalResponse.json") as Parameters<typeof validateInstance>[1];
  const base = parse("fixtures/retrievalresponse.sample.json");
  assert.deepEqual(validateInstance(base, schema), [], "更新后的样例必须通过");
  const sample = base as { chunks: Array<Record<string, unknown>> };
  assert.equal(sample.chunks[0]!.trust, "trusted");
  assert.equal(sample.chunks[0]!.published_at, "2021-12-10T10:15:08.540Z");
  const legacy = JSON.parse(JSON.stringify(base)) as { chunks: Array<Record<string, unknown>> };
  delete legacy.chunks[0]!.published_at;
  delete legacy.chunks[0]!.trust;
  assert.deepEqual(validateInstance(legacy, schema), [], "旧形状（无新字段）必须仍然合法，保证向后兼容");
  const bad = JSON.parse(JSON.stringify(base)) as { chunks: Array<Record<string, unknown>> };
  bad.chunks[0]!.trust = "maybe";
  const errors = validateInstance(bad, schema);
  assert.ok(errors.length > 0, "未知信任级必须被拒");
  const badDate = JSON.parse(JSON.stringify(base)) as { chunks: Array<Record<string, unknown>> };
  badDate.chunks[0]!.published_at = "not-a-date";
  assert.ok(validateInstance(badDate, schema).length > 0, "非法发布时间必须被拒");
});
