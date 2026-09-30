import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { EventBus, SqliteEventStore, sha256Json } from "@safetrace/shared";

async function main(): Promise<void> {
  const command = process.argv[2] ?? "";
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  await mkdir(dirname(dbPath), { recursive: true });
  const store = new SqliteEventStore(dbPath);
  const bus = new EventBus({ store });
  try {
    if (command === "list") {
      const cases = await bus.listPendingReviewCases();
      const output = await Promise.all(cases.map(async (review) => {
        const snapshot = await bus.getLastGoodPageSnapshotByHash(review.page_sha256);
        return { ...review, snapshot_available: Boolean(snapshot), snapshot_preview: snapshot?.text.slice(0, 600) };
      }));
      console.log(JSON.stringify({ pending: output.length, cases: output }, null, 2));
      return;
    }
    if (command !== "decide") {
      console.error("用法：npm run review:queue -- list\n      npm run review:queue -- decide <review_id> <accept|reject|defer> <reviewer_id> <reason>");
      process.exitCode = 2;
      return;
    }
    const reviewId = process.argv[3] ?? "";
    const rawAction = process.argv[4] ?? "";
    const reviewerId = process.argv[5] ?? "";
    const rationale = process.argv.slice(6).join(" ").trim();
    const action = rawAction === "accept" ? "accepted" : rawAction === "reject" ? "rejected" : rawAction === "defer" ? "deferred" : undefined;
    if (!reviewId || !action || !reviewerId || !rationale) throw new Error("review_id、accept/reject/defer、reviewer_id 和 reason 都必须提供");
    const review = await bus.getReviewCase(reviewId);
    if (!review) throw new Error("review case 不存在：" + reviewId);
    if (review.status === "accepted" || review.status === "rejected") throw new Error("review case 已终结：" + review.status);
    const decidedAt = new Date().toISOString();
    const decision = { action, reviewer_id: reviewerId, rationale };
    const lineage = await bus.recordLineage({
      trace_id: review.trace_id,
      parent_lineage_ids: [review.lineage_id],
      stage: "human.review_decision",
      operation_version: "human-review-cli.v1",
      status: action === "deferred" ? "review" : "success",
      started_at: decidedAt,
      input_refs: [{ kind: "ReviewCase", id: review.review_id, sha256: sha256Json({ review_id: review.review_id, source_url: review.source_url, page_sha256: review.page_sha256, reason: review.reason }) }],
      output_refs: [{ kind: "ReviewDecision", id: review.review_id, sha256: sha256Json(decision) }],
      decision: { reason: rationale, review_required: action === "deferred" },
    });
    const applied = await bus.appendReviewCaseDecision({
      review_id: review.review_id,
      trace_id: review.trace_id,
      action,
      reviewer_id: reviewerId,
      rationale,
      lineage_id: lineage.lineage_id,
      recorded_at: decidedAt,
    });
    if (!applied) {
      await bus.recordLineage({
        trace_id: review.trace_id,
        parent_lineage_ids: [lineage.lineage_id],
        stage: "human.review_decision_apply",
        operation_version: "human-review-cli.v1",
        status: "rejected",
        input_refs: [{ kind: "ReviewCase", id: review.review_id, sha256: review.page_sha256 }],
        decision: { reason: "case was already resolved or disappeared" },
      });
      throw new Error("review decision was recorded but could not change queue state");
    }
    console.log(JSON.stringify({ review_id: review.review_id, status: action, trace_id: review.trace_id, lineage_id: lineage.lineage_id }, null, 2));
  } finally {
    store.close();
  }
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
