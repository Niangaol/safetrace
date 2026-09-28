/** S2 情报总线事件信封（contracts/events.md 契约件）。 */
import { nextId } from "./time.js";

export const TOPICS = [
  "raw.docs", "intel.items", "dq.verdicts", "enrich.triage",
  "enrich.papers", "enrich.items", "qa.queries", "qa.answers",
  "decision.replies", "fallback.events",
] as const;

export type Topic = (typeof TOPICS)[number];

export interface Envelope<T = unknown> {
  event_id: string;
  topic: Topic;
  occurred_at: string;
  trace_id: string;
  causation_id: string | null;
  payload: T;
  schema_version: string;
}

/** 构造信封。causation_id 串联「哪个事件触发了本事件」，支撑一键回放。 */
export function makeEnvelope<T>(
  topic: Topic,
  payload: T,
  opts: { trace_id?: string; causation_id?: string | null; schema_version?: string } = {},
): Envelope<T> {
  return {
    event_id: nextId("ev"),
    topic,
    occurred_at: new Date().toISOString(),
    trace_id: opts.trace_id ?? nextId("tr"),
    causation_id: opts.causation_id ?? null,
    payload,
    schema_version: opts.schema_version ?? "1.0",
  };
}
