import type { EnrichmentResult, FallbackEvent, IntelItem, QualityVerdict } from "@safetrace/shared";

/** A successful empty result is not a source failure; EPSS failures do not trip the arXiv cutoff. */
export function nextArxivFailureStreak(previous: number, events: readonly Pick<FallbackEvent, "trigger">[]): number {
  return events.some(event => event.trigger.startsWith("arxiv_")) ? previous + 1 : 0;
}

/** Events are append-only: last verdict wins; historical passes do not authorize later quarantines. */
export function planPendingEnrichment(
  intelEvents: readonly IntelItem[], verdictEvents: readonly QualityVerdict[], enrichEvents: readonly EnrichmentResult[],
) {
  const latestIntel = new Map(intelEvents.map(item => [item.intel_id, item]));
  const latestVerdicts = new Map(verdictEvents.map(item => [item.item_id, item]));
  const latestEnriched = new Map(enrichEvents.map(item => [item.intel_id, item]));
  const accepted = [...latestIntel.values()].filter(item => {
    const verdict = latestVerdicts.get(item.intel_id)?.verdict;
    return verdict === "pass" || verdict === "degrade";
  });
  return {
    unique_intel_ids: latestIntel.size,
    accepted_ids: accepted.length,
    accepted_items: accepted,
    already_enriched: accepted.filter(item => latestEnriched.has(item.intel_id)).length,
    recorded_with_failed_dimensions: accepted.filter(item => (latestEnriched.get(item.intel_id)?.dimensions_failed.length ?? 0) > 0).length,
    pending: accepted.filter(item => !latestEnriched.has(item.intel_id)),
  };
}
