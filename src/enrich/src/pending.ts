import { enrichmentInputHash, enrichmentRetryDue, sha256Json } from "@safetrace/shared";
import type { EnrichmentResult, FallbackEvent, IntelItem, QualityVerdict, EnrichmentDimensionState, EnrichmentDimension } from "@safetrace/shared";

/** A successful empty result is not a source failure; EPSS failures do not trip the arXiv cutoff. */
export function nextArxivFailureStreak(previous: number, events: readonly Pick<FallbackEvent, "trigger">[]): number {
  return events.some(event => event.trigger.startsWith("arxiv_")) ? previous + 1 : 0;
}

/** Events are append-only: last verdict wins; historical passes do not authorize later quarantines. */
export function planPendingEnrichment(
  intelEvents: readonly IntelItem[], verdictEvents: readonly QualityVerdict[], enrichEvents: readonly EnrichmentResult[],
  options: { states?: readonly EnrichmentDimensionState[]; now?: Date; publishedEnrichments?: readonly { event_id: string; payload: EnrichmentResult }[]; currentIntelEventIds?: ReadonlyMap<string, string>; dimensions?: readonly EnrichmentDimension[]; cvssDependencyHashes?: ReadonlyMap<string, string> } = {},
) {
  const latestIntel = new Map(intelEvents.map(item => [item.intel_id, item]));
  const latestVerdicts = new Map(verdictEvents.filter(item => item.item_kind === "intel").map(item => [item.item_id, item]));
  const latestEnriched = new Map(enrichEvents.map(item => [item.intel_id, item]));
  const accepted = [...latestIntel.values()].filter(item => {
    const verdict = latestVerdicts.get(item.intel_id)?.verdict;
    return verdict === "pass" || verdict === "degrade";
  });
  const latestDQ = latestVerdicts;
  const stateMap = new Map((options.states ?? []).map(state => [state.intel_id + ":" + state.dimension, state]));
  const published = new Map((options.publishedEnrichments ?? []).map(event => [event.payload.intel_id, event]));
  const isPublishedCurrent = (state: EnrichmentDimensionState): boolean => {
    const item = latestIntel.get(state.intel_id), receipt = published.get(state.intel_id);
    if (!item || !accepted.some(candidate => candidate.intel_id === state.intel_id) || state.status !== "live" || !receipt || !state.enrich_event_id
      || receipt.event_id !== state.enrich_event_id || state.input_hash !== enrichmentInputHash(item) || state.result_hash !== sha256Json(state.artifact)) return false;
    const artifacts = receipt.payload.artifacts;
    const artifact = state.dimension === "paper" ? artifacts.papers ?? [] : state.dimension === "cvss" ? artifacts.score_assessment ?? null
      : artifacts.score_assessment ? { epss_score: artifacts.score_assessment.epss_score ?? null, epss_percentile: artifacts.score_assessment.epss_percentile ?? null } : null;
    return sha256Json(artifact) === state.result_hash;
  };
  const pending_dimensions = new Map<string, EnrichmentDimension[]>();
  const scoped = (dimension: EnrichmentDimension) => options.dimensions === undefined || options.dimensions.includes(dimension);
  for (const item of accepted) {
    const hash = enrichmentInputHash(item);
    pending_dimensions.set(item.intel_id, (["paper", "cvss", "epss"] as const).filter(scoped).filter(dimension => {
      const state = stateMap.get(item.intel_id + ":" + dimension);
      const currentIntel = options.currentIntelEventIds?.get(item.intel_id);
      const latestReceipt = published.get(item.intel_id);
      // Missing/mismatched success receipts need repair, but failed/empty/degraded
      // attempts may intentionally have no receipt and must retain their source backoff.
      const receiptRepair = Boolean(state && ((state.status === "live" && (!state.enrich_event_id
        || (options.publishedEnrichments !== undefined && (!latestReceipt || latestReceipt.event_id !== state.enrich_event_id))))
        || (currentIntel && state.intel_event_id !== currentIntel)));
      const dependency = dimension === "cvss" ? options.cvssDependencyHashes?.get(item.intel_id) : undefined;
      return receiptRepair || Boolean(dependency && state?.dependency_hash !== dependency) || enrichmentRetryDue(state, hash, options.now);
    }));
  }
  return {
    latestDQ,
    latestEnriched,
    pending_dimensions,
    real_live_dimensions: (options.states ?? []).filter(isPublishedCurrent).length,
    live_marked_but_unverified_dimensions: (options.states ?? []).filter(state => state.status === "live" && !isPublishedCurrent(state)).length,
    unique_intel_ids: latestIntel.size,
    accepted_ids: accepted.length,
    accepted_items: accepted,
    already_enriched: accepted.filter(item => latestEnriched.has(item.intel_id)).length,
    recorded_with_failed_dimensions: accepted.filter(item => (latestEnriched.get(item.intel_id)?.dimensions_failed.length ?? 0) > 0).length,
    // New facts and new source event bindings outrank routine historical retries.
    pending: accepted.filter(item => pending_dimensions.get(item.intel_id)!.length > 0).sort((a, b) => {
      const priority = (item: IntelItem) => {
        const hash = enrichmentInputHash(item), event = options.currentIntelEventIds?.get(item.intel_id);
        return (["paper", "cvss", "epss"] as const).filter(scoped).some(d => {
          const state = stateMap.get(item.intel_id + ":" + d);
          const dependency = d === "cvss" ? options.cvssDependencyHashes?.get(item.intel_id) : undefined;
          return !state || state.input_hash !== hash || Boolean(event && state.intel_event_id !== event) || Boolean(dependency && state.dependency_hash !== dependency);
        }) ? 1 : 0;
      };
      return priority(b) - priority(a);
    }),
  };
}
