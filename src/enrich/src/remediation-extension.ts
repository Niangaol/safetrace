import { readFileSync } from "node:fs";
import { nextId, sha256, sha256Json } from "@safetrace/shared";
import type { IntelItem } from "@safetrace/shared";
import { readIntelIndexSnapshot } from "../../../scripts/intel-index-data.js";
import { readRemediationEvidence } from "../../qa/src/remediation-reader.js";
import { extensionDependency, type RemediationReceipt, type ExtensionRunSummary, SqliteExtensionReceiptStore } from "./extension-receipts.js";

/** Source/DQ gates are reused from the established QA reader; no transport or model inference. */
export async function prepareRemediationReceipt(options: {sqlitePath:string;payloadRoots?:readonly string[];item:IntelItem;now?:Date}): Promise<RemediationReceipt> {
  const snapshot = readIntelIndexSnapshot(options.sqlitePath);
  const entry = snapshot.accepted.get(options.item.intel_id);
  if (!entry || sha256Json(entry.item) !== sha256Json(options.item)) throw new Error('Intel absent, changed or latest DQ not released');
  const derived = await readRemediationEvidence({...options,intelIds:[options.item.intel_id],limit:1,receiptMode:'derive'});
  if (derived.rejected.length) throw new Error('Remediation source validation rejected; refusing empty-success replacement');
  const artifacts = derived.evidence.map(e => e.artifact).sort((a,b)=>sha256Json(a).localeCompare(sha256Json(b)));
  const proofs = derived.evidence.map(e => ({raw_ref:e.artifact.raw_ref,source_id:e.artifact.source_id,source_url:e.artifact.source_url,source_sha256:e.artifact.source_sha256,parent_lineage_ids:[...e.parent_lineage_ids].sort()}));
  const sources = [...new Map(proofs.map(p=>[sha256Json(p),p])).values()].sort((a,b)=>sha256Json(a).localeCompare(sha256Json(b)));
  if (readIntelIndexSnapshot(options.sqlitePath).fingerprint !== snapshot.fingerprint) throw new Error('Intel/DQ changed while preparing extension');
  const receipt = {receipt_id:nextId('rx'),dimension:'remediation',operation_version:'f5-remediation.v1',intel_id:entry.item.intel_id,
    intel_event_id:entry.intel_event.event_id,intel_sha256:sha256Json(entry.item),dq_event_id:entry.verdict_event.event_id,dq_sha256:sha256Json(entry.verdict),
    status:artifacts.length?'live':'empty',created_at:(options.now??new Date()).toISOString(),sources,artifacts,artifact_sha256:sha256Json(artifacts)} as Omit<RemediationReceipt,'dependency_sha256'>;
  return {...receipt,dependency_sha256:extensionDependency(receipt)};
}
export function commitRemediationReceipt(options: {sqlitePath:string;receipt:RemediationReceipt;store:SqliteExtensionReceiptStore}): ExtensionRunSummary {
  const {receipt,newly_recorded} = options.store.put(options.receipt,()=>{
    const entry = readIntelIndexSnapshot(options.sqlitePath).accepted.get(options.receipt.intel_id);
    if (!entry || entry.intel_event.event_id !== options.receipt.intel_event_id || entry.verdict_event.event_id !== options.receipt.dq_event_id
      || sha256Json(entry.item) !== options.receipt.intel_sha256 || sha256Json(entry.verdict) !== options.receipt.dq_sha256) throw new Error('Intel/DQ changed before extension commit');
    for (const source of options.receipt.sources) if(sha256(readFileSync(source.raw_ref)) !== source.source_sha256) throw new Error('Remediation source changed before commit');
  });
  return {dimension:'remediation',status:receipt.status,receipt_id:receipt.receipt_id,artifacts:receipt.artifacts.length,newly_recorded};
}
