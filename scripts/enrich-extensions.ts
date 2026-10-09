/** Explicit maintenance extension entrypoint; default preview, no network/model/scan/execution. */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { EventBus, SqliteEventStore, nextId } from "@safetrace/shared";
import { runEnrichment } from "@safetrace/enrich";
import { SqliteExtensionReceiptStore } from "../src/enrich/src/extension-receipts.js";
import { prepareRemediationReceipt, commitRemediationReceipt } from "../src/enrich/src/remediation-extension.js";
import { prepareAssetReceipt, commitAssetReceipt, captureAssetSnapshot } from "../src/enrich/src/asset-extension.js";
import { preparePocReceipt, commitPocReceipt } from "../src/enrich/src/poc-extension.js";
import type { PocAdvisory } from "../src/enrich/src/extension-receipts.js";
import { readFileSync } from "node:fs";
import { defaultAssetsDbPath } from "../src/assets/src/config.js";
import { nameVariants } from "../src/assets/src/matcher.js";
import { normalizeName } from "../src/enrich/src/f2-assets.js";
import { readIntelIndexSnapshot } from "./intel-index-data.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { acquireIntelIndexLease } from "./intel-index-lock.js";

async function main() {
  const db = resolve(process.env.SQLITE_PATH ?? './var/safetrace.sqlite');
  const apply = process.argv.includes('--apply');
  if(apply && process.argv.includes('--dry-run'))throw new Error('--apply and --dry-run are mutually exclusive');
  const dimension = process.argv.find(a=>a.startsWith('--dimension='))?.slice('--dimension='.length) ?? 'remediation';
  if(dimension !== 'remediation' && dimension !== 'asset' && dimension !== 'poc')throw new Error('Only implemented remediation/asset/poc extensions are accepted');
  const jevModelId=dimension==='poc'?(process.argv.find(a=>a.startsWith('--jev-model-id='))?.slice('--jev-model-id='.length)??'Open-Jev-2B@0c7aa49'):'';
  const jevBaseUrl=process.env.JEV_BASE_URL??'http://127.0.0.1:8791';
  const jevProvenance=(()=>{const p=process.argv.find(a=>a.startsWith('--jev-provenance='))?.slice('--jev-provenance='.length);if(!p)return undefined;const m=JSON.parse(readFileSync(resolve(p),'utf8'));for(const k of ['model','checkpoint_sha256','base_revision','code_commit'])if(typeof m[k]!=='string'||!m[k])throw new Error('Jev provenance requires model/checkpoint_sha256/base_revision/code_commit');return m;})();
  const assetsPath=resolve(process.argv.find(a=>a.startsWith('--assets-db='))?.slice('--assets-db='.length)??defaultAssetsDbPath());
  const assetNames=dimension==='asset'?new Set(captureAssetSnapshot(assetsPath).components.flatMap(c=>nameVariants(c.name))):undefined;
  const limit = Number(process.argv.find(a=>a.startsWith('--limit='))?.slice('--limit='.length) ?? 20);
  if(!Number.isSafeInteger(limit)||limit<1||limit>50)throw new Error('Extension limit must be 1–50');
  const requested = process.argv.find(a=>a.startsWith('--ids='))?.slice('--ids='.length);
  const ids = requested === undefined ? undefined : new Set(requested.split(',').filter(Boolean));
  const snapshot = readIntelIndexSnapshot(db);
  if(ids && (!ids.size || [...ids].some(id=>!snapshot.accepted.has(id))))throw new Error('Requested Intel is absent or latest DQ not released');
  const selected = [...snapshot.accepted.values()].filter(e=>ids?ids.has(e.item.intel_id):dimension==='asset'?assetNames!.has(normalizeName(e.item.entities.product)):dimension==='poc'?['nvd_cve','cve_org'].includes(e.item.source_ids[0]??''):e.item.source_ids.some(s=>['cisa_kev','ubuntu_usn'].includes(s))).slice(0,limit);
  if(!apply) {
    const preview=[];
    for(const entry of selected) {
      const receipt=dimension==="asset"?await prepareAssetReceipt({sqlitePath:db,assetsPath,item:entry.item}):dimension==="poc"?await preparePocReceipt({sqlitePath:db,item:entry.item,jevModelId,jevBaseUrl,...(jevProvenance?{jevProvenance}:{})}):await prepareRemediationReceipt({sqlitePath:db,item:entry.item});
      preview.push({intel_id:receipt.intel_id,dimension:receipt.dimension,status:receipt.status,artifacts:receipt.artifacts.length,dependency_sha256:receipt.dependency_sha256,...(dimension==="poc"&&receipt.dimension==="poc"?{advisories:receipt.advisories.map((a:PocAdvisory)=>({candidate_id:a.candidate_id,choice:a.choice,p_related:a.p_related}))}:{})});
    }
    console.log(JSON.stringify({mode:'extension-preview',business_writes:0,network_calls:0,model_calls:0,selected:preview},null,2));return;
  }
  const backup = process.argv.find(a=>a.startsWith("--backup="))?.slice("--backup=".length);
  await requireVerifiedBackup(db,backup);
  const release=acquireIntelIndexLease('http://127.0.0.1','enrichment-db:'+db,fileURLToPath(new URL('../.tmp/data-maintenance-locks/',import.meta.url)));
  let receipts:SqliteExtensionReceiptStore|undefined,events:SqliteEventStore|undefined;
  try {
    receipts=new SqliteExtensionReceiptStore(db);events=new SqliteEventStore(db);
    const bus=new EventBus({store:events}),traceId=nextId('tr_extensions');
    await runEnrichment(selected.map(e=>e.item),{dimensions:[],extensionDimensions:[dimension],bus,traceId,
      causation_by_intel_id:Object.fromEntries(selected.map(e=>[e.item.intel_id,e.intel_event.event_id])),
      extensionRunner:async(item)=>{
        if(dimension==="asset")return commitAssetReceipt({sqlitePath:db,assetsPath,receipt:await prepareAssetReceipt({sqlitePath:db,assetsPath,item}),store:receipts!});
        if(dimension==="poc")return commitPocReceipt({sqlitePath:db,receipt:await preparePocReceipt({sqlitePath:db,item,jevModelId,jevBaseUrl,...(jevProvenance?{jevProvenance}:{})}),store:receipts!});
        return commitRemediationReceipt({sqlitePath:db,receipt:await prepareRemediationReceipt({sqlitePath:db,item}),store:receipts!});
      },onExtension:(intelId,summary)=>{console.log(JSON.stringify({type:'extension_receipt',intel_id:intelId,...summary}));}});
    console.log(JSON.stringify({mode:'extension-apply',trace_id:traceId,processed:selected.length,network_calls:0,model_calls:0,frozen_result_writes:0}));
  } finally {receipts?.close();events?.close();release();}
}
void main().catch(error=>{console.error(error);process.exitCode=1});
