/**
 * 资产相关 triage：只汇总已收据的证据（资产影响 + 修复指导 + PoC 候选），
 * 按证据确定性排序。纪律：
 *   - 不新增扫描、不抓取 PoC 链接、不调用模型；
 *   - 不猜严重度/优先级分数；没有证据的维度不参与排序；
 *   - unknown 不等于安全，absent 也不等于安全；
 *   - 输出是"下一步人工复核顺序建议"，不是结论。
 */
import type { DatabaseSync } from "node:sqlite";
import { sha256Json } from "@safetrace/shared";
import { SqliteExtensionReceiptStore, type AssetReceipt, type PocReceipt, type RemediationReceipt } from "./extension-receipts.js";

export type TriageTier = "review_first" | "review_next" | "informational";
export interface TriageEntry {
  intel_id:string;tier:TriageTier;rationale:string;
  asset:{status:"verified"|"absent"|"stale"|"revoked"|"invalid";potentially_affected:number;unknown:number;groups:string[]};
  remediation:{status:"verified"|"absent"|"stale"|"revoked"|"invalid";vendor_statements:number;agency_guidance:number};
  poc:{status:"verified"|"absent"|"stale"|"revoked"|"invalid";candidates:number;advisory_supported:number};
}
export interface TriageReport {generated_at:string;entries:TriageEntry[];truncated:boolean;
  note:string;business_writes:number;network_calls:number;model_calls:number}

const TIER_ORDER:Record<TriageTier,number>={"review_first":0,"review_next":1,"informational":2};

/** 纯排序：先看资产是否可能受影响，再看是否有修复指导，最后看 PoC 候选。 */
export function rankTriage(rows:Omit<TriageEntry,"tier"|"rationale">[]):TriageEntry[]{
  return rows.map(row=>{
    const affected=row.asset.status==="verified"?row.asset.potentially_affected:0;
    const unknown=row.asset.status==="verified"?row.asset.unknown:0;
    const fixes=row.remediation.status==="verified"?row.remediation.vendor_statements+row.remediation.agency_guidance:0;
    const pocs=row.poc.status==="verified"?row.poc.candidates:0;
    if(affected>0&&fixes>0)return {...row,tier:"review_first" as const,rationale:"资产可能受影响且已有来源明确的修复指导；先人工核对适用版本"};
    if(affected>0)return {...row,tier:"review_first" as const,rationale:"资产可能受影响但暂无合格修复指导；需要人工确认缓解措施"};
    if(unknown>0)return {...row,tier:"review_next" as const,rationale:"资产版本/身份无法排除受影响（unknown 不是安全）；需要补充版本或人工核验"};
    if(pocs>0)return {...row,tier:"review_next" as const,rationale:"存在 PoC 候选引用但资产未命中；确认资产范围后再评估"};
    return {...row,tier:"informational" as const,rationale:"当前资产快照未命中；仅为情报留存，不表示无风险"};
  }).sort((a,b)=>TIER_ORDER[a.tier]-TIER_ORDER[b.tier]||a.intel_id.localeCompare(b.intel_id));
}

/** 从已收据汇总；缺表/缺收据都是 absent，不产假成功。 */
export function buildTriageReport(sqlitePath:string,options:{now?:Date;limit?:number}={}):TriageReport{
  const limit=Math.min(Math.max(options.limit??50,1),200);
  const store=new SqliteExtensionReceiptStore(sqlitePath,{readOnly:true});
  const rows:Omit<TriageEntry,"tier"|"rationale">[]=[];let truncated=false;
  try{
    const ids=[...new Set([...storeIds(store,"asset"),...storeIds(store,"remediation"),...storeIds(store,"poc")])].sort();
    for(const id of ids){
      if(rows.length>=limit){truncated=true;break;}
      const asset=safe(()=>store.get(id,"asset")) as AssetReceipt|undefined;
      const rem=safe(()=>store.get(id,"remediation")) as RemediationReceipt|undefined;
      const poc=safe(()=>store.get(id,"poc")) as PocReceipt|undefined;
      rows.push({intel_id:id,
        asset:{status:asset?"verified":"absent",potentially_affected:asset?asset.artifacts.filter(a=>a.status==="potentially_affected").length:0,unknown:asset?asset.artifacts.filter(a=>a.status==="unknown").length:0,groups:asset?[...new Set(asset.asset_scope.groups.map(g=>g.group_id))].sort():[]},
        remediation:{status:rem?"verified":"absent",vendor_statements:rem?rem.artifacts.filter(a=>a.validation_level==="vendor_statement").length:0,agency_guidance:rem?rem.artifacts.filter(a=>a.validation_level==="agency_guidance").length:0},
        poc:{status:poc?"verified":"absent",candidates:poc?poc.artifacts.length:0,advisory_supported:poc?poc.advisories.filter(a=>a.choice==="related"&&a.p_related>=0.9).length:0}});
    }
  }finally{store.close();}
  return {generated_at:(options.now??new Date()).toISOString(),entries:rankTriage(rows),truncated,
    note:"Review-order suggestion from stored receipts only; not a severity score and not a safety conclusion",business_writes:0,network_calls:0,model_calls:0};
}

function storeIds(store:SqliteExtensionReceiptStore,dimension:"asset"|"remediation"|"poc"):string[]{
  try{return (store as unknown as {db:DatabaseSync}).db
    .prepare("SELECT intel_id FROM enrichment_extension_receipts WHERE dimension=?").all(dimension)
    .map((r:unknown)=>String((r as {intel_id:string}).intel_id));}catch{return []}
}
function safe<T>(fn:()=>T):T|undefined{try{return fn();}catch{return undefined;}}
export function triageDigest(report:TriageReport):string{return sha256Json({entries:report.entries,truncated:report.truncated});}