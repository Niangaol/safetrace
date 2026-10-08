import {screenPromptInjection} from "@safetrace/shared";
import type {RetrievalResponse} from "@safetrace/shared";
export type UiKind="evidence"|"comparison"|"checklist";
export interface UiPlan {version:1;blocks:Array<{type:UiKind;evidence_ids:string[]}>}
export interface UiItem {id:string;doc_type:string;text:string;url:string;cve_id:string|null}
export interface UiDocument {version:1;source:"model"|"rules";blocks:Array<{id:string;type:UiKind;items:UiItem[]}>}
export interface UiStatus {status:"accepted"|"fallback"|"skipped";reason:string}
function object(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==="object"&&!Array.isArray(v);}
function keys(v:Record<string,unknown>,allowed:string[]){return Object.keys(v).every(k=>allowed.includes(k));}
/** The model chooses references and component kinds, never facts, markup, styles or executable actions. */
export function validateUiPlan(raw:unknown,allowedIds:readonly string[]):UiPlan|null {
 if(!object(raw)||!keys(raw,["version","blocks"])||raw.version!==1||!Array.isArray(raw.blocks)||raw.blocks.length>4)return null;
 const blocks:UiPlan["blocks"]=[],seen=new Set<string>();
 for(const row of raw.blocks){
  if(!object(row)||!keys(row,["type","evidence_ids"])||!(["evidence","comparison","checklist"] as unknown[]).includes(row.type)||!Array.isArray(row.evidence_ids)||row.evidence_ids.length<1||row.evidence_ids.length>5)return null;
  if(seen.has(String(row.type)))return null;seen.add(String(row.type));
  const ids=row.evidence_ids;
  if(ids.some(id=>typeof id!=="string"||!allowedIds.includes(id))||new Set(ids).size!==ids.length)return null;
  blocks.push({type:row.type as UiKind,evidence_ids:ids as string[]});
 }
 return {version:1,blocks};
}
/** Primary identity comes only from the leading structured CVE, not sibling mentions in prose. */
export function primaryCve(text:string):string|null{return /^(CVE-\d{4}-\d{4,})(?=\s|$)/i.exec(text.trim())?.[1]?.toUpperCase()??null;}
export function compileUi(plan:UiPlan,evidence:RetrievalResponse,source:UiDocument["source"]):UiDocument|null {
 const validated=validateUiPlan(plan,evidence.chunks.slice(0,5).map(c=>c.chunk_id));if(!validated)return null;
 const blocks:UiDocument["blocks"]=[];
 for(const [index,block] of validated.blocks.entries()){
  const items:UiItem[]=[];
  for(const id of block.evidence_ids){
   const chunk=evidence.chunks.slice(0,5).find(c=>c.chunk_id===id);if(!chunk)return null;
   let url:URL;try{url=new URL(chunk.provenance.url);}catch{return null;}
   if(!["http:","https:"].includes(url.protocol)||url.username||url.password)return null;
   if(screenPromptInjection([chunk.text]).flags.length)return null;
   items.push({id:chunk.chunk_id,doc_type:chunk.doc_type,text:chunk.text.slice(0,1200),url:url.href,cve_id:primaryCve(chunk.text)});
  }
  // Comparison means grouped source material, not inferred severity or an unsupported winner.
  if(block.type==="comparison"&&new Set(items.map(i=>i.cve_id).filter(Boolean)).size<2)return null;
  blocks.push({id:"ui_"+index,type:block.type,items});
 }
 return {version:1,source,blocks};
}
export function ruleUiPlan(question:string,evidence:RetrievalResponse):UiPlan {
 const rows=evidence.chunks.slice(0,5),ids=rows.map(c=>c.chunk_id);
 if(!ids.length||(!/CVE-\d{4}-\d{4,}/i.test(question)&&/是什么|定义|含义|what is/i.test(question)))return {version:1,blocks:[]};
 const compare=/比较|对比|区别|compare/i.test(question)&&new Set(rows.map(c=>primaryCve(c.text)).filter(Boolean)).size>=2;
 const checklist=/修复|升级|缓解|remediat|patch/i.test(question);
 return {version:1,blocks:[{type:compare?"comparison":checklist?"checklist":"evidence",evidence_ids:ids}]};
}
