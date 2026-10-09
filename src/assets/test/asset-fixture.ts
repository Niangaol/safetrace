import type { ScanRun } from "../src/types.js";
import type { IntelItem, QualityVerdict } from "@safetrace/shared";
export function assetIntel(id='intel_vue',versionRange=['<3.5.0']):IntelItem {
  return {intel_id:id,cve_ids:['CVE-2026-1001'],source_ids:['nvd_cve'],title:'Vue vulnerability',published_at:'2026-10-01T00:00:00Z',first_seen_at:'2026-10-01T00:00:00Z',source_reliability:0.95,raw_refs:[],entities:{product:'vue',vendor:null,version_range:versionRange,cwe:[],cpes:[]},schema_version:'1.0'};
}
export function assetDq(id='intel_vue',verdict:QualityVerdict['verdict']='pass'):QualityVerdict {
  return {item_id:id,item_kind:'intel',verdict,quality_score:0.9,dimension_scores:{structure:1,completeness:1,consistency:1,timeliness:1,sourcing:1},flags:[],gate_version:'dq1.v1'};
}
export function assetRun(root:string,runId='scan_1',version='3.4.0',floor=false):ScanRun {
  return {run_id:runId,group_id:'g1',group_name:'Fixture group',roots:[root],started_at:'2026-10-01T01:00:00Z',finished_at:runId==='scan_1'?'2026-10-01T01:00:01Z':'2026-10-02T01:00:01Z',status:'ok',degraded_to:null,note:'Synthetic asset snapshot for isolated regression tests',repo_count:1,component_count:1,skipped:[],repos:[{repo_id:'repo_1',path:root,remote_url:null,branch:null,head_commit:null,head_commit_at:null,is_git:false,git_note:null,languages:[],frameworks:[],manifests:['package.json'],components:[{ecosystem:'npm',name:'vue',version,constraint_raw:floor?'^'+version:version,version_is_range_floor:floor,source_file:'package.json'}]}]};
}
