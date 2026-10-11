/** 内部监测→富化→索引协作运行时。事件持久化交接，不依赖跨进程内存subscribe。 */
import { enrichmentInputHash, sha256Json } from "@safetrace/shared";
import type { EnrichmentDimension, EnrichmentDimensionState, EnrichmentResult } from "@safetrace/shared";
import { planPendingEnrichment } from "../../../enrich/src/pending.js";
import type { AcceptedIntel, IntelSnapshot } from "../intel-index-plan.js";

import type { UpdateDraft, UpdateClaim, UpdateTask, UpdateQueue } from "./update-queue.js";
export type UpdateStage = "enrich" | "index";
export type AgentUpdateDraft = UpdateDraft;
export type AgentUpdateClaim = UpdateClaim;
export type AgentQueueRow = UpdateTask;
export type UpdateQueuePort = Pick<UpdateQueue, "enqueue" | "claim" | "complete" | "fail" | "isCurrent" | "revoke" | "list">;
export interface AgentUpdateSnapshot {snapshot:IntelSnapshot;states:readonly EnrichmentDimensionState[];
  receipts:readonly {event_id:string;payload:EnrichmentResult}[];cvssDependencyHashes?:ReadonlyMap<string,string>;kevCveIds?:ReadonlySet<string>}
export interface IndexReadiness {visible:boolean;source_chunks:number;artifact_chunks:number;mode:"bm25-live-projection"|"test"}
export interface AgentUpdateEvent {at:string;stage:"handoff"|"source_ready"|"enrich"|"index"|"stale"|"failed";
  intel_id?:string;intel_event_seq?:number;detail:string;elapsed_ms?:number;source_chunks?:number;artifact_chunks?:number}
export interface UpdateAgentOptions {
  queue:UpdateQueuePort;readSnapshot:()=>Promise<AgentUpdateSnapshot>;now?:()=>number;
  owner?:string;leaseMs?:number;workerConcurrency?:number;maxJobsPerWake?:number;
  dimensions?:readonly EnrichmentDimension[];
  /** Source proof release must not wait for paper/EPSS/model completion. */
  refreshSources?:(snapshot:AgentUpdateSnapshot)=>Promise<{source_chunks:number;mode:"bm25-live-projection"|"test"}>;
  enrich:(entry:AcceptedIntel,dimensions:readonly EnrichmentDimension[],guard:()=>Promise<boolean>)=>Promise<void>;
  index:(entry:AcceptedIntel,guard:()=>Promise<boolean>)=>Promise<IndexReadiness>;
  onEvent?:(event:AgentUpdateEvent)=>void|Promise<void>;
}
export class IntelligenceUpdateAgents {
  private readonly now:()=>number;private readonly owner:string;private readonly leaseMs:number;
  private readonly concurrency:number;private readonly maxJobs:number;
  private work:Promise<void>|null=null;private requested=false;private sourceFingerprint:string|undefined;
  private timer:ReturnType<typeof setInterval>|null=null;private stopping=false;
  private observing:Promise<number>|null=null;private observeRequested=false;
  private draining:Promise<void>|null=null;
  readonly errors: string[]=[];
  constructor(private readonly opts:UpdateAgentOptions) {
    this.now=opts.now??Date.now;this.owner=opts.owner??"intel-update-agent";this.leaseMs=opts.leaseMs??120_000;
    this.concurrency=opts.workerConcurrency??2;this.maxJobs=opts.maxJobsPerWake??50;
    for(const [name,value] of [["leaseMs",this.leaseMs],["workerConcurrency",this.concurrency],["maxJobsPerWake",this.maxJobs]] as const) {
      if(!Number.isSafeInteger(value)||value<=0)throw new Error(name+" must be positive integer");
    }
  }
  private recordError(error:unknown):void {
    this.errors.push(error instanceof Error?error.message:String(error));
    if(this.errors.length>100)this.errors.splice(0,this.errors.length-100);
  }
  private async emit(event:Omit<AgentUpdateEvent,"at">) {
    await this.opts.onEvent?.({at:new Date(this.now()).toISOString(),...event});
  }
  private plan(view:AgentUpdateSnapshot) {
    const entries=[...view.snapshot.accepted.values()];
    return planPendingEnrichment(entries.map(e=>e.item),entries.map(e=>e.verdict),view.receipts.map(r=>r.payload),{
      now:new Date(this.now()),states:view.states,publishedEnrichments:view.receipts,
      currentIntelEventIds:new Map(entries.map(e=>[e.item.intel_id,e.intel_event.event_id])),
      dimensions:this.opts.dimensions??["cvss","epss"],
      ...(view.cvssDependencyHashes?{cvssDependencyHashes:view.cvssDependencyHashes}:{}),
    });
  }
  /** 每源落库后立即调用；拒绝/隔离先撤销，再交接最新版本。 */
  observe():Promise<number> {
    if(this.stopping)return Promise.resolve(0);
    this.observeRequested=true;if(this.observing)return this.observing;
    const active=(async()=>{let enqueued=0;while(this.observeRequested&&!this.stopping){this.observeRequested=false;enqueued+=await this.observeOnce();}return enqueued;})();
    this.observing=active;
    void active.finally(()=>{if(this.observing===active)this.observing=null;}).catch(()=>{});
    return active;
  }
  private async observeOnce():Promise<number> {
    const view=await this.opts.readSnapshot(),at=this.now(),plan=this.plan(view);let accepted=0;
    const existingRows=new Map(this.opts.queue.list().map(row=>[row.intel_id,row]));
    for(const row of existingRows.values()) {
      if(!view.snapshot.accepted.has(row.intel_id))this.opts.queue.revoke(row.intel_id,view.snapshot.watermark,at);
    }
    for(const entry of view.snapshot.accepted.values()) {
      const item=entry.item,hash=enrichmentInputHash(item),due=plan.pending_dimensions.get(item.intel_id)??[];
      const current=existingRows.get(item.intel_id);
      // No due work and already-known source generation: do not manufacture repeated refresh jobs.
      if(current && current.intel_event_seq===entry.intel_event.seq && due.length===0)continue;
      const stateVersion=view.states.filter(s=>s.intel_id===item.intel_id).map(s=>({dimension:s.dimension,input_hash:s.input_hash,result_hash:s.result_hash,updated_at:s.updated_at,retry_after:s.retry_after,dependency_hash:s.dependency_hash,enrich_event_id:s.enrich_event_id}));
      const refresh_key=sha256Json({due,stateVersion,source_dependency:view.cvssDependencyHashes?.get(item.intel_id)??null});
      const priority=item.source_ids.includes("cisa_kev")?200:Date.parse(item.first_seen_at)>=at-3600_000?100:10;
      const result=this.opts.queue.enqueue({intel_id:item.intel_id,refs:[entry.intel_event.event_id,...item.raw_refs],input_hash:hash,intel_event_seq:entry.intel_event.seq,detected_at:at,priority,refresh_key});
      if(result.accepted){accepted++;await this.emit({stage:"handoff",intel_id:item.intel_id,intel_event_seq:entry.intel_event.seq,detail:"durable latest-version handoff"});}
    }
    if(this.opts.refreshSources && this.sourceFingerprint!==view.snapshot.fingerprint) {
      const started=this.now();const readiness=await this.opts.refreshSources(view);
      // Never mark a changed generation ready using an earlier asynchronous source projection.
      const latest=await this.opts.readSnapshot();
      if(latest.snapshot.fingerprint!==view.snapshot.fingerprint)throw new Error("source snapshot changed during readiness preparation");
      if(view.snapshot.accepted.size===0){this.sourceFingerprint=view.snapshot.fingerprint;return accepted;}
      if(readiness.source_chunks<1){await this.emit({stage:"failed",detail:"source projection has no original proofs; not ready",elapsed_ms:this.now()-started});return accepted;}
      this.sourceFingerprint=view.snapshot.fingerprint;
      await this.emit({stage:"source_ready",detail:readiness.mode+" source evidence readiness (not every item or final enriched answer)",source_chunks:readiness.source_chunks,elapsed_ms:this.now()-started});
    }
    return accepted;
  }
  /** 一次有界唤醒。onIngestResult不要await此work，以免慢富化占住监测slot。 */
  wake():void {
    if(this.stopping)return;this.requested=true;if(this.work)return;
    const work=(async()=>{while(this.requested&&!this.stopping){this.requested=false;await this.drain();}})();
    this.work=work;
    void work.catch(e=>{this.recordError(e);}).finally(()=>{if(this.work===work)this.work=null;});
  }
  private async process(claim:AgentUpdateClaim):Promise<void> {
    const started=this.now();
    const guard=async()=>{
      if(!this.opts.queue.isCurrent(claim,this.now()))return false;
      const view=await this.opts.readSnapshot(),entry=view.snapshot.accepted.get(claim.intel_id);
      return !!entry&&entry.intel_event.seq===claim.intel_event_seq&&entry.intel_event.event_id===claim.refs[0]
        &&enrichmentInputHash(entry.item)===claim.input_hash&&this.opts.queue.isCurrent(claim,this.now());
    };
    try {
      if(!await guard()){await this.emit({stage:"stale",intel_id:claim.intel_id,intel_event_seq:claim.intel_event_seq,detail:"current source/DQ/lease differs; no business commit"});return;}
      const view=await this.opts.readSnapshot(),entry=view.snapshot.accepted.get(claim.intel_id)!;
      if(claim.stage==="enrich") {
        const dimensions=this.plan(view).pending_dimensions.get(claim.intel_id)??[];
        if(dimensions.length)await this.opts.enrich(entry,dimensions,guard);
        if(!await guard()||!this.opts.queue.complete(claim,this.now()))throw new Error("enrichment handoff fenced by newer version/lease");
        await this.emit({stage:"enrich",intel_id:claim.intel_id,intel_event_seq:claim.intel_event_seq,detail:dimensions.length?"requested dimensions processed; live proof is checked at index":"no due dimension; proceed to source index",elapsed_ms:this.now()-started});
      } else {
        const readiness=await this.opts.index(entry,guard);
        if(!readiness.visible||readiness.source_chunks<1)throw new Error("no verified source projection ready; do not mark indexed");
        if(!await guard()||!this.opts.queue.complete(claim,this.now()))throw new Error("index completion fenced by newer version/lease");
        await this.emit({stage:"index",intel_id:claim.intel_id,intel_event_seq:claim.intel_event_seq,detail:readiness.mode+" readiness; not Qdrant or browser receipt",source_chunks:readiness.source_chunks,artifact_chunks:readiness.artifact_chunks,elapsed_ms:this.now()-started});
      }
    } catch(e) {
      const stillCurrent=this.opts.queue.isCurrent(claim,this.now());
      if(stillCurrent)this.opts.queue.fail(claim,this.now());
      await this.emit({stage:stillCurrent?"failed":"stale",intel_id:claim.intel_id,intel_event_seq:claim.intel_event_seq,detail:e instanceof Error?e.message:String(e),elapsed_ms:this.now()-started});
    }
  }
  drain():Promise<void> {
    if(this.draining)return this.draining;
    const active=this.drainOnce();this.draining=active;
    void active.finally(()=>{if(this.draining===active)this.draining=null;}).catch(()=>{});
    return active;
  }
  private async drainOnce():Promise<void> {
    let claimed=0;
    const workers=Array.from({length:this.concurrency},(_,worker)=>(async()=>{
      while(claimed<this.maxJobs&&!this.stopping){
        const claim=this.opts.queue.claim("index",this.owner+":"+worker,this.now(),this.leaseMs)
          ??this.opts.queue.claim("enrich",this.owner+":"+worker,this.now(),this.leaseMs);
        if(!claim)return;claimed++;await this.process(claim);
      }
    })());
    await Promise.all(workers);
  }
  /** 独立短周期只检查durable due任务，不改变外部源poll频率/限流。 */
  start(intervalMs=5000):void {
    if(!Number.isSafeInteger(intervalMs)||intervalMs<=0||intervalMs>2_147_483_647)throw new Error("intervalMs must be a positive 32-bit timer interval");
    if(this.timer)return;this.stopping=false;
    this.timer=setInterval(()=>{void this.observe().then(()=>this.wake()).catch(e=>{this.recordError(e);});},intervalMs);
  }
  async whenIdle():Promise<void> {while(this.work){const active=this.work;await active.catch(()=>{});if(this.work===active)await Promise.resolve();}}
  async stop():Promise<void> {this.stopping=true;if(this.timer){clearInterval(this.timer);this.timer=null;}await this.observing?.catch(()=>{});await this.whenIdle();await this.draining?.catch(()=>{});}
}

export function updateTimeliness(rows:readonly AgentQueueRow[],now:number) {
  const completed=rows.filter(r=>r.indexed_at!==null),known=completed.filter(r=>r.indexed_at!>=r.detected_at);
  const values=known.map(r=>r.indexed_at!-r.detected_at).sort((a,b)=>a-b);
  const percentile=(p:number)=>values.length?values[Math.ceil(values.length*p)-1]!:null;
  return {detected_to_index_ready_ms:{samples:values.length,p50:percentile(.5),p95:percentile(.95)},
    pending:rows.filter(r=>["pending","running","retry"].includes(r.status)).length,
    oldest_pending_ms:Math.max(0,...rows.filter(r=>["pending","running","retry"].includes(r.status)).map(r=>now-r.enqueued_at)),
    rejected_negative_timestamps:completed.length-known.length,
    label:"internal detected→verified projection readiness; not source publication delay or real network SLA"};
}
