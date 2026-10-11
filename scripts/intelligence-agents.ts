/** 内部情报协作入口：缺省只在.tmp离线运行；--live --apply须同库已验证备份与单写lease。 */
import { resolve, dirname, relative, isAbsolute } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { mkdir, appendFile } from "node:fs/promises";
import { EventBus, SqliteEventStore, SqliteEnrichmentStateStore } from "@safetrace/shared";
import { runEnrichment, scoreSourceDependencyHash } from "@safetrace/enrich";
import { runIngestScheduler } from "../src/ingest/src/scheduler.js";
import { SqliteSourceScheduleStore } from "../src/ingest/src/schedule-state.js";
import { readAgentUpdateSnapshot } from "../src/qa/src/orchestrator/update-snapshot.js";
import { IntelligenceUpdateAgents, updateTimeliness } from "../src/qa/src/orchestrator/intel-update-agents.js";
import { SQLiteUpdateQueue } from "../src/qa/src/orchestrator/update-queue.js";
import { readKnowledgeProjection } from "../src/qa/src/knowledge-reader.js";
import { MemoryIndex } from "../src/qa/src/q2-retrieval.js";
import { requireVerifiedBackup } from "./verified-backup-gate.js";
import { acquireIntelIndexLease } from "./intel-index-lock.js";
import { canonicalWritePath, rejectHardLinkedFile } from "./agent-path-safety.js";
const root=fileURLToPath(new URL("../",import.meta.url));
export interface IntelligenceAgentArgs {sqlitePath:string;statePath:string;offline:boolean;apply:boolean;cycles:number;sourceIds:string[];workers:number;runLogPath:string;monitorLogPath?:string;pollProfile:"timely"|"registry"}
export function parseIntelligenceAgentArgs(args:readonly string[],env:Record<string,string|undefined>=process.env):IntelligenceAgentArgs {
  const value=(flag:string,fallback:string)=>{const i=args.indexOf(flag);if(i===-1)return fallback;const v=args[i+1];if(!v||v.startsWith("--"))throw new Error(flag+" needs value");return v;};
  const positive=(text:string,name:string,allowZero=false)=>{const n=Number(text);if(!Number.isSafeInteger(n)||n<(allowZero?0:1))throw new Error(name+" invalid");return n;};
  if(args.includes("--live")&&args.includes("--offline"))throw new Error("--live and --offline conflict");
  const pollProfile=value("--poll-profile","timely");if(!["timely","registry"].includes(pollProfile))throw new Error("poll-profile must be timely or registry");
  const sqlitePath=resolve(value("--sqlite",env.SQLITE_PATH??resolve(root,".tmp/agent-updates/events.sqlite")));
  return {pollProfile:pollProfile as "timely"|"registry",sqlitePath,statePath:resolve(value("--state",resolve(dirname(sqlitePath),"collaboration.sqlite"))),offline:!args.includes("--live"),apply:args.includes("--apply"),
    cycles:positive(value("--cycles","1"),"cycles",true),sourceIds:value("--sources","nvd_cve").split(",").filter(Boolean),workers:positive(value("--workers","2"),"workers"),runLogPath:resolve(value("--log",resolve(dirname(sqlitePath),"agent-updates.jsonl")))};
}
export async function requireAgentWriteGate(opts:IntelligenceAgentArgs,verify:(path:string)=>Promise<void>=requireVerifiedBackup):Promise<void> {
  const demoRoot=resolve(await canonicalWritePath(root),".tmp");
  const db=await canonicalWritePath(opts.sqlitePath),state=await canonicalWritePath(opts.statePath);
  const log=await canonicalWritePath(opts.runLogPath),monitor=await canonicalWritePath(opts.monitorLogPath??opts.runLogPath+".monitor");
  const cache=await canonicalWritePath(resolve(dirname(db),"payloads"));
  const companionInputs=[db,state].flatMap(base=>[base+"-wal",base+"-shm",base+"-journal"]);
  const companions=await Promise.all(companionInputs.map(canonicalWritePath));
  const identity=(path:string)=>process.platform==="win32"?path.toLowerCase():path;
  for(let i=0;i<companions.length;i++)if(identity(companions[i]!)!==identity(companionInputs[i]!))throw new Error("database journal alias is not an authorized write target");
  const paths=[db,state,log,monitor,cache,...companions];
  for(const path of paths)await rejectHardLinkedFile(path);
  const protectedDbPaths=new Set([db,state,...companions].map(identity));
  if(protectedDbPaths.has(identity(log))||protectedDbPaths.has(identity(monitor)))throw new Error("log path must not alias a database or journal");
  if(![log,monitor].every(path=>/[.](jsonl|log|monitor)$/i.test(path)))throw new Error("agent logs must have a log/jsonl/monitor extension");
  const localPaths=paths.every(path=>{const rel=relative(demoRoot,path);return rel!==""&&!isAbsolute(rel)&&!rel.startsWith("..");});
  const localDemo=opts.offline&&localPaths;
  if(!localDemo){if(!opts.apply)throw new Error("non-demo or live business writes require --apply and verified backup");await verify(db);}
}

export async function runIntelligenceAgents(opts:IntelligenceAgentArgs) {
  await requireAgentWriteGate(opts);
  opts={...opts,sqlitePath:await canonicalWritePath(opts.sqlitePath),statePath:await canonicalWritePath(opts.statePath),runLogPath:await canonicalWritePath(opts.runLogPath),monitorLogPath:await canonicalWritePath(opts.monitorLogPath??opts.runLogPath+".monitor")};
  // Startup guard, not protection against an operator changing junctions while the service runs.
  await mkdir(dirname(opts.sqlitePath),{recursive:true});await mkdir(dirname(opts.statePath),{recursive:true});await mkdir(dirname(opts.runLogPath),{recursive:true});
  const release=acquireIntelIndexLease("http://127.0.0.1","enrichment-db:"+opts.sqlitePath,resolve(root,".tmp/data-maintenance-locks"));
  let store:SqliteEventStore|undefined,states:SqliteEnrichmentStateStore|undefined,schedules:SqliteSourceScheduleStore|undefined,queue:SQLiteUpdateQueue|undefined,agents:IntelligenceUpdateAgents|undefined;
  const prior={offline:process.env.OFFLINE_FIXTURES,cache:process.env.SAFETRACE_CACHE_DIR};
  const events:unknown[]=[];let eventTotal=0;let stop=false;const onStop=()=>{stop=true;};
  let failed=false;
  try {
    store=new SqliteEventStore(opts.sqlitePath);states=new SqliteEnrichmentStateStore(opts.sqlitePath);schedules=new SqliteSourceScheduleStore(opts.statePath);queue=new SQLiteUpdateQueue(opts.statePath);
    const stateStore=states,eventStore=store,updateQueue=queue,bus=new EventBus({store});
    const cacheDir=resolve(dirname(opts.sqlitePath),"payloads");await mkdir(cacheDir,{recursive:true});
    process.env.OFFLINE_FIXTURES=opts.offline?"true":"false";process.env.SAFETRACE_CACHE_DIR=cacheDir;
    const projectionOptions={sqlitePath:opts.sqlitePath,payloadRoots:[cacheDir,resolve(root,"fixtures")]};
    process.on("SIGINT",onStop);process.on("SIGTERM",onStop);
    const readSnapshot=()=>readAgentUpdateSnapshot(opts.sqlitePath);
    agents=new IntelligenceUpdateAgents({queue:updateQueue,readSnapshot,workerConcurrency:opts.workers,
      refreshSources:async()=>{const p=await readKnowledgeProjection(projectionOptions);return {source_chunks:p.evidence.filter(e=>e.kind==="source").length,mode:opts.offline?"test":"bm25-live-projection"};},
      enrich:async(entry,dimensions,guard)=>{
        const atStart=await readSnapshot(),kev=atStart.kevCveIds??new Set<string>();
        const dependency=await scoreSourceDependencyHash(entry.item,{kevSet:kev});
        await runEnrichment([entry.item],{bus,stateStore,offline:opts.offline,dimensions:[...dimensions],kevSet:kev,
          causation_by_intel_id:{[entry.item.intel_id]:entry.intel_event.event_id},
          beforeCommit:async()=>{
            if(!await guard())return false;
            const latest=await readSnapshot();
            return await scoreSourceDependencyHash(entry.item,{kevSet:latest.kevCveIds??new Set<string>()})===dependency&&await guard();
          }});
      },
      index:async(entry,guard)=>{
        if(!await guard())throw new Error("index input is stale before preparation");
        const projection=await readKnowledgeProjection(projectionOptions);
        const proofs=projection.evidence.filter(p=>p.intel_id===entry.item.intel_id&&p.intel_event_id===entry.intel_event.event_id),source=proofs.filter(p=>p.kind==="source");
        const index=new MemoryIndex();await index.upsert(proofs.map(p=>p.chunk));
        return {visible:await guard()&&source.length>0,source_chunks:source.length,artifact_chunks:proofs.length-source.length,mode:opts.offline?"test":"bm25-live-projection"};
      },
      onEvent:async event=>{eventTotal++;events.push(event);if(events.length>2000)events.shift();await appendFile(opts.runLogPath,JSON.stringify({data_mode:opts.offline?"fixture":"live",...event})+"\n");},
    });
    const runtime=agents;
    await runtime.observe();runtime.wake();runtime.start(5000);
    const monitor=await runIngestScheduler({...(opts.pollProfile==="timely"?{pollIntervalOverridesS:{nvd_cve:1800,cisa_kev:900}}:{}),store:eventStore,scheduleState:schedules,sourceIds:opts.sourceIds,offline:opts.offline,maxCycles:opts.cycles,shouldStop:()=>stop,runLogPath:opts.monitorLogPath!,maxConcurrency:opts.workers,
      onIngestResult:async()=>{await runtime.observe();runtime.wake();}});
    await runtime.whenIdle();
    const tasks=updateQueue.list();
    return {data_mode:opts.offline?"fixture":"live",update_status:tasks.length===0?"empty":tasks.every(t=>t.status==="done")?"ready":"partial",source_cycles:monitor.cycles,source_records:monitor.records,source_records_total:monitor.records_total,source_records_dropped_from_memory:monitor.records_dropped_from_memory,
      timeliness:updateTimeliness(tasks,Date.now()),tasks,events,event_total:eventTotal,events_dropped_from_memory:eventTotal-events.length,worker_errors:runtime.errors,
      index_mode:"verified BM25 projection readiness; no Qdrant writes or browser receipt",model_calls:0,source_network_enabled:!opts.offline,automatic_llm_enabled:false,poll_profile:opts.pollProfile};
  } catch(error) {failed=true;throw error;}
  finally {
    let cleanupError:unknown;
    for(const cleanup of [()=>agents?.stop(),()=>queue?.close(),()=>schedules?.close(),()=>states?.close(),()=>store?.close(),release]) {
      try {await cleanup();}catch(error){cleanupError??=error;}
    }
    process.off("SIGINT",onStop);process.off("SIGTERM",onStop);
    if(prior.offline===undefined)delete process.env.OFFLINE_FIXTURES;else process.env.OFFLINE_FIXTURES=prior.offline;
    if(prior.cache===undefined)delete process.env.SAFETRACE_CACHE_DIR;else process.env.SAFETRACE_CACHE_DIR=prior.cache;
    if(cleanupError&&!failed)throw cleanupError;
  }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){runIntelligenceAgents(parseIntelligenceAgentArgs(process.argv.slice(2))).then(report=>console.log(JSON.stringify(report,null,2))).catch(e=>{console.error(e);process.exitCode=1;});}
