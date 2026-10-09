import {DatabaseSync} from "node:sqlite";
import type {IncomingMessage,ServerResponse} from "node:http";
import type {LineageRecord} from "@safetrace/shared";
export type ActivityStage="collect"|"normalize"|"dedupe"|"quality"|"paper"|"score"|"knowledge"|"answer"|"review"|"fallback"|"assets";
export interface ActivityItem{event:"activity";id:string;sequence:number;trace_id:string;intel_id:string|null;stage:ActivityStage;status:string;at:string;label:string;origin:"live"|"recorded";details:{source_id?:string;source_type?:string;elapsed_ms?:number;artifact_count?:number;reason?:string}}
function stage(name:string):ActivityStage {if(/fallback/.test(name))return"fallback";if(/review/.test(name))return"review";if(/dq1|quality/.test(name))return"quality";if(/dedupe/.test(name))return"dedupe";if(/parse|construct|normalize/.test(name))return"normalize";if(/fetch|snapshot|raw_publish|publish_raw/.test(name))return"collect";if(/f1/.test(name))return"paper";if(/f4|cvss|remediation/.test(name))return"score";if(/f6|index/.test(name))return"knowledge";if(/assets/.test(name))return"assets";return"answer";}
function safeId(value:unknown):string|undefined {return typeof value==="string"&&/^[A-Za-z0-9_.:/-]{1,200}$/.test(value)?value:undefined;}
export class ActivityStream {
 private seq=0;private journal:ActivityItem[]=[];private clients=new Set<ServerResponse>();private timer:ReturnType<typeof setInterval>|undefined;private lastDb=0;private initialized=false;private dbStatus="unknown";private tickCount=0;
 constructor(private sqlitePath:string){}
 private send(res:ServerResponse,value:unknown){if(res.destroyed)return;if(res.writableLength>128*1024){res.destroy();return;}res.write("data: "+JSON.stringify(value)+"\n\n");}
 publish(item:Omit<ActivityItem,"event"|"sequence"|"id"|"origin">&{id?:string;origin?:"live"|"recorded"}){const value:ActivityItem={...item,id:item.id??"activity_"+(this.seq+1),event:"activity",sequence:++this.seq,origin:item.origin??"live"};this.journal.push(value);if(this.journal.length>2000)this.journal.shift();for(const res of this.clients)this.send(res,value);return value;}
 private map(record:LineageRecord,origin:"live"|"recorded"){const start=Date.parse(record.started_at),end=Date.parse(record.completed_at),elapsed=Number.isFinite(start)&&Number.isFinite(end)&&end>=start?end-start:undefined;
  const intel=record.input_refs.concat(record.output_refs).map(r=>r.id).find(id=>/^intel_[A-Za-z0-9_-]+$/.test(id));
  const s=stage(record.stage);return this.publish({id:record.lineage_id,trace_id:safeId(record.trace_id)??"trace_unknown",intel_id:safeId(intel)??null,stage:s,status:["success","degraded","failed","review","rejected","running"].includes(record.status)?record.status:"running",at:record.completed_at??record.recorded_at,label:record.stage.slice(0,100),origin,
    details:{...(safeId(record.source?.source_id)?{source_id:record.source!.source_id}:{}),...(safeId(record.source?.source_type)?{source_type:record.source!.source_type}:{}),...(elapsed!==undefined?{elapsed_ms:elapsed}:{}),artifact_count:record.output_refs.length,...(record.status==="degraded"?{reason:"本阶段显式降级，不能视为全链成功"}:record.status==="review"?{reason:"等待复核"}:record.status==="rejected"?{reason:"本阶段拒绝/隔离"}:{})}});
 }
 private read(initial=false){initial=initial||this.dbStatus!=="available";let db:DatabaseSync|undefined;try{db=new DatabaseSync(this.sqlitePath,{readOnly:true});const max=Number(db.prepare("SELECT COALESCE(MAX(seq),0) AS n FROM lineage_records").get()!.n);
    if(!initial&&max<this.lastDb){this.lastDb=0;this.journal=[];for(const res of this.clients)this.send(res,{event:"reset",reason:"持久处理记录发生代际变化；旧游标已重置",cursor:this.seq});}
    const rows=initial?db.prepare("SELECT seq,payload FROM lineage_records ORDER BY seq DESC LIMIT 20").all().reverse():db.prepare("SELECT seq,payload FROM lineage_records WHERE seq>? ORDER BY seq LIMIT 500").all(this.lastDb);
    for(const row of rows){this.lastDb=Number(row.seq);try{const record=JSON.parse(String(row.payload)) as LineageRecord;if(!record||!Array.isArray(record.input_refs)||!Array.isArray(record.output_refs))throw new Error();this.map(record,initial?"recorded":"live");}catch{for(const client of this.clients)this.send(client,{event:"error",message:"处理记录格式不合法，已跳过该序号并继续；请复核持久日志"});}}
    if(initial)this.lastDb=max;this.dbStatus="available";
   }catch{this.dbStatus="unavailable";if(!initial)for(const res of this.clients)this.send(res,{event:"error",message:"持久处理记录暂不可读；不会模拟新的处理事件"});}finally{db?.close();}}
 attach(req:IncomingMessage,res:ServerResponse,url:URL){const after=url.searchParams.get("after");if(after!==null&&(!/^[0-9]+$/.test(after)||!Number.isSafeInteger(Number(after)))){res.writeHead(400);res.end("invalid activity cursor");return;}
  if(!this.initialized){this.initialized=true;this.read(true);}
  res.writeHead(200,{"content-type":"text/event-stream; charset=utf-8","cache-control":"no-cache, no-transform","x-accel-buffering":"no"});this.send(res,{event:"hello",live:true,cursor:this.seq,db_status:this.dbStatus});
  const cursor=after===null?null:Number(after),first=this.journal[0]?.sequence??this.seq;
  if(cursor!==null&&(cursor>this.seq||cursor<first-1))this.send(res,{event:"reset",reason:"活动历史游标已过期或服务已重启；下方为已保留记录，不是假新数据",cursor:this.seq});
  const backlog=this.journal.filter(r=>cursor===null||r.sequence>cursor);
  if(backlog.length>500)this.send(res,{event:"reset",reason:"重连积压超过500条；较早 "+(backlog.length-500)+" 条未在本次回放展示，请按Trace检查持久记录",cursor:this.seq});
  for(const row of backlog.slice(-500))this.send(res,{...row,origin:"recorded"});
  this.clients.add(res);res.on("close",()=>{this.clients.delete(res);if(!this.clients.size&&this.timer){clearInterval(this.timer);this.timer=undefined;}});
  if(!this.timer)this.timer=setInterval(()=>{this.read();if(++this.tickCount%15===0)for(const client of this.clients)this.send(client,{event:"heartbeat",at:new Date().toISOString(),cursor:this.seq});},1000);
 }
 dispose(){if(this.timer)clearInterval(this.timer);this.timer=undefined;for(const res of this.clients)res.end();this.clients.clear();}
}
