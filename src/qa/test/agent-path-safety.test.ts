import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, link, writeFile, readFile, rm } from "node:fs/promises";
import { sha256Json } from "@safetrace/shared";
import { join, resolve } from "node:path";
import { parseIntelligenceAgentArgs,requireAgentWriteGate } from "../../../scripts/intelligence-agents.js";
import { canonicalWritePath } from "../../../scripts/agent-path-safety.js";
import { acquireIntelIndexLease } from "../../../scripts/intel-index-lock.js";
async function setup(){await mkdir(resolve(".tmp"),{recursive:true});await mkdir(resolve("tmp"),{recursive:true});const local=await mkdtemp(join(resolve(".tmp"),"agent-path-")),outside=await mkdtemp(join(resolve("tmp"),"safetrace-fake-official-"));const opts=parseIntelligenceAgentArgs(["--sqlite",join(local,"events.sqlite"),"--state",join(local,"q.sqlite"),"--log",join(local,"updates.jsonl")],{});return {local,outside,opts};}
async function dispose(s:{local:string;outside:string}){await rm(s.local,{recursive:true,force:true});await rm(s.outside,{recursive:true,force:true});}
test("离线门禁：现存目录junction/symlink不能把正式模拟目录伪装成.tmp",async()=>{
  const s=await setup();try {const alias=join(s.local,"alias");await symlink(s.outside,alias,process.platform==="win32"?"junction":"dir");
    await assert.rejects(requireAgentWriteGate({...s.opts,sqlitePath:join(alias,"events.sqlite")}),/--apply/);
  }finally{await dispose(s);}
});
test("离线门禁：派生monitor硬链接不能追加到数据库；正式模拟文件字节不变",async()=>{
  const s=await setup();try {const target=join(s.outside,"official.sqlite");await writeFile(target,"DO_NOT_TOUCH");await link(target,s.opts.runLogPath+".monitor");
    await assert.rejects(requireAgentWriteGate(s.opts),/hard-linked/);assert.equal(await readFile(target,"utf8"),"DO_NOT_TOUCH");
  }finally{await dispose(s);}
});
test("离线门禁：悬空目录链接不能当不存在的安全叶路径",async()=>{
  const s=await setup();try {const alias=join(s.local,"dangling");await symlink(join(s.outside,"missing-dir"),alias,process.platform==="win32"?"junction":"dir");
    await assert.rejects(canonicalWritePath(join(alias,"new.jsonl")),/dangling|unresolved/);
    await assert.rejects(requireAgentWriteGate({...s.opts,runLogPath:join(alias,"new.jsonl")}),/dangling|unresolved/);
  }finally{await dispose(s);}
});
test("日志不能指向主数据库或WAL/SHM/journal（即使伴随文件尚不存在）",async()=>{
  const s=await setup();try {for(const path of [s.opts.sqlitePath,s.opts.statePath+"-wal",s.opts.sqlitePath+"-shm",s.opts.statePath+"-journal"]){
    await assert.rejects(requireAgentWriteGate({...s.opts,monitorLogPath:path}),/alias|journal/);
  }}finally{await dispose(s);}
});
test("已有旧版词法锁不能被规范路径升级绕过",async()=>{
  const s=await setup();try {const db=join(s.outside,"events.sqlite"),locks=join(s.local,"locks");await writeFile(db,"test-only");await mkdir(locks);
    const collection="enrichment-db:"+db;const key=sha256Json({url:new URL("http://127.0.0.1").href,collection});
    await writeFile(join(locks,key+".lock"),JSON.stringify({token:"existing-legacy-writer",pid:process.pid,created_at:new Date().toISOString()}));
    assert.throws(()=>acquireIntelIndexLease("http://127.0.0.1",collection,locks),/already leased/);
  }finally{await dispose(s);}
});

test("同一个实际数据库目录别名仍是同monitor leader锁",async()=>{
  const s=await setup();let release:(()=>void)|undefined;try {const db=join(s.outside,"events.sqlite"),alias=join(s.local,"alias");await writeFile(db,"test-only-placeholder");await symlink(s.outside,alias,process.platform==="win32"?"junction":"dir");
    const locks=join(s.local,"locks");release=acquireIntelIndexLease("http://127.0.0.1","enrichment-db:"+db,locks);
    assert.throws(()=>acquireIntelIndexLease("http://127.0.0.1","enrichment-db:"+join(alias,"events.sqlite"),locks),/already leased/);
  }finally{release?.();await dispose(s);}
});
