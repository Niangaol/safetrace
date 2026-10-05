import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createVerifiedBackup, verifyBackup, verifyVectorRestore, databaseBackupStats } from "../src/backup.js";
import type { BackupOptions } from "../src/backup.js";

async function setup() {
  const root=await mkdtemp(join(tmpdir(),"safetrace-backup-")),path=join(root,"source.sqlite");
  const db=new DatabaseSync(path);db.exec("PRAGMA journal_mode=WAL; CREATE TABLE events(seq INTEGER,topic TEXT,payload TEXT); CREATE TABLE extra(id INTEGER,body TEXT)");
  db.prepare("INSERT INTO events VALUES(?,?,?)").run(1,"intel.items",JSON.stringify({intel_id:"intel_a",raw_refs:[]}));db.prepare("INSERT INTO extra VALUES(?,?)").run(1,"must survive backup");
  const points=[{id:1,payload:{chunk_id:"intel_a",text:"original"},vector:{dense:[0.2,0.8]}}];
  let scans=0,reads=0;
  const opts:BackupOptions={sqlitePath:path,outputRoot:join(root,"backups"),qdrantUrl:"http://127.0.0.1:1",collection:"test",batchSize:1,fetchImpl:(async (input,init)=>{
    reads++; if(String(input).endsWith("/points/scroll")){scans++;assert.equal(JSON.parse(String(init?.body)).with_vector,true);return Response.json({result:{points,next_page_offset:null}});}
    return Response.json({result:{points_count:points.length,config:{params:{vectors:{dense:{size:2,distance:"Cosine"}}}}}});
  }) as typeof fetch};
  return {root,path,db,points,opts,counts:()=>({scans,reads})};
}
test("online SQLite backup includes WAL and independent clone plus full vectors verifies without production mutation",async()=>{
  const s=await setup();try{
    const before=databaseBackupStats(s.path);const {directory,manifest}=await createVerifiedBackup(s.opts);
    assert.deepEqual(databaseBackupStats(s.path),before);assert.deepEqual(manifest.sqlite.tables,before);
    assert.equal(manifest.qdrant.points,1);assert.equal(manifest.qdrant.dimension,2);assert.equal(s.counts().scans,2);
    assert.deepEqual(await verifyBackup(directory),{sqlite_tables:2,points:1,raw_files:0});
    const restored=new DatabaseSync(join(directory,"safetrace.sqlite"),{readOnly:true});try{assert.equal(restored.prepare("SELECT body FROM extra").get()!.body,"must survive backup");}finally{restored.close();}
    const line=JSON.parse((await readFile(join(directory,"qdrant-points.jsonl"),"utf8")).trim());assert.deepEqual(line.vector.dense,[0.2,0.8]);
  }finally{s.db.close();await rm(s.root,{recursive:true,force:true});}
});
test("same-count vector updates and SQLite changes during export refuse a verified manifest",async()=>{
  for(const change of ["vector","sqlite"]){const s=await setup();try{
    const transport=s.opts.fetchImpl!;let scan=0;s.opts.fetchImpl=(async (input,init)=>{
      if(String(input).endsWith("/points/scroll") && ++scan===2){if(change==="vector")s.points[0]!.vector.dense=[0.9,0.1];else s.db.prepare("INSERT INTO extra VALUES(?,?)").run(2,"concurrent write");}
      return transport(input,init);
    }) as typeof fetch;
    await assert.rejects(createVerifiedBackup(s.opts),/changed during/);
  }finally{s.db.close();await rm(s.root,{recursive:true,force:true});}}
});
test("backup failure/invalid vectors and tampered exports cannot masquerade as restorable",async()=>{
  const s=await setup();try{
    await assert.rejects(createVerifiedBackup({...s.opts,fetchImpl:(async()=>new Response("denied",{status:401})) as typeof fetch}),/HTTP 401/);
    const saved=s.points[0]!.vector.dense;s.points[0]!.vector.dense=[];await assert.rejects(createVerifiedBackup(s.opts),/invalid dense/);s.points[0]!.vector.dense=saved;
    const {directory}=await createVerifiedBackup(s.opts);
    await writeFile(join(directory,"qdrant-points.jsonl"),"{}\n");await assert.rejects(verifyBackup(directory),/checksum mismatch/);
  }finally{s.db.close();await rm(s.root,{recursive:true,force:true});}
});
test("manifest paths cannot escape backup root",async()=>{
  const s=await setup();try{const {directory,manifest}=await createVerifiedBackup(s.opts);manifest.sqlite.path="../source.sqlite";await assert.rejects(verifyBackup(directory,manifest),/escapes/);
  }finally{s.db.close();await rm(s.root,{recursive:true,force:true});}
});

test("scratch restore verifies actual PUT/readback and deletes only its generated collection",async()=>{
  for(const tamper of [false,true]){const s=await setup();try{
    const {directory}=await createVerifiedBackup(s.opts);const requests:Array<{url:string;method:string}>=[];let restored:unknown[]=[];
    const transport={qdrantUrl:"http://127.0.0.1:1",fetchImpl:(async(input,init)=>{
      const url=String(input),method=init?.method??"GET";requests.push({url,method});
      assert.match(url,/collections\/safetrace_restore_verify_[a-f0-9]{32}/);assert.ok(!url.includes("/collections/test"));
      if(method==="DELETE")return Response.json({result:true});
      if(url.endsWith("/points/scroll"))return Response.json({result:{points:restored,next_page_offset:null}});
      if(url.includes("/points?")){restored=JSON.parse(String(init?.body)).points;if(tamper)(restored[0] as {payload:{text:string}}).payload.text="corrupted";return Response.json({result:{status:"completed"}});}
      return Response.json({result:true});
    }) as typeof fetch};
    if(tamper)await assert.rejects(verifyVectorRestore(directory,transport),/differs/);
    else assert.deepEqual(Object.values(await verifyVectorRestore(directory,transport)).slice(1),[1,true]);
    assert.equal(requests.at(-1)!.method,"DELETE");
  }finally{s.db.close();await rm(s.root,{recursive:true,force:true});}}
});

test("raw payload backup copies captured files, never treats references as permission to read secrets",async()=>{
  const s=await setup();try{
    const raw=join(s.root,"captured.json");await writeFile(raw,'{"captured":true}');
    s.db.prepare("INSERT INTO events VALUES(?,?,?)").run(2,"raw.docs",JSON.stringify({payload_ref:raw}));
    const opts={...s.opts,rawPayloadRoots:[s.root]};const {directory,manifest}=await createVerifiedBackup(opts);
    assert.equal(manifest.raw_files.length,1);assert.equal((await verifyBackup(directory)).raw_files,1);
    s.db.prepare("INSERT INTO events VALUES(?,?,?)").run(3,"raw.docs",JSON.stringify({payload_ref:join(s.root,".env.local")}));
    await assert.rejects(createVerifiedBackup(opts),/private file type/);
  }finally{s.db.close();await rm(s.root,{recursive:true,force:true});}
});
