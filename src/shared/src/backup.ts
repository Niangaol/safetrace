import { DatabaseSync, backup } from "node:sqlite";
import { constants, createReadStream, createWriteStream } from "node:fs";
import { mkdir, mkdtemp, copyFile, readFile, writeFile, stat, realpath } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { resolve, join, relative, isAbsolute } from "node:path";
import { sha256Json } from "./lineage.js";

export interface TableBackupStat { name: string; rows: number; sha256: string }
export interface BackupManifest {
  version: 1; created_at: string; status: "verified"; source_sqlite: string;
  sqlite: { path: string; sha256: string; tables: TableBackupStat[] };
  qdrant: { collection: string; config: unknown; path: string; sha256: string; points: number; content_sha256: string; dimension: number };
  raw_files: Array<{ source: string; path: string; sha256: string }>;
  missing_raw_refs: string[];
  note: string;
}
export interface BackupOptions {
  sqlitePath: string; outputRoot: string; qdrantUrl: string; collection: string;
  apiKey?: string; fetchImpl?: typeof fetch; now?: () => Date; batchSize?: number;
  /** Explicit roots for local captured payloads; references can never authorize arbitrary secret reads. */
  rawPayloadRoots?: readonly string[];
}
export async function fileSha256(path: string): Promise<string> {
  const hash = createHash("sha256"); for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}
function jsonValue(value: unknown): unknown {
  if (typeof value === "bigint") return { bigint: value.toString() };
  if (value instanceof Uint8Array) return { bytes: Buffer.from(value).toString("hex") };
  return value;
}
export function databaseBackupStats(path: string): TableBackupStat[] {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const integrity = db.prepare("PRAGMA integrity_check").all();
    if (integrity.length !== 1 || Object.values(integrity[0]!)[0] !== "ok") throw new Error("SQLite integrity_check failed");
    const names = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all();
    return names.map(row => {
      const name = String(row.name), hashes: string[] = [];
      const identifier = '"' + name.replaceAll('"','""') + '"';
      for (const record of db.prepare("SELECT * FROM " + identifier).iterate()) {
        hashes.push(sha256Json(Object.fromEntries(Object.entries(record).map(([key,value]) => [key,jsonValue(value)]))));
      }
      hashes.sort(); return { name, rows: hashes.length, sha256: sha256Json(hashes) };
    });
  } finally { db.close(); }
}
function localEndpoint(raw: string, collection: string): string {
  const url = new URL(raw);
  if (!["127.0.0.1","[::1]","::1"].includes(url.hostname) || !["http:","https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash || !collection.trim()) throw new Error("backup only permits explicit loopback Qdrant endpoint/collection");
  return raw.replace(/\/+$/,"") + "/collections/" + encodeURIComponent(collection);
}
function headers(apiKey?: string) { return { "content-type":"application/json", ...(apiKey ? { "api-key":apiKey } : {}) }; }
async function collectionInfo(opts: BackupOptions): Promise<{ config: unknown; count: number; dimension: number }> {
  const res = await (opts.fetchImpl ?? fetch)(localEndpoint(opts.qdrantUrl,opts.collection), { method:"GET",headers:headers(opts.apiKey),redirect:"error",signal:AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error("backup collection info HTTP " + res.status);
  const data = await res.json() as { result?: { points_count?: number; config?: { params?: { vectors?: { dense?: { size?: number } } } } } };
  const dimension = data.result?.config?.params?.vectors?.dense?.size;
  if (!Number.isSafeInteger(dimension) || (dimension ?? 0) <= 0 || !Number.isSafeInteger(data.result?.points_count)) throw new Error("backup requires named dense vector metadata and exact points_count");
  return { config:data.result!.config!,count:data.result!.points_count!,dimension:dimension! };
}
function validatePoint(value: unknown, dimension: number): { id: number | string; payload: Record<string, unknown>; vector: unknown } {
  const point = value as { id?: unknown; payload?: unknown; vector?: { dense?: unknown } };
  if (!point || (typeof point.id !== "string" && !Number.isSafeInteger(point.id)) || !point.payload || typeof point.payload !== "object" || Array.isArray(point.payload)) throw new Error("backup point identity/payload missing");
  const vector = point.vector?.dense;
  if (!Array.isArray(vector) || vector.length !== dimension || vector.some(v => typeof v !== "number" || !Number.isFinite(v))) throw new Error("backup missing or invalid dense vector");
  return point as { id: number | string; payload: Record<string, unknown>; vector: unknown };
}
async function scanPoints(opts: BackupOptions, dimension: number, output?: string): Promise<{ count:number; hash:string }> {
  const count = opts.batchSize ?? 250;
  if (!Number.isSafeInteger(count) || count < 1 || count > 1000) throw new Error("backup batchSize must be 1–1000");
  const writer = output ? createWriteStream(output,{flags:"wx",mode:0o600}) : undefined;
  let writerError: Error | undefined; writer?.on("error",error => { writerError = error; });
  const digests = new Map<string,string>(); const cursors = new Set<string>(); let offset: unknown;
  try {
    for(let page=0;page<10000;page++) {
      const res = await (opts.fetchImpl ?? fetch)(localEndpoint(opts.qdrantUrl,opts.collection)+"/points/scroll",{method:"POST",headers:headers(opts.apiKey),redirect:"error",signal:AbortSignal.timeout(30000),body:JSON.stringify({limit:count,with_vector:true,with_payload:true,...(offset!==undefined?{offset}:{})})});
      if(!res.ok) throw new Error("backup scroll HTTP "+res.status);
      const data = await res.json() as {result?:{points?:unknown;next_page_offset?:unknown}};
      if(!Array.isArray(data.result?.points)) throw new Error("backup scroll malformed");
      for(const candidate of data.result.points) {
        const point=validatePoint(candidate,dimension), key=JSON.stringify(point.id);
        if(digests.has(key)) throw new Error("backup duplicate point ID/unstable scroll");
        digests.set(key,sha256Json(point));
        if(writerError) throw writerError;
        if(writer && !writer.write(JSON.stringify(point)+"\n")) await once(writer,"drain");
      }
      offset=data.result.next_page_offset;
      if(offset===null || offset===undefined) break;
      const cursor=JSON.stringify(offset); if(cursors.has(cursor)) throw new Error("backup cursor loop"); cursors.add(cursor);
      if(page===9999) throw new Error("backup scan incomplete");
    }
    if(writer) { writer.end(); await once(writer,"finish"); if(writerError) throw writerError; }
    return {count:digests.size,hash:sha256Json([...digests].sort(([a],[b])=>a.localeCompare(b)))};
  } finally { writer?.destroy(); }
}
function safeFile(root:string,path:string):string {
  if(isAbsolute(path)) throw new Error("backup manifest paths must be relative");
  const full=resolve(root,path),rel=relative(resolve(root),full);
  if(rel==="" || rel.startsWith("..") || isAbsolute(rel)) throw new Error("backup path escapes manifest root");
  return full;
}
/** Reopen an independent SQLite copy and reparse every vector; no restore ever targets production. */
export async function verifyBackup(root:string, manifest?:BackupManifest):Promise<{sqlite_tables:number;points:number;raw_files:number}> {
  const m=manifest ?? JSON.parse(await readFile(join(root,"manifest.json"),"utf8")) as BackupManifest;
  if(m.version!==1 || m.status!=="verified") throw new Error("backup manifest is not verified version 1");
  const sql=safeFile(root,m.sqlite.path);
  if(await fileSha256(sql)!==m.sqlite.sha256) throw new Error("backup SQLite checksum mismatch");
  const restoreRoot=await mkdtemp(join(root,"verify-restore-")); const restored=join(restoreRoot,"safetrace.sqlite");
  await copyFile(sql,restored,constants.COPYFILE_EXCL);
  if(sha256Json(databaseBackupStats(restored))!==sha256Json(m.sqlite.tables)) throw new Error("independent SQLite restore logical mismatch");
  const exportPath=safeFile(root,m.qdrant.path);
  if(await fileSha256(exportPath)!==m.qdrant.sha256) throw new Error("backup vector export checksum mismatch");
  const digests=new Map<string,string>();
  const reader=createInterface({input:createReadStream(exportPath),crlfDelay:Infinity});
  for await (const line of reader) {
    if(!line) throw new Error("backup vector export contains empty record");
    const p=validatePoint(JSON.parse(line),m.qdrant.dimension),key=JSON.stringify(p.id);
    if(digests.has(key)) throw new Error("backup duplicate exported ID");digests.set(key,sha256Json(p));
  }
  if(digests.size!==m.qdrant.points || sha256Json([...digests].sort(([a],[b])=>a.localeCompare(b)))!==m.qdrant.content_sha256) throw new Error("backup vector restore content mismatch");
  for(const raw of m.raw_files) if(await fileSha256(safeFile(root,raw.path))!==raw.sha256) throw new Error("backup raw payload checksum mismatch");
  return {sqlite_tables:m.sqlite.tables.length,points:digests.size,raw_files:m.raw_files.length};
}
export async function createVerifiedBackup(opts:BackupOptions):Promise<{directory:string;manifest:BackupManifest}> {
  localEndpoint(opts.qdrantUrl,opts.collection); // validate before opening output files or network
  await mkdir(opts.outputRoot,{recursive:true});
  const directory=await mkdtemp(join(resolve(opts.outputRoot),"safetrace-"));
  const sqlPath=join(directory,"safetrace.sqlite"); const source= new DatabaseSync(opts.sqlitePath,{readOnly:true});
  try { await backup(source,sqlPath); } finally {source.close();}
  const tables=databaseBackupStats(sqlPath); const info=await collectionInfo(opts);
  const vectors=join(directory,"qdrant-points.jsonl"); const first=await scanPoints(opts,info.dimension,vectors);
  if(first.count!==info.count) throw new Error("backup point count differs from collection metadata");
  const raw_files:BackupManifest["raw_files"]=[]; const missing_raw_refs:string[]=[];
  const db=new DatabaseSync(sqlPath,{readOnly:true}); const refs=new Set<string>();
  try {
    for(const row of db.prepare("SELECT topic,payload FROM events WHERE topic IN ('raw.docs','intel.items') ORDER BY seq").iterate()) {
      const p=JSON.parse(String(row.payload)) as {payload_ref?:unknown;raw_refs?:unknown};
      if(typeof p.payload_ref==="string") refs.add(p.payload_ref);
      if(Array.isArray(p.raw_refs)) for(const r of p.raw_refs) if(typeof r==="string") refs.add(r);
    }
  } finally {db.close();}
  await mkdir(join(directory,"raw"));
  for(const ref of [...refs].sort()) {
    if(ref.startsWith("sqlite-page:")) continue; // immutable page snapshots are inside SQLite
    const path=resolve(ref);
    if (!/[.](json|xml|html?|txt|md|pdf|payload)$/i.test(path)) throw new Error("raw reference has unsupported/private file type");
    let actual: string;
    try { actual = await realpath(path); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") { missing_raw_refs.push(ref); continue; } throw error; }
    const allowedRoots = await Promise.all((opts.rawPayloadRoots ?? [resolve(".")]).map(root => realpath(resolve(root))));
    if (!allowedRoots.some(root => { const rel=relative(root,actual);return rel!=="" && !rel.startsWith("..") && !isAbsolute(rel); })) throw new Error("raw reference escapes explicit payload roots");
    try { if(!(await stat(path)).isFile()) {missing_raw_refs.push(ref);continue;} }
    catch(error) {if((error as NodeJS.ErrnoException).code!=="ENOENT") throw error;missing_raw_refs.push(ref);continue;}
    const target="raw/"+sha256Json({path})+".payload";
    await copyFile(path,safeFile(directory,target),constants.COPYFILE_EXCL);
    raw_files.push({source:path,path:target,sha256:await fileSha256(safeFile(directory,target))});
  }
  // A second full vector scan detects in-place changes, not just equal point counts.
  const second=await scanPoints(opts,info.dimension); const after=await collectionInfo(opts);
  if(first.hash!==second.hash || first.count!==second.count || sha256Json(info.config)!==sha256Json(after.config) || first.count!==after.count) throw new Error("Qdrant changed during backup; no verified manifest published");
  if(sha256Json(databaseBackupStats(opts.sqlitePath))!==sha256Json(tables)) throw new Error("SQLite changed during cross-store backup; no verified manifest published");
  for(const raw of raw_files) if(await fileSha256(raw.source)!==raw.sha256) throw new Error("raw payload changed during backup");
  const manifest:BackupManifest={version:1,created_at:(opts.now??(()=>new Date()))().toISOString(),status:"verified",source_sqlite:resolve(opts.sqlitePath),
    sqlite:{path:"safetrace.sqlite",sha256:await fileSha256(sqlPath),tables},
    qdrant:{collection:opts.collection,config:info.config,path:"qdrant-points.jsonl",sha256:await fileSha256(vectors),points:first.count,content_sha256:first.hash,dimension:info.dimension},raw_files,missing_raw_refs,
    note:"Verified logical SQLite clone and full vector export, not an in-place restore. Existing missing/overwritten historical raw payloads cannot be reconstructed by backup."};
  await verifyBackup(directory,manifest);
  await writeFile(join(directory,"manifest.json"),JSON.stringify(manifest,null,2)+"\n",{flag:"wx",mode:0o600});
  return {directory,manifest};
}

/** Exercise exported vectors against a fresh scratch collection; never restore over production. */
export async function verifyVectorRestore(directory:string, transport:Pick<BackupOptions,"qdrantUrl"|"apiKey"|"fetchImpl">):Promise<{collection:string;points:number;deleted:boolean}> {
  await verifyBackup(directory);
  const manifest=JSON.parse(await readFile(join(directory,"manifest.json"),"utf8")) as BackupManifest;
  const collection="safetrace_restore_verify_"+randomUUID().replaceAll("-","");
  const opts:BackupOptions={...transport,collection,sqlitePath:"unused",outputRoot:"unused"};
  const endpoint=localEndpoint(opts.qdrantUrl,collection),fetcher=opts.fetchImpl??fetch;
  const config=manifest.qdrant.config as {params?:{vectors?:unknown}};
  let created=false;let verified=false;
  try {
    const response=await fetcher(endpoint,{method:"PUT",headers:headers(opts.apiKey),redirect:"error",signal:AbortSignal.timeout(30000),body:JSON.stringify({vectors:config.params?.vectors})});
    if(!response.ok) throw new Error("scratch restore create HTTP "+response.status);
    const result=await response.json() as {result?:unknown};
    if(result.result!==true) throw new Error("scratch collection creation not confirmed");
    created=true;
    const reader=createInterface({input:createReadStream(safeFile(directory,manifest.qdrant.path)),crlfDelay:Infinity});
    let batch:unknown[]=[];
    const put=async()=>{
      if(!batch.length)return;
      const res=await fetcher(endpoint+"/points?wait=true",{method:"PUT",headers:headers(opts.apiKey),redirect:"error",signal:AbortSignal.timeout(30000),body:JSON.stringify({points:batch})});
      if(!res.ok)throw new Error("scratch restore PUT HTTP "+res.status);
      const body=await res.json() as {result?:{status?:string}};
      if(body.result?.status!=="completed")throw new Error("scratch restore PUT not completed");batch=[];
    };
    for await(const line of reader){batch.push(validatePoint(JSON.parse(line),manifest.qdrant.dimension));if(batch.length===250)await put();}
    await put();
    const actual=await scanPoints(opts,manifest.qdrant.dimension);
    if(actual.count!==manifest.qdrant.points || actual.hash!==manifest.qdrant.content_sha256) throw new Error("scratch vector restore differs from verified backup");
    verified=true;
  }finally{
    // The exact endpoint was constructed from a fresh UUID above; never delete a supplied collection name.
    if(created){
      const removed=await fetcher(endpoint,{method:"DELETE",headers:headers(opts.apiKey),redirect:"error",signal:AbortSignal.timeout(30000)});
      if(!removed.ok || (await removed.json() as {result?:unknown}).result!==true)throw new Error("scratch restore collection cleanup failed: "+collection);
    }
  }
  return {collection,points:manifest.qdrant.points,deleted:created&&verified};
}
