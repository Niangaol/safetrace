import { DatabaseSync } from "node:sqlite";
import { realpath, stat } from "node:fs/promises";
import { resolve, relative, isAbsolute } from "node:path";
import { sha256Json } from "@safetrace/shared";
import { fileSha256 } from "../../shared/src/backup.js";

/** Cheap read generation plus original-byte fingerprints; never rely only on file names or a TTL. */
export async function knowledgeGeneration(options:{sqlitePath:string;payloadRoots?:readonly string[]}):Promise<string>{
  const db=new DatabaseSync(options.sqlitePath,{readOnly:true});db.exec("BEGIN");
  try{
    const has=(table:string)=>!!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table);
    const epoch={events:db.prepare("SELECT MAX(seq) AS seq,COUNT(*) AS rows FROM events").get(),lineage:db.prepare("SELECT MAX(seq) AS seq,COUNT(*) AS rows FROM lineage_records").get(),
      states:has("enrichment_dimension_history")?db.prepare("SELECT MAX(seq) AS seq,COUNT(*) AS rows FROM enrichment_dimension_history").get():null};
    const roots=await Promise.all((options.payloadRoots??[resolve("tmp/ingest-cache")]).map(r=>realpath(resolve(r))));
    const refs=new Set<string>();for(const row of db.prepare("SELECT payload FROM events WHERE topic='raw.docs'").all()){const value=JSON.parse(String(row.payload)) as {payload_ref?:unknown};if(typeof value.payload_ref==="string"&&!value.payload_ref.startsWith("sqlite-page:"))refs.add(value.payload_ref);}
    const files=[];for(const ref of [...refs].sort()){
      try{const full=await realpath(resolve(ref));if(!/[.](json|xml|html?|txt|payload)$/i.test(full)||!roots.some(root=>{const r=relative(root,full);return r!==""&&!r.startsWith("..")&&!isAbsolute(r);})||(await stat(full)).size>25*1024*1024){files.push({ref,unavailable:true});continue;}files.push({ref,sha256:await fileSha256(full)});}catch{files.push({ref,unavailable:true});}
    }
    const fileInfo=async(path:string)=>{try{const s=await stat(path);return {ino:s.ino,size:s.size,mtime:s.mtimeMs};}catch{return null;}};
    return sha256Json({epoch,files,sqlite:await fileInfo(options.sqlitePath),wal:await fileInfo(options.sqlitePath+"-wal")});
  }finally{db.exec("ROLLBACK");db.close();}
}
