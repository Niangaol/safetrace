import { mkdirSync, openSync, writeFileSync, closeSync, readFileSync, unlinkSync, realpathSync, statSync, lstatSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { resolve, dirname, basename, join } from "node:path";
import { sha256Json } from "@safetrace/shared";

/** Same-workspace CLI single writer; stale leases require operator reconciliation, never PID-only auto-stealing. */
export function acquireIntelIndexLease(url: string, collection: string, directory: string): () => void {
  const original=collection;
  if(collection.startsWith("enrichment-db:")){
    let current=resolve(collection.slice("enrichment-db:".length));const tail:string[]=[];
    try {const info=statSync(current);if(info.isFile()&&info.nlink>1)throw new Error("hard-linked database cannot be leased safely");}catch(error){if((error as NodeJS.ErrnoException).code!=="ENOENT")throw error;}
    for(;;){try{current=join(realpathSync(current),...tail.reverse());break;}catch(error){if((error as NodeJS.ErrnoException).code!=="ENOENT")throw error;try{lstatSync(current);throw new Error("unresolved existing database alias cannot be leased");}catch(check){if((check as NodeJS.ErrnoException).code!=="ENOENT")throw check;}const parent=dirname(current);if(parent===current)throw error;tail.push(basename(current));current=parent;}}
    collection="enrichment-db:"+(process.platform==="win32"?current.toLowerCase():current);
  }
  const normalized = new URL(url); normalized.pathname = normalized.pathname.replace(/\/+$/, "");
  const keys=[...new Set([original,collection])].sort();
  const releases:Array<()=>void>=[];
  const acquire=(key:string):(()=>void)=>{
  mkdirSync(directory, { recursive: true });
  const path = resolve(directory, sha256Json({ url: normalized.href, collection: key }) + ".lock");
  let fd: number;
  try { fd = openSync(path, "wx", 0o600); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new Error("intel collection already leased: " + path + "; reconcile unfinished audit and confirm writer stopped before removing stale lease");
    throw error;
  }
  const owner = JSON.stringify({ token: randomUUID(), pid: process.pid, created_at: new Date().toISOString() });
  try { writeFileSync(fd, owner); }
  catch (error) { closeSync(fd); throw error; }
  let released = false;
  return () => {
    if (released) return; released = true;
    closeSync(fd);
    // Never erase a replaced lease belonging to another process.
    if (readFileSync(path, "utf8") !== owner) throw new Error("intel lease ownership changed; refusing release");
    unlinkSync(path);
  };
  };
  try {for(const key of keys)releases.push(acquire(key));}
  catch(error){for(const release of releases.reverse())release();throw error;}
  return ()=>{let failed:unknown;for(const release of [...releases].reverse()){try{release();}catch(error){failed??=error;}}if(failed)throw failed;};
}
