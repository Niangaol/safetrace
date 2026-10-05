import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { verifyBackup } from "../src/shared/src/backup.js";
import type { BackupManifest } from "../src/shared/src/backup.js";

/** Maintenance writes require a verified backup of this database, not a different fixture DB. */
export async function requireVerifiedBackup(sqlitePath:string,directory=process.env.SAFETRACE_VERIFIED_BACKUP_DIR):Promise<void> {
  if(!directory)throw new Error("--apply requires SAFETRACE_VERIFIED_BACKUP_DIR; create/verify backup before changing business data");
  const manifest=JSON.parse(await readFile(join(resolve(directory),"manifest.json"),"utf8")) as BackupManifest;
  if(resolve(manifest.source_sqlite)!==resolve(sqlitePath))throw new Error("verified backup belongs to another business database");
  if(manifest.missing_raw_refs.length)throw new Error("verified backup has missing raw payloads; resolve backup coverage before maintenance");
  await verifyBackup(resolve(directory),manifest);
}
