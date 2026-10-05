import { resolve } from "node:path";
import { createVerifiedBackup, verifyBackup, verifyVectorRestore } from "../src/shared/src/backup.js";

async function main():Promise<void> {
  const args=process.argv.slice(2);
  if(args[0]==="--restore-check" && args.length===2) {
    const result=await verifyVectorRestore(resolve(args[1]!),{qdrantUrl:process.env.QDRANT_URL??"http://127.0.0.1:6333",apiKey:process.env.QDRANT_API_KEY});
    console.log(JSON.stringify({mode:"scratch-vector-restore-verified",...result},null,2));return;
  }
  if(args[0]==="--verify" && args.length===2) {
    const directory=resolve(args[1]!);const result=await verifyBackup(directory);
    console.log(JSON.stringify({mode:"verified-existing",directory,...result},null,2));return;
  }
  if(args.length!==1 || args[0]!=="--create") throw new Error("Use --create for read-only-source backup, or --verify <backup-directory>; no production restore command is provided.");
  const result=await createVerifiedBackup({sqlitePath:resolve(process.env.SQLITE_PATH??"./var/safetrace.sqlite"),outputRoot:resolve("./.tmp/verified-backups"),
    qdrantUrl:process.env.QDRANT_URL??"http://127.0.0.1:6333",collection:process.env.QDRANT_INTEL_COLLECTION??"safetrace_intel_demo",apiKey:process.env.QDRANT_API_KEY});
  console.log(JSON.stringify({mode:"created-and-independent-restore-verified",directory:result.directory,
    tables:result.manifest.sqlite.tables.map(t=>({name:t.name,rows:t.rows})),points:result.manifest.qdrant.points,dimension:result.manifest.qdrant.dimension,
    raw_files:result.manifest.raw_files.length,missing_raw_refs:result.manifest.missing_raw_refs.length,
    note:result.manifest.note},null,2));
}
main().catch(error=>{console.error("backup failed: "+(error instanceof Error?error.message:String(error)));process.exitCode=1;});
