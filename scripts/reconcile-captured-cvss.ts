import { reconcileCapturedCvss } from "../src/enrich/src/captured-cvss.js";
async function main(){const args=process.argv.slice(2),arg=args.find(a=>a.startsWith("--limit="));if(args.some(a=>!["--apply","--dry-run"].includes(a)&&!a.startsWith("--limit=")))throw new Error("unsupported argument");if(args.includes("--apply")&&args.includes("--dry-run"))throw new Error("apply/dry-run mutually exclusive");
console.log(JSON.stringify(await reconcileCapturedCvss({sqlitePath:process.env.SQLITE_PATH??"./var/safetrace.sqlite",apply:args.includes("--apply"),limit:arg?Number(arg.slice(8)):20,backupDirectory:process.env.SAFETRACE_VERIFIED_BACKUP_DIR}),null,2));}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
