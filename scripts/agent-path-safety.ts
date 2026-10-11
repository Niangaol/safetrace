/** Resolve existing ancestors before any SQLite/log writes; lexical .tmp prefixes are not permission. */
import { realpath, stat, lstat } from "node:fs/promises";
import { resolve, dirname, basename, join } from "node:path";
export async function canonicalWritePath(input:string):Promise<string> {
  let current=resolve(input);const tail:string[]=[];
  for(;;){
    try {const base=await realpath(current);return join(base,...tail.reverse());}
    catch(error){if((error as NodeJS.ErrnoException).code!=="ENOENT")throw error;
      try {await lstat(current);throw new Error("existing unresolved path or dangling link is not a safe write target");}
      catch(check){if((check as NodeJS.ErrnoException).code!=="ENOENT")throw check;}
      const parent=dirname(current);if(parent===current)throw error;tail.push(basename(current));current=parent;}
  }
}
export async function rejectHardLinkedFile(input:string):Promise<void> {
  try {const info=await stat(input);if(info.isFile()&&info.nlink>1)throw new Error("hard-linked write target is ambiguous; use an independent database/log file");}
  catch(error){if((error as NodeJS.ErrnoException).code!=="ENOENT")throw error;}
}
