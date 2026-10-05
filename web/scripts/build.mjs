// A per-build temp directory avoids shared Windows Temp delete restrictions.
// No system permission changes, and concurrent builds never share esbuild files.
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = fileURLToPath(new URL("../", import.meta.url));
const cache = join(root, "node_modules", ".cache");
mkdirSync(cache, { recursive: true });
const temp = mkdtempSync(join(cache, "safetrace-build-"));
let code = 0;
try {
  for (const [entry, args] of [["vue-tsc/bin/vue-tsc.js", ["--noEmit"]], ["vite/bin/vite.js", ["build", ...process.argv.slice(2)]]]) {
    const result = spawnSync(process.execPath, [join(root, "node_modules", entry), ...args], {
      cwd: root, stdio: "inherit", env: { ...process.env, TEMP: temp, TMP: temp, TMPDIR: temp },
    });
    if (result.error) { console.error(result.error.message); code = 1; break; }
    if (result.status !== 0) { code = result.status ?? 1; break; }
  }
} finally {
  // Delete only the exact unique directory created by this invocation, not any computed ancestor.
  if (resolve(temp).startsWith(resolve(cache) + "/") || resolve(temp).startsWith(resolve(cache) + "\\")) {
    try { rmSync(temp, { recursive: true, force: true }); }
    catch (error) { console.error("build temp cleanup failed: " + error.message); code ||= 1; }
  } else { console.error("build temp path verification failed"); code ||= 1; }
}
process.exitCode = code;
