import { mkdirSync, openSync, writeFileSync, closeSync, readFileSync, unlinkSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { sha256Json } from "@safetrace/shared";

/** Same-workspace CLI single writer; stale leases require operator reconciliation, never PID-only auto-stealing. */
export function acquireIntelIndexLease(url: string, collection: string, directory: string): () => void {
  const normalized = new URL(url); normalized.pathname = normalized.pathname.replace(/\/+$/, "");
  mkdirSync(directory, { recursive: true });
  const path = resolve(directory, sha256Json({ url: normalized.href, collection }) + ".lock");
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
}
