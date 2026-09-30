import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { SqliteEventStore } from "@safetrace/shared";

const traceId = process.argv[2]?.trim();
if (!traceId) {
  console.error("用法：npm run trace:lineage -- <trace_id>");
  process.exitCode = 2;
} else {
  const dbPath = resolve(process.env.SQLITE_PATH ?? "./var/safetrace.sqlite");
  if (!existsSync(dbPath)) {
    console.error("lineage DB 不存在：" + dbPath);
    process.exitCode = 1;
  } else {
    const store = new SqliteEventStore(dbPath);
    try {
      const records = await store.readLineage(traceId);
      console.log(JSON.stringify({ trace_id: traceId, count: records.length, records }, null, 2));
      if (records.length === 0) process.exitCode = 1;
    } finally {
      store.close();
    }
  }
}
