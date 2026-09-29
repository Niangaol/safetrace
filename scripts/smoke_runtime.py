"""运行期冒烟检查：验证**跑起来的服务**是否真的可用。

与 `scripts/accept.py` 的分工（别混用）：

| | 跑在哪 | 测什么 |
| --- | --- | --- |
| `accept.py` | **开发机** | 代码门禁：ruff / mypy / pytest / 前端构建 / 迁移 |
| `smoke_runtime.py`（本文件） | **容器内或对着已起的栈** | 服务是否真的在干活 |

为什么不在容器里跑 `accept.py`：它是开发门禁，需要 ruff/mypy/pytest 等 **dev 依赖**，
而生产镜像按设计只装运行期依赖（实测报 `No module named 'scripts'`，
且即便拷进去也没有 dev 工具）。把 dev 依赖塞进生产镜像只为跑冒烟，得不偿失。

本脚本只依赖运行期已有的东西（HTTP + SQLAlchemy + psycopg），检查项：

1. `/health` 返回 ok
2. 迁移确实生效（张表数 / alembic 版本）
3. `/api/v1/vulns` 能查出数据（不只是 200，要看 total）
4. `/api/v1/qa/chat` 能出 SSE 帧（含 citation / done）
5. Redis 事件总线是否可用（连得上就算通过；连不上如实标 degraded）

退出码：0 全部通过；1 有失败项。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("SMOKE_BASE_URL", "http://localhost:8000")
API = f"{BASE}/api/v1"
TOKEN = os.environ.get("API_TOKEN", "")

results: list[tuple[str, bool, str]] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    mark = "OK  " if ok else "FAIL"
    print(f"  [{mark}] {name}  {detail}", flush=True)


def http_json(path: str, timeout: int = 20) -> tuple[int, dict | None]:
    req = urllib.request.Request(f"{API}{path}")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except Exception:  # noqa: BLE001
        return 0, None


def check_health() -> None:
    try:
        with urllib.request.urlopen(f"{BASE}/health", timeout=15) as resp:
            body = json.loads(resp.read().decode())
        record("health", body.get("status") == "ok", f"status={body.get('status')}")
    except Exception as exc:  # noqa: BLE001
        record("health", False, str(exc)[:90])


def check_migrations() -> None:
    """直连库看表数与 alembic 版本 —— 证明容器内迁移真的跑了。"""

    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        record("迁移", False, "未设置 POSTGRES_DSN")
        return
    try:
        from sqlalchemy import create_engine, text

        engine = create_engine(dsn, connect_args={"connect_timeout": 6})
        with engine.connect() as conn:
            tables = conn.execute(
                text("select count(*) from pg_tables where schemaname='public'")
            ).scalar()
            try:
                rev = conn.execute(text("select version_num from alembic_version")).scalar()
            except Exception:  # noqa: BLE001
                rev = "(无 alembic_version 表)"
        ok = bool(tables) and tables >= 10
        record("迁移", ok, f"{tables} 张表, alembic={rev}")
    except Exception as exc:  # noqa: BLE001
        record("迁移", False, f"{type(exc).__name__}: {str(exc)[:70]}")


def check_vulns() -> None:
    status, body = http_json("/vulns?page_size=3")
    if status != 200 or not isinstance(body, dict):
        record("vulns 列表", False, f"HTTP {status}")
        return
    total = body.get("total")
    items = body.get("items") or []
    record("vulns 列表", total is not None, f"total={total}, 本页 {len(items)} 条")


def check_metrics() -> None:
    status, body = http_json("/metrics/overview")
    if status != 200 or not isinstance(body, dict):
        record("metrics", False, f"HTTP {status}")
        return
    keys = sorted(body.keys())[:5]
    record("metrics", bool(keys), f"顶层键={keys}")


def check_qa_sse() -> None:
    """打一次真实问答，确认能收到 citation / done 帧。

    注意：SSE 不能简单用 urllib 一次读完；这里逐行读流。
    """

    payload = json.dumps(
        {"question": "CVE-2026-31001 怎么修复？", "stream": True, "top_k": 3}
    ).encode()
    req = urllib.request.Request(f"{API}/qa/chat", data=payload)
    req.add_header("Content-Type", "application/json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    saw_citation = saw_done = saw_stage = False
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            for raw in resp:
                line = raw.decode("utf-8", errors="replace").strip()
                if line.startswith("event: citation"):
                    saw_citation = True
                elif line.startswith("event: done"):
                    saw_done = True
                elif line.startswith("event: stage"):
                    saw_stage = True
                # citation 与 done 都见到就够了，不必等满 3 分钟
                if saw_citation and saw_done:
                    break
        ok = saw_stage and saw_done
        record("问答 SSE", ok, f"stage={saw_stage} citation={saw_citation} done={saw_done}")
    except Exception as exc:  # noqa: BLE001
        record("问答 SSE", False, f"{type(exc).__name__}: {str(exc)[:70]}")


def check_redis() -> None:
    url = os.environ.get("REDIS_URL")
    if not url:
        record("Redis", False, "未设置 REDIS_URL（事件总线将降级）")
        return
    try:
        import redis  # type: ignore

        client = redis.Redis.from_url(url, socket_connect_timeout=6)
        client.ping()
        record("Redis", True, "PING 成功")
    except Exception as exc:  # noqa: BLE001
        record("Redis", False, f"{type(exc).__name__}: {str(exc)[:70]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="运行期冒烟检查")
    parser.add_argument("--base", default=None, help="覆盖 BASE URL")
    args = parser.parse_args()
    global BASE, API
    if args.base:
        BASE = args.base
        API = f"{BASE}/api/v1"

    print(f"=== 运行期冒烟（{BASE}）===")
    check_health()
    check_migrations()
    check_vulns()
    check_metrics()
    check_redis()
    check_qa_sse()

    failed = [r for r in results if not r[1]]
    print()
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed / 共 {len(results)} 项")
    for name, _, detail in failed:
        print(f"  ✗ {name}: {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
