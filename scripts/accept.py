"""一键验收：把"能不能交"变成一条命令的可执行判据。

用法：
    python -m scripts.accept

退出码 0 表示所有已验证项通过。有几项依赖外部服务（PostgreSQL/pgvector、
Redis、DeepSeek、Ollama），缺依赖时会标 SKIP 而不是 FAIL——区分"没测"和"测挂了"。
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

OK = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"


@dataclass
class Result:
    name: str
    status: str
    detail: str = ""
    seconds: float = 0.0


@dataclass
class Suite:
    results: list[Result] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "", seconds: float = 0.0) -> None:
        self.results.append(Result(name, status, detail, seconds))

    @property
    def failed(self) -> list[Result]:
        return [r for r in self.results if r.status == FAIL]

    def render(self) -> str:
        width = max(len(r.name) for r in self.results) + 2
        lines = []
        icon = {OK: "[ OK ]", FAIL: "[FAIL]", SKIP: "[SKIP]"}
        for r in self.results:
            head = f"{icon[r.status]} {r.name.ljust(width)}"
            if r.detail:
                head += r.detail
            if r.seconds >= 1:
                head += f"  ({r.seconds:.1f}s)"
            lines.append(head)
        passed = sum(1 for r in self.results if r.status == OK)
        skipped = sum(1 for r in self.results if r.status == SKIP)
        lines.append("")
        lines.append(
            f"{passed} passed, {len(self.failed)} failed, {skipped} skipped"
            f" / 共 {len(self.results)} 项"
        )
        return "\n".join(lines)


def npm_exe() -> str:
    """Windows 上 npm 是 npm.cmd 包装脚本；不带 shell 的 subprocess 跑不了 .ps1。"""

    if os.name != "nt":
        return "npm"
    import shutil

    return shutil.which("npm.cmd") or shutil.which("npm") or "npm"


def run(
    label: str, cmd: list[str], *, cwd: str | None = None, timeout: int = 900
) -> tuple[str, str, float]:
    """跑一条命令。返回 (状态, 失败原因或提示, 耗时秒)。"""

    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return FAIL, f"超时 {timeout}s", time.perf_counter() - started
    except FileNotFoundError:
        return SKIP, f"命令不存在: {cmd[0]}", time.perf_counter() - started
    elapsed = time.perf_counter() - started
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr).strip().splitlines()
        return FAIL, (tail[-1][:120] if tail else f"exit={proc.returncode}"), elapsed
    return OK, "", elapsed


def db_available() -> bool:
    """能否连上真实 PostgreSQL。评测与迁移脚本依赖它。

    注意 DSN 是 SQLAlchemy 形式的 `postgresql+psycopg://...`，**不能直接喂给
    `psycopg.connect`**——psycopg 不认识 `+psycopg` 这个 driver 后缀，会抛
    `missing "=" after ... in connection info`，被下面的 except 吞掉后误判成
    "数据库不可用"。必须先用 make_url 拆出连接参数。
    """

    try:
        import psycopg
        from sqlalchemy.engine import make_url

        dsn = os.getenv("POSTGRES_DSN")
        if not dsn:
            return False
        url = make_url(dsn)
        with psycopg.connect(
            host=url.host,
            port=url.port,
            user=url.username,
            password=url.password,
            dbname=url.database,
            connect_timeout=3,
        ) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


def main() -> int:
    os.environ.setdefault("APP_ENV", "dev")
    os.environ.setdefault("API_TOKEN", "")
    suite = Suite()

    # 1. 静态质量门禁
    for name, cmd in (
        ("ruff check", [sys.executable, "-m", "ruff", "check", "."]),
        ("ruff format", [sys.executable, "-m", "ruff", "format", "--check", "."]),
        ("mypy", [sys.executable, "-m", "mypy", "src"]),
        # 契约校验：EnrichmentResult / IntelItem / EventEnvelope 与 fixture 必须自洽
        ("契约校验", [sys.executable, "-m", "scripts.validate_contracts"]),
    ):
        suite.add(name, *run(name, cmd))

    # 2. 全部单测（含真实启动 uvicorn 的冒烟）
    suite.add("单元测试", *run("pytest", [sys.executable, "-m", "pytest", "-q", "--no-cov"]))

    # 3. 前端类型检查 + 构建
    suite.add("前端构建", *run("前端构建", [npm_exe(), "run", "build"], cwd="web"))

    # 4. 依赖数据库的项：连不上就 SKIP，不算失败
    if db_available():
        suite.add(
            "数据库迁移", *run("alembic", [sys.executable, "-m", "alembic", "upgrade", "head"])
        )
        suite.add("评测脚本", *run("评测", [sys.executable, "-m", "eval.run_all"], timeout=1800))
    else:
        # pgvector 不再是硬前提：0001 缺扩展时会建缺 embedding 列的 chunk 表并
        # 降级到关键词检索（见 versions/0001_init.py 的降级契约）。
        suite.add("数据库迁移", SKIP, "需要 POSTGRES_DSN 指向可连的 PostgreSQL")
        suite.add("评测脚本", SKIP, "需要真实数据库；可先跑各脚本的 sample 数据")

    # 5. 演示数据自检：SQLite 不依赖任何外部服务，这里能真跑。
    #
    # ⚠️ **必须传 `--db` 指向临时库**：`demo_seed.py` 的默认值是 `data/demo.db`，
    # 那正是运行中的 API 服务握着的文件。不传的话：
    #   ① 服务在跑时这一步直接因文件锁失败（报错还指向"环境问题"）；
    #   ② 服务没跑时它会**静默覆写**开发者正在用的演示库。
    # 验收脚本不该假设"没人开着服务"，也不该弄坏别人的数据。
    accept_db = Path("data/accept_check.db")
    with contextlib.suppress(OSError):
        accept_db.unlink()
    status, detail, seconds = run(
        "演示数据",
        [sys.executable, "-m", "scripts.demo_seed", "--db", str(accept_db)],
    )
    suite.add("演示数据", status, detail, seconds)
    # 跑完清理临时库（失败也不该让整轮验收炸掉）
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(OSError):
            Path(f"{accept_db}{suffix}").unlink()

    # 5. 需要真实外部服务的项
    for name, env_key, hint in (
        ("采集联调", "LLM_API_KEY", "需要 DeepSeek API Key"),
        ("本地兜底模型", "LLM_LOCAL_BASE_URL", "需要 Ollama 运行"),
    ):
        if os.getenv(env_key):
            suite.add(name, SKIP, "需人工联调，本脚本不代跑")
        else:
            suite.add(name, SKIP, hint)

    print(suite.render())
    if suite.failed:
        print("\n未通过项：")
        for r in suite.failed:
            print(f"  - {r.name}: {r.detail}")
    return 1 if suite.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
