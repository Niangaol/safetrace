"""一键演示：像打开 APP 一样看前端。

一条命令拉起完整环境：
  1. 生成演示数据到 data/demo.db（SQLite，无需 PostgreSQL）
  2. 起后端 uvicorn（含 /docs）
  3. 起前端 vite
  4. 自动打开浏览器

用法：
    python -m scripts.demo              # 起全部
    python -m scripts.demo --no-reseed  # 复用已有演示数据
    python -m scripts.demo --api-only   # 只起后端
    python -m scripts.demo --reset      # 清掉残留进程后再起

Ctrl+C 一并停掉两个服务。

注意：这里开了 DEMO_MODE。无 LLM 凭据时问答返回带【演示模式】标注的占位回答，
用来验证前端渲染与 SSE 流式链路；配了 LLM_API_KEY 则照常走真实模型。
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO_DB = ROOT / "data" / "demo.db"
DEMO_DSN = f"sqlite:///{DEMO_DB.as_posix()}"
API_PORT = 8000
WEB_PORT = 5173
# 绑 0.0.0.0 而不是 127.0.0.1：后者在浏览器把 localhost 解析成 ::1(IPv6)、
# 或用本机 IP/机器名访问时会被直接拒掉，前端表现为一片 "Failed to fetch"
BIND_HOST = os.environ.get("DEMO_BIND_HOST", "0.0.0.0")

DEMO_ENV = {
    "APP_ENV": "dev",
    "API_TOKEN": "",
    "POSTGRES_DSN": DEMO_DSN,
    "REDIS_URL": "",  # 演示不依赖 Redis，事件总线走降级分支
    "COST_TRACKER_PATH": "./data/demo.cost.jsonl",
    "DEMO_MODE": "true",
    "LLM_LOCAL_ENABLED": "false",
    "PYTHONPATH": str(ROOT / "src"),
    "PYTHONIOENCODING": "utf-8",
    "PYTHONUTF8": "1",
}


def _log(msg: str) -> None:
    print(f"[demo] {msg}", flush=True)


def _npm() -> str | None:
    if os.name != "nt":
        return shutil.which("npm")
    return shutil.which("npm.cmd") or shutil.which("npm")


def _wait_http(url: str, timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:  # noqa: S310
                if resp.status < 500:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.6)
    return False


def _kill_port(port: int) -> None:
    if os.name == "nt":
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-NetTCPConnection -LocalPort {port} -ErrorAction SilentlyContinue | "
                f"ForEach-Object {{ Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }}",
            ],
            capture_output=True,
            check=False,
        )
    else:  # pragma: no cover
        subprocess.run(["pkill", "-f", f":{port}"], capture_output=True, check=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="一键演示模式")
    parser.add_argument("--no-reseed", action="store_true", help="复用已有演示数据")
    parser.add_argument("--api-only", action="store_true", help="只起后端，不起前端")
    parser.add_argument("--reset", action="store_true", help="先杀掉占用端口的残留进程")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args()

    env = {**os.environ, **DEMO_ENV}

    if args.reset:
        _log("清理端口残留…")
        _kill_port(API_PORT)
        _kill_port(WEB_PORT)
        time.sleep(1.5)

    if not args.no_reseed or not DEMO_DB.exists():
        _log("生成演示数据…")
        subprocess.run(
            [sys.executable, "-m", "scripts.demo_seed", "--db", str(DEMO_DB)],
            cwd=ROOT,
            env=env,
            check=True,
        )

    npm = _npm()
    if not args.api_only and npm is None:
        _log("找不到 npm，只起后端（前端需 Node.js 20+）")

    procs: list[tuple[str, subprocess.Popen]] = []

    _log(f"启动后端 http://127.0.0.1:{API_PORT} (docs: /docs, 绑定 {BIND_HOST})")
    api = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "aiintel.api.main:app",
            "--host",
            BIND_HOST,
            "--port",
            str(API_PORT),
        ],
        cwd=ROOT,
        env=env,
    )
    procs.append(("后端", api))

    web: subprocess.Popen | None = None
    if npm and not args.api_only:
        if not (ROOT / "web" / "node_modules").is_dir():
            _log("安装前端依赖（首次较慢）…")
            subprocess.run([npm, "install"], cwd=ROOT / "web", env=env, check=False)
        _log(f"启动前端 http://127.0.0.1:{WEB_PORT} (绑定 {BIND_HOST})")
        web = subprocess.Popen(
            [npm, "run", "dev", "--", "--host", BIND_HOST, "--port", str(WEB_PORT)],
            cwd=ROOT / "web",
            env=env,
        )
        procs.append(("前端", web))

    def shutdown(*_: object) -> None:
        _log("停止服务…")
        for _name, proc in procs:
            if proc.poll() is None:
                proc.terminate()
        time.sleep(1.0)
        for _name, proc in procs:
            if proc.poll() is None:
                proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    api_ready = _wait_http(f"http://127.0.0.1:{API_PORT}/api/v1/system/health")
    _log("后端就绪" if api_ready else "后端启动超时，看上面的日志")

    if web:
        web_ready = _wait_http(f"http://127.0.0.1:{WEB_PORT}/", timeout=60)
        _log("前端就绪" if web_ready else "前端启动超时，看上面的日志")

    target = (
        f"http://127.0.0.1:{API_PORT}/docs"
        if args.api_only or not web
        else f"http://127.0.0.1:{WEB_PORT}"
    )
    print()
    print("  ┌─────────────────────────────────────────────┐")
    print("  │  演示模式已启动                              │")
    print("  ├─────────────────────────────────────────────┤")
    print(f"  │  前端界面   {target:<38}│")
    print(f"  │  API 文档   http://127.0.0.1:{API_PORT}/docs{'':<15}│")
    print("  ├─────────────────────────────────────────────┤")
    print("  │  问答返回带【演示模式】标注 = 没有 LLM 凭据    │")
    print("  │  配 LLM_API_KEY 后重启即为真实模型输出         │")
    print("  └─────────────────────────────────────────────┘")
    print()
    print("  Ctrl+C 停止\n")

    if not args.no_browser:
        try:
            webbrowser.open(target)
        except Exception as exc:  # noqa: BLE001
            _log(f"打开浏览器失败，手动访问 {target}: {exc}")

    try:
        while True:
            for name, proc in procs:
                if proc.poll() is not None:
                    _log(f"{name} 已退出 (code={proc.returncode})")
                    shutdown()
            time.sleep(0.8)
    except KeyboardInterrupt:
        shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
