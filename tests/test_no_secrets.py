"""防止真实密钥再次进入仓库。

**为什么需要这个**：本仓已经**两次**把真实密钥写进了会被提交的文件——
第一次是配置界面的备份文件（`.env.env.bak`，含真实 key），
第二次是测试文件里拿真实 key 当测试数据（"反正只是个字符串"）。
两次都是"顺手"造成的，靠人记不住。所以用测试兜住。

判据：扫描**会被提交的文本文件**，找形似 `sk-` 开头的长串。
允许的例外只有明显是占位的假串（见 ALLOWED）。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: 形似真实密钥：sk- 后跟 32 位以上字母数字
KEY_LIKE = re.compile(r"sk-[A-Za-z0-9]{32,}")

#: 明确是假串的允许名单（测试用的占位符）
ALLOWED = {
    "sk-fake0123456789abcdefghijklmnopqrst",
    "sk-existing-key-1234567890",
}

#: 不扫描的路径（第三方代码、构建产物、虚拟环境）
SKIP_PARTS = ("node_modules", ".git", "__pycache__", ".venv", "venv", "dist", ".mypy_cache")


def _tracked_files() -> list[str]:
    r = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def test_no_real_api_key_in_tracked_files() -> None:
    """被跟踪的文件里不许出现真实外观的密钥。"""

    offenders: list[str] = []
    for rel in _tracked_files():
        if any(part in rel for part in SKIP_PARTS):
            continue
        path = REPO / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for match in KEY_LIKE.findall(text):
            if match not in ALLOWED:
                offenders.append(f"{rel}: {match[:12]}…（长度 {len(match)}）")

    assert not offenders, "检测到疑似真实密钥被跟踪，必须移除并把该 key 轮换：\n  " + "\n  ".join(
        offenders
    )


def test_env_variants_are_gitignored() -> None:
    """`.env` 的所有变体都必须被忽略（备份/临时文件同样含密钥）。"""

    for name in (".env", ".env.bak", ".env.env.bak", ".env.tmp", ".env.local"):
        r = subprocess.run(
            ["git", "check-ignore", name], cwd=REPO, capture_output=True, text=True, timeout=20
        )
        assert r.returncode == 0, f"{name} 未被 .gitignore 覆盖，可能被误提交"


def test_env_example_still_tracked() -> None:
    """但不能把示例文件也忽略掉——那是给人照抄的。"""

    r = subprocess.run(
        ["git", "check-ignore", ".env.example"],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert r.returncode != 0, ".env.example 被忽略了，示例文件应当入库"
