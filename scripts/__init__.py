"""开发脚本包。

两件事：
1. 把 src 加进 sys.path，这些脚本（验收、演示、种子数据）不要求先 `pip install -e .`；
   已安装过也不冲突——sys.path 里的重复项无副作用。
2. 把 stdout 切成 UTF-8。Windows 控制台默认 GBK，脚本里一旦出现 ¥、→、✅
   之类字符就会抛 UnicodeEncodeError，或者在 PowerShell 里显示成乱码。
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def enable_utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        # 被重定向到不支持的流时忽略：总比脚本直接崩掉好
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8", errors="replace")


enable_utf8_stdout()
