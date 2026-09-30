"""从 hf-mirror 下载 ONNX 版中文嵌入模型（bge-small-zh-v1.5 量化版，22.9MB）。

为什么走 ONNX 而不是 sentence-transformers：
- `sentence-transformers` 需要 `torch`（约 2.5GB，构建/安装易断）；
- 本机 `huggingface.co` 不可达，但 **`hf-mirror.com` 可达**；
- `onnxruntime` 体积小得多，且量化模型只有 22.9MB。

产物落在 `data/models/bge-small-zh-v1.5/`（已 gitignore，不入库）。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

MIRROR = "https://hf-mirror.com"

#: 可选的 ONNX 嵌入模型。都是量化版（体积小、CPU 可跑）。
CANDIDATES: dict[str, dict[str, object]] = {
    # 中文专用：22.9MB，中文语义好；但中文词表不含 vLLM/LangChain 这类英文产品名，
    # 会被切成 [UNK]（实测）——我们的语料里产品名很关键。
    "bge-small-zh": {
        "repo": "Xenova/bge-small-zh-v1.5",
        "dir": "bge-small-zh-v1.5",
        "dim": 512,
        "vocab": "vocab.txt",
    },
    # 多语言：113MB，中英混排友好，能保留英文产品名的子词。
    "multilingual-minilm": {
        "repo": "Xenova/paraphrase-multilingual-MiniLM-L12-v2",
        "dir": "paraphrase-multilingual-MiniLM-L12-v2",
        "dim": 384,
        "vocab": "vocab.txt",
    },
}

BASE_FILES = ["tokenizer.json", "config.json", "tokenizer_config.json", "special_tokens_map.json"]


def fetch(repo: str, remote: str, dest: Path, retries: int = 3) -> bool:
    url = f"{MIRROR}/{repo}/resolve/main/{remote}"
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "safetrace-demo/1.0"})
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = resp.read()
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            print(f"  ✓ {remote} -> {dest.name}  {len(data) / 1024 / 1024:.1f}MB")
            return True
        except Exception as exc:  # noqa: BLE001
            print(f"  … {remote} 第 {attempt}/{retries} 次失败: {type(exc).__name__}")
    print(f"  ✗ {remote} 放弃")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="从 hf-mirror 下载 ONNX 嵌入模型")
    ap.add_argument("--model", default="bge-small-zh", choices=sorted(CANDIDATES))
    ap.add_argument("--all", action="store_true", help="下载全部候选（用于对比评测）")
    args = ap.parse_args()

    targets = sorted(CANDIDATES) if args.all else [args.model]
    for key in targets:
        spec = CANDIDATES[key]
        repo = str(spec["repo"])
        dest_dir = Path("data/models") / str(spec["dir"])
        print(f"=== {key}  ({repo}) ===")
        print(f"    目标: {dest_dir.resolve()}   维度 {spec['dim']}")

        wanted = ["onnx/model_quantized.onnx", *BASE_FILES, str(spec["vocab"])]
        for remote in wanted:
            name = "model_quantized.onnx" if remote.startswith("onnx/") else remote
            target = dest_dir / name
            if target.exists() and target.stat().st_size > 0:
                print(f"  = {name} 已存在（{target.stat().st_size / 1024 / 1024:.1f}MB）")
                continue
            fetch(repo, remote, target)

        cfg_path = dest_dir / "config.json"
        if cfg_path.exists():
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            print(f"    hidden_size={cfg.get('hidden_size')}  model_type={cfg.get('model_type')}")
        print()

    print("✓ 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
