"""Pinned isolated Open-Jev GPU deployment; never writes SafeTrace business databases."""
import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UPSTREAM = ROOT / "third_party" / "open-jev"
MODEL_ROOT = ROOT / "third_party" / "open-jev-models"
CODE_REVISION = "80ca8e81d08992cb2a4cbb6a0caa1355ad3e5aee"
MODEL_REVISION = "0c7aa498b1627be8da4acf34c863ff0ee0a92785"
BASE_REVISION = "15852e8c16360a2fea060d615a32b45270f8a8fc"
MODEL_REPO = "ZefanCai/Open-Jev-2B"
os.environ["HF_HOME"] = str(MODEL_ROOT / "cache")
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
# httpx 0.28 misparses bare IPv6 NO_PROXY entries on this Windows host.
# Normalize this interpreter only; retain all non-IPv6 exclusions and configured proxy.
for key in ("NO_PROXY", "no_proxy"):
    if key in os.environ:
        os.environ[key] = ",".join(part.strip() for part in os.environ[key].split(",")
                                   if part.strip() not in ("::1", "[::1]"))

def checkpoint_hash(path):
    digest = hashlib.sha256()
    for file in sorted(path.rglob("*")):
        if file.is_file():
            digest.update(str(file.relative_to(path)).encode() + b"\0")
            with file.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
    return digest.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "serve", "verify"))
    parser.add_argument("--port", type=int, default=8791)
    args = parser.parse_args()
    import torch
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is unavailable; refusing silent CPU fallback")
    probe = torch.ones(16, device="cuda:0")
    assert probe.sum().item() == 16
    print(json.dumps({"torch": torch.__version__, "cuda": torch.version.cuda,
                      "gpu": torch.cuda.get_device_name(0), "capability": torch.cuda.get_device_capability(0)}, ensure_ascii=False), flush=True)
    if args.action == "verify":
        return
    from huggingface_hub import snapshot_download
    package = MODEL_ROOT / "Open-Jev-2B"
    if args.action == "prepare":
        snapshot_download(MODEL_REPO, revision=MODEL_REVISION, local_dir=str(package),
                          allow_patterns=["package/checkpoint/*"])
        checkpoint = package / "package" / "checkpoint"
        config = json.loads((checkpoint / "model.json").read_text(encoding="utf-8"))
        revision = config.get("revision")
        if revision != BASE_REVISION:
            raise RuntimeError(f"Checkpoint base revision mismatch: {revision}")
        base_id = config.get("model_id")
        if base_id != "Qwen/Qwen3.5-2B":
            raise RuntimeError(f"Unexpected base model: {base_id}")
        snapshot_download(base_id, revision=BASE_REVISION,
                          allow_patterns=["*.safetensors", "*.json", "*.txt", "*.model"])
        manifest = {"code_revision": CODE_REVISION, "model_repo": MODEL_REPO,
                    "model_revision": MODEL_REVISION, "base_revision": BASE_REVISION,
                    "checkpoint_sha256": checkpoint_hash(checkpoint), "checkpoint": str(checkpoint)}
        (MODEL_ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(json.dumps(manifest), flush=True)
        return
    from jev.serving import load_predictor
    from jev.server import make_server
    manifest = json.loads((MODEL_ROOT / "manifest.json").read_text(encoding="utf-8"))
    checkpoint = package / "package" / "checkpoint"
    if checkpoint_hash(checkpoint) != manifest["checkpoint_sha256"]:
        raise RuntimeError("Checkpoint changed after preparation")
    predictor = load_predictor(checkpoint=str(checkpoint), device="cuda:0", max_length=4096,
                               batch_size=1, prefix_cache=False, backend="torch")
    devices = sorted({str(p.device) for p in predictor.scorer.model.parameters()})
    if devices != ["cuda:0"]:
        raise RuntimeError(f"Model is not fully on GPU: {devices}")
    if predictor.provenance.get("code_commit") != CODE_REVISION:
        raise RuntimeError("Open-Jev code commit mismatch")
    predictor.provenance.update(device="cuda:0", gpu=torch.cuda.get_device_name(0),
                                model_revision=MODEL_REVISION, parameter_devices=devices)
    print(json.dumps({"ready": True, "model": predictor.model_name, "provenance": predictor.provenance,
                      "allocated_bytes": torch.cuda.memory_allocated()}), flush=True)
    server = make_server(predictor, host="127.0.0.1", port=args.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
