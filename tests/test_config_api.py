"""配置管理接口的回归测试。

**重点在"不该泄漏"和"不该写坏"**，而不是功能能不能跑：

1. 密钥**永不明文回传**（只有 `configured` + 脱敏 `preview`）；
2. `.env` 写入**不能产生重复键**、不能丢键 ——
   `.env` 是启动依赖，写坏会让整个服务起不来；
3. 建连接时用掉的配置（`POSTGRES_DSN`/`REDIS_URL`）必须标 `requires_restart`，
   不能在界面上假装能热改。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aiintel.api.routers import config as cfg


@pytest.fixture()
def env_file(tmp_path, monkeypatch):
    """把 .env 指到临时文件，避免测试动到开发者真实的 .env。"""

    path = tmp_path / ".env"
    path.write_text(
        "# 注释应保留\n"
        "LLM_API_KEY=sk-existing-key-1234567890\n"
        "LLM_FLASH_MODEL=deepseek-flash\n"
        "POSTGRES_DSN=sqlite:///tmp/demo.db\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cfg, "ENV_PATH", path)
    return path


def _keys(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        s = raw.strip()
        if s and not s.startswith("#") and "=" in s:
            out.append(s.split("=", 1)[0].strip())
    return out


def test_mask_never_reveals_full_secret() -> None:
    secret = "sk-fake0123456789abcdefghijklmnopqrst"
    masked = cfg._mask(secret)
    assert secret not in masked
    assert masked.startswith("sk-71a7")
    assert masked.endswith("5ac9")
    assert "****" in masked
    # 短值整体打星，避免"脱敏后反而泄漏长度与内容"
    assert cfg._mask("short") == "*****"
    assert cfg._mask("") == ""


def test_upsert_env_no_duplicate_keys(env_file: Path) -> None:
    """回归：重复键会让后写的值覆盖先写的，是最容易出的写入 bug。"""

    cfg._upsert_env({"LLM_FLASH_MODEL": "deepseek-v4-pro", "DEMO_MODE": "false"})
    text = env_file.read_text(encoding="utf-8")
    keys = _keys(text)

    duplicates = {k for k in keys if keys.count(k) > 1}
    assert not duplicates, f"出现重复键: {duplicates}"
    # 就地替换，而不是追加
    assert "LLM_FLASH_MODEL=deepseek-v4-pro" in text
    assert "LLM_FLASH_MODEL=deepseek-flash" not in text
    # 新键追加
    assert "DEMO_MODE=false" in text
    # 原有其它键与注释都不能丢
    assert "LLM_API_KEY=sk-existing-key-1234567890" in text
    assert "POSTGRES_DSN=sqlite:///tmp/demo.db" in text
    assert "# 注释应保留" in text


def test_upsert_env_is_atomic_and_leaves_no_temp(env_file: Path) -> None:
    cfg._upsert_env({"A": "1"})
    # 不留临时文件（半截文件会让服务起不来）
    assert not list(env_file.parent.glob(".env.tmp")), "残留了 .env.tmp"
    # 也别留下"错名字"的临时文件
    assert not list(env_file.parent.glob(".env.env.tmp")), "残留了 .env.env.tmp"


def test_backup_filename_is_gitignore_safe(env_file: Path) -> None:
    """回归：备份文件名必须是 `.env.bak`，**不能是 `.env.env.bak`**。

    这条测试存在的理由：`Path('.env').with_suffix('.env.bak')` 会得到
    `.env.env.bak`，而它**不被 `.gitignore` 的 `.env` 规则覆盖** ——
    结果含真实密钥的备份被 `git add -A` 一起提交并推送了（真实事故）。

    注意：断言必须写**精确文件名**。早先这里写的是
    `assert (… / '.env.bak').exists() or True`，`or True` 让断言永远成立，
    等于没测 —— 所以 bug 没被拦住。
    """

    from pathlib import Path as _Path

    cfg._upsert_env({"A": "1"})
    names = sorted(p.name for p in env_file.parent.iterdir())
    assert ".env.bak" in names, f"没有生成 .env.bak，实际文件: {names}"
    assert ".env.env.bak" not in names, f"生成了错名字的备份 .env.env.bak: {names}"

    # 备份内容应与写入前的 .env 一致（确认确实备份到了那个时刻）
    backup_text = (_Path(env_file.parent) / ".env.bak").read_text(encoding="utf-8")
    assert "LLM_API_KEY=sk-existing-key-1234567890" in backup_text


def test_gitignore_covers_env_variants() -> None:
    """`.gitignore` 必须挡住 .env 的全部变体（含 .bak / .tmp），但放行示例文件。

    这条是"事故复盘"型测试：光写 `.env` 一条规则是不够的。
    """

    import subprocess

    repo = Path(__file__).resolve().parent.parent
    gitignore = repo / ".gitignore"
    if not gitignore.exists():  # pragma: no cover - 正常仓库都有
        pytest.skip("无 .gitignore")

    def ignored(rel: str) -> bool:
        r = subprocess.run(
            ["git", "check-ignore", rel],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return r.returncode == 0

    for dangerous in (".env", ".env.bak", ".env.env.bak", ".env.tmp", ".env.local"):
        assert ignored(dangerous), f"{dangerous} 未被忽略，可能被误提交（含密钥）"

    for allowed in (".env.example", "web/.env.example"):
        assert not ignored(allowed), f"{allowed} 被忽略了，示例文件应当入库"


def test_read_config_marks_dsn_as_requires_restart(monkeypatch, env_file: Path) -> None:
    """建连接时用掉的配置必须如实标注不可热改。"""

    body = cfg.read_config()
    dsn = body["runtime"]["postgres_dsn"]
    assert dsn["requires_restart"] is True
    assert dsn["editable"] is False
    assert dsn["restart_reason"]

    redis = body["runtime"]["redis_url"]
    assert redis["requires_restart"] is True

    key = body["llm"]["llm_api_key"]
    assert key["secret"] is True
    # 绝不能把明文放进 value
    assert key.get("value") is None
    assert "configured" in key and "preview" in key


def test_read_config_does_not_leak_key_value(env_file: Path, monkeypatch) -> None:
    """把 settings 换成带真实密钥的对象，确认响应体里不含明文。"""

    class FakeSettings:
        llm_provider = "deepseek"
        llm_flash_model = "deepseek-flash"
        llm_pro_model = "deepseek-v4-pro"
        llm_base_url = "https://api.deepseek.com"
        llm_local_enabled = False
        llm_local_base_url = "http://localhost:11434"
        llm_local_model = "qwen2.5:7b-instruct"
        llm_thinking_deep = False
        llm_cache_enabled = True
        llm_api_key = "sk-fake0123456789abcdefghijklmnopqrst"
        cost_daily_budget_cny = 20.0
        cost_warn_ratio = 0.8
        cost_tracker_path = "./data/cost.jsonl"
        app_env = "dev"
        demo_mode = False
        postgres_dsn = "postgresql+psycopg://intel:secretpw@localhost:5432/intel"
        redis_url = ""
        embedding_dim = 1024

    monkeypatch.setattr(cfg, "get_settings", lambda: FakeSettings())
    body = cfg.read_config()
    import json

    dumped = json.dumps(body, ensure_ascii=False, default=str)
    assert "sk-fake0123456789abcdefghijklmnopqrst" not in dumped, "明文密钥泄漏到响应里"
    assert "secretpw" not in dumped, "DSN 里的密码泄漏到响应里"
    # 但脱敏预览要在
    assert "sk-71a7" in dumped
