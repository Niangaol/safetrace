"""配置管理：读取 / 修改运行配置，并测试 LLM 连通性。

**为什么能做"不重启就生效"**：`config.get_settings()` 是 `@lru_cache(maxsize=1)`，
而 `Settings.model_config` 指定了 `env_file=".env"`。所以只要
①把改动写进 `.env`、②`get_settings.cache_clear()`，
下一次请求就会重新读文件 —— 全进程生效，不需要重启服务。

**三条安全/诚实约束**：

1. **密钥永不回传**。读接口只返回 `api_key_configured` 与 `api_key_preview`
   （形如 `sk-71a7****5ac9`，够确认"是不是那把"但不泄漏）。不提供任何"读出密钥"的接口。
2. **写入必须原子**：先写临时文件再 `os.replace`，并在写入前备份 `.env`。
   半截文件会让整个服务起不来（`.env` 是启动依赖）。
3. **改不了的字段要说清楚**：`POSTGRES_DSN` / `REDIS_URL` 这类"建连接时用掉"的配置
   改了**不会**热生效（引擎与连接池已按旧值建好），所以标为 `requires_restart`，
   不允许在这个界面里假装能改。
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from aiintel.api.deps import Auth
from aiintel.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/config", tags=["config"])

#: `.env` 位置（相对进程工作目录，与 `Settings.model_config` 的 `env_file` 一致）
ENV_PATH = Path(".env")

#: 允许在界面里修改的字段 → 环境变量名。
#: **故意不含** POSTGRES_DSN / REDIS_URL / EMBEDDING_*：它们在建引擎/连接池时就用掉了，
#: 热改不会生效，放进界面等于骗人（见模块 docstring 第 3 条）。
EDITABLE: dict[str, str] = {
    "llm_provider": "LLM_PROVIDER",
    "llm_flash_model": "LLM_FLASH_MODEL",
    "llm_pro_model": "LLM_PRO_MODEL",
    "llm_api_key": "LLM_API_KEY",
    "llm_base_url": "LLM_BASE_URL",
    "llm_local_enabled": "LLM_LOCAL_ENABLED",
    "llm_local_base_url": "LLM_LOCAL_BASE_URL",
    "llm_local_model": "LLM_LOCAL_MODEL",
    "llm_thinking_deep": "LLM_THINKING_DEEP",
    "llm_cache_enabled": "LLM_CACHE_ENABLED",
    "cost_daily_budget_cny": "COST_DAILY_BUDGET_CNY",
    "cost_warn_ratio": "COST_WARN_RATIO",
    "demo_mode": "DEMO_MODE",
}

#: 这些字段即使在界面上改了也要重启才生效，如实标注
REQUIRES_RESTART: dict[str, str] = {
    "postgres_dsn": "数据库引擎与连接池已按旧值建立，热改不生效",
    "redis_url": "事件总线客户端已按旧值建立，热改不生效",
    "embedding_dim": "向量列宽度由建表时决定，改动需要重建表",
    "embedding_backend": "嵌入模型在首次使用时加载，热改不生效",
}

#: 密钥只回传"是否已配置 + 脱敏预览"，绝不回传明文
SECRET_FIELDS = {"llm_api_key", "github_token", "github_webhook_secret", "api_token"}


def _mask(value: str) -> str:
    """脱敏：保留首尾各若干字符，中间打星。太短则整体打星。"""

    value = (value or "").strip()
    if not value:
        return ""
    if len(value) <= 12:
        return "*" * len(value)
    return f"{value[:7]}****{value[-4:]}"


def _read_env_file() -> dict[str, str]:
    """读 `.env` 的键值（保留注释不动，这里只做读取）。"""

    if not ENV_PATH.exists():
        return {}
    out: dict[str, str] = {}
    for raw in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip()
    return out


def _upsert_env(updates: dict[str, str]) -> None:
    """把键值写回 `.env`：已存在的键就地替换，新键追加到末尾。

    原子写入 + 先备份。**为什么必须原子**：`.env` 是启动依赖，
    写到一半（进程被杀）会留下半截文件，服务下次直接起不来。
    """

    if ENV_PATH.exists():
        # ⚠️ **不能用 `with_suffix(".env.bak")`**：`.env` 会被 Path 解析成
        # "无 stem + 后缀 .env"，结果变成 **`.env.env.bak`** —— 一个
        # **不被 `.gitignore` 的 `.env` 规则覆盖**的新文件，里面同样有真实密钥。
        # 实测踩过：含密钥的备份被误提交并推送。用字符串拼接更可靠。
        backup = ENV_PATH.parent / (ENV_PATH.name + ".bak")
        shutil.copy2(ENV_PATH, backup)

    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    remaining = dict(updates)
    out: list[str] = []
    for raw in lines:
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.partition("=")[0].strip()
            if key in remaining:
                out.append(f"{key}={remaining.pop(key)}")
                continue
        out.append(raw)
    for key, val in remaining.items():
        out.append(f"{key}={val}")

    # 同样别用 with_suffix：会得到 `.env.env.tmp`（不影响正确性，但要多忽略一类文件名）
    tmp = ENV_PATH.parent / (ENV_PATH.name + ".tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.replace(tmp, ENV_PATH)


def _coerce(value: Any) -> str:
    """环境变量只能存字符串；布尔统一成 true/false（pydantic 能解析）。"""

    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class ConfigUpdate(BaseModel):
    """只要传要改的字段；未传的保持原值。"""

    llm_provider: str | None = None
    llm_flash_model: str | None = None
    llm_pro_model: str | None = None
    llm_api_key: str | None = None
    llm_base_url: str | None = None
    llm_local_enabled: bool | None = None
    llm_local_base_url: str | None = None
    llm_local_model: str | None = None
    llm_thinking_deep: bool | None = None
    llm_cache_enabled: bool | None = None
    cost_daily_budget_cny: float | None = Field(default=None, gt=0)
    cost_warn_ratio: float | None = Field(default=None, gt=0, le=1)
    demo_mode: bool | None = None


@router.get("", dependencies=[Auth])
def read_config() -> dict[str, Any]:
    """当前生效配置。**密钥永不明文返回**。"""

    s = get_settings()
    env_file = _read_env_file()

    def field(name: str, value: Any, *, source: str = "default") -> dict[str, Any]:
        return {
            "value": value,
            "source": source,
            "env_var": EDITABLE.get(name, ""),
            "editable": name in EDITABLE,
            "requires_restart": name in REQUIRES_RESTART,
        }

    llm = {
        "llm_provider": field("llm_provider", s.llm_provider),
        "llm_flash_model": field("llm_flash_model", s.llm_flash_model),
        "llm_pro_model": field("llm_pro_model", s.llm_pro_model),
        "llm_base_url": field("llm_base_url", s.llm_base_url),
        "llm_local_enabled": field("llm_local_enabled", s.llm_local_enabled),
        "llm_local_base_url": field("llm_local_base_url", s.llm_local_base_url),
        "llm_local_model": field("llm_local_model", s.llm_local_model),
        "llm_thinking_deep": field("llm_thinking_deep", s.llm_thinking_deep),
        "llm_cache_enabled": field("llm_cache_enabled", s.llm_cache_enabled),
        # 密钥：只给"配没配"和脱敏预览
        "llm_api_key": {
            "value": None,
            "configured": bool((s.llm_api_key or "").strip()),
            "preview": _mask(s.llm_api_key),
            "env_var": "LLM_API_KEY",
            "editable": True,
            "requires_restart": False,
            "secret": True,
        },
    }
    cost = {
        "cost_daily_budget_cny": field("cost_daily_budget_cny", s.cost_daily_budget_cny),
        "cost_warn_ratio": field("cost_warn_ratio", s.cost_warn_ratio),
        "cost_tracker_path": field("cost_tracker_path", s.cost_tracker_path),
    }
    runtime = {
        "app_env": field("app_env", s.app_env),
        "demo_mode": field("demo_mode", s.demo_mode),
        "postgres_dsn": {
            **_dsn_view(s.postgres_dsn),
            "env_var": "POSTGRES_DSN",
            "editable": False,
            "requires_restart": True,
            "restart_reason": REQUIRES_RESTART["postgres_dsn"],
        },
        "redis_url": {
            "value": s.redis_url or "（空 → 事件总线禁用，走内存降级）",
            "env_var": "REDIS_URL",
            "editable": False,
            "requires_restart": True,
            "restart_reason": REQUIRES_RESTART["redis_url"],
        },
    }
    return {
        "llm": llm,
        "cost": cost,
        "runtime": runtime,
        "env_file": str(ENV_PATH.resolve()),
        "env_file_exists": ENV_PATH.exists(),
        "env_keys_present": sorted(env_file.keys())[:40],
        "note": (
            "修改会写入 .env 并立即生效（get_settings 有 lru_cache，写入后清缓存）。"
            "POSTGRES_DSN / REDIS_URL 等建连接时用掉的配置不可热改，标了 requires_restart。"
        ),
    }


def _dsn_view(dsn: str) -> dict[str, Any]:
    """DSN 里可能带密码，回传时脱敏，只显示 host/db。"""

    from sqlalchemy.engine import make_url

    try:
        url = make_url(dsn)
    except Exception:  # noqa: BLE001
        return {"value": "（无法解析）"}
    return {
        "value": f"{url.drivername}://{url.username or '-'}@{url.host or '-'}:{url.port or '-'}/{url.database or '-'}",
        "driver": url.drivername,
        "host": url.host,
        "database": url.database,
    }


@router.put("", dependencies=[Auth])
def update_config(payload: ConfigUpdate) -> dict[str, Any]:
    """写入 `.env` 并清缓存，返回改动后的**脱敏**视图。"""

    updates: dict[str, str] = {}
    for name in EDITABLE:
        value = getattr(payload, name, None)
        if value is None:
            continue
        # 密钥传空字符串 = 明确要求清空；传 None = 不动（None 已被上面过滤）
        updates[EDITABLE[name]] = _coerce(value)

    if not updates:
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "NO_CHANGES", "message": "没有可更新的字段"}},
        )

    # 基本校验：模型名不能带空格、base_url 必须是 http(s)
    if "LLM_BASE_URL" in updates and not updates["LLM_BASE_URL"].startswith(
        ("http://", "https://")
    ):
        raise HTTPException(
            status_code=422,
            detail={
                "error": {
                    "code": "BAD_URL",
                    "message": "LLM_BASE_URL 必须以 http:// 或 https:// 开头",
                }
            },
        )
    for key in ("LLM_FLASH_MODEL", "LLM_PRO_MODEL"):
        if key in updates and (" " in updates[key].strip() or not updates[key].strip()):
            raise HTTPException(
                status_code=422,
                detail={"error": {"code": "BAD_MODEL", "message": f"{key} 不能为空或含空格"}},
            )

    try:
        _upsert_env(updates)
    except OSError as exc:
        logger.exception("写 .env 失败")
        raise HTTPException(
            status_code=500,
            detail={"error": {"code": "ENV_WRITE_FAILED", "message": f"写 .env 失败: {exc}"}},
        ) from exc

    # 清缓存 → 下一次 get_settings() 重新读 .env，**全进程立即生效**
    get_settings.cache_clear()

    s = get_settings()
    return {
        "updated": sorted(updates.keys()),
        "effective_now": True,
        "llm_api_key_configured": bool((s.llm_api_key or "").strip()),
        "llm_api_key_preview": _mask(s.llm_api_key),
        "llm_flash_model": s.llm_flash_model,
        "llm_pro_model": s.llm_pro_model,
        "llm_base_url": s.llm_base_url,
        "demo_mode": s.demo_mode,
        "note": "已写入 .env 并清除设置缓存；无需重启。",
    }


@router.post("/test-llm", dependencies=[Auth])
async def test_llm() -> dict[str, Any]:
    """用**当前**配置真打一次模型，用于确认"配好了没有"。

    只发一个极短请求，如实返回模型名 / 耗时 / 花费 / 失败原因；
    **不回传密钥**。
    """

    s = get_settings()
    if not (s.llm_api_key or "").strip():
        return {
            "ok": False,
            "reason": "未配置 LLM_API_KEY（当前走 DEMO_MODE 占位或本地兜底）",
            "api_key_configured": False,
        }

    from aiintel.core.llm import get_llm

    started = time.perf_counter()
    try:
        result = await get_llm().complete(
            [{"role": "user", "content": "只回复两个字：收到"}],
            task="classify",
            # 同 qa.plan 的教训：本仓模型强制输出思维链，max_tokens 给小了正文会是空串
            max_tokens=2000,
            node="config.test",
            agent="ConfigAgent",
        )
    except Exception as exc:  # noqa: BLE001 - 要把失败原因如实带回前端
        return {
            "ok": False,
            "reason": f"{type(exc).__name__}: {str(exc)[:220]}",
            "api_key_configured": True,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
        }

    return {
        "ok": bool(result.text.strip()),
        "api_key_configured": True,
        "model": result.model,
        "reply": (result.text or "").strip()[:80],
        "elapsed_ms": int((time.perf_counter() - started) * 1000),
        "cost_cny": result.cost_cny,
        "reasoning_tokens": result.reasoning_tokens,
        "truncated": result.truncated,
        "reason": ""
        if result.text.strip()
        else "模型返回空正文（可能是 max_tokens 太小被思维链吃满）",
        "base_url": s.llm_base_url,
    }
