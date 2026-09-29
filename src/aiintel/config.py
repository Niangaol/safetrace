"""全局配置：所有可调项集中在 .env，便于容器化与成本治理。"""

from __future__ import annotations

from functools import lru_cache
from zoneinfo import ZoneInfo

from pydantic_settings import BaseSettings, SettingsConfigDict

BEIJING_TZ = ZoneInfo("Asia/Shanghai")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "dev"
    log_level: str = "INFO"
    api_token: str = "dev-token"

    postgres_dsn: str = "postgresql+psycopg://intel:intel@localhost:5432/intel"
    redis_url: str = "redis://localhost:6379/0"
    # Redis 是可选依赖。没设超时时 redis-py 要 4s 才放弃连接，
    # 一轮富化发 ~11 条事件 = 白等 44s，所以必须显式给短超时。
    redis_socket_timeout_seconds: float = 0.5
    embedding_dim: int = 1024

    # ---- LLM 路由 ----
    llm_provider: str = "deepseek"
    # 模型 ID **必须**用服务端真实存在的名字。2026-09-29 实测
    # `GET https://api.deepseek.com/models` 返回的 id 是 `deepseek-flash` 与 `deepseek-v4-pro`；
    # 原先这里写 `deepseek-v4-flash`（不存在的 ID），一旦配好 key 走 flash 档就会被 400 顶回来。
    llm_flash_model: str = "deepseek-flash"
    llm_pro_model: str = "deepseek-v4-pro"
    llm_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com"

    llm_local_enabled: bool = True
    llm_local_base_url: str = "http://localhost:11434"
    llm_local_model: str = "qwen2.5:7b-instruct"

    # 思考模式：抽取/分类类任务必须为 False（思考 token 按输出计费，会放大 2~3 倍成本）
    llm_thinking_deep: bool = False
    # 前缀缓存：固定 system prompt 放最前，命中价约为未命中的 1/30
    llm_cache_enabled: bool = True

    cost_daily_budget_cny: float = 20.0
    cost_warn_ratio: float = 0.8
    cost_tracker_path: str = "./data/cost.jsonl"

    embedding_backend: str = "local"
    embedding_model: str = "BAAI/bge-m3"
    reranker_model: str = "BAAI/bge-reranker-v2-m3"

    alert_webhook_url: str = ""

    collect_user_agent: str = "ai-threat-intel/0.1 (coursework)"
    collect_interval_minutes: int = 30
    collect_full_sync_weekday: int = 0

    # ---- 外部 webhook / 第三方 API ----
    github_webhook_secret: str = ""
    github_token: str = ""

    # ---- 富化线（F 线）----
    # 论文检索源：arxiv 始终可用；openalex 作为第二源（真实第二源，非 Mock）
    enrich_paper_sources: str = "arxiv,openalex"
    enrich_openalex_enabled: bool = True
    enrich_http_timeout_seconds: float = 8.0
    # F5 修复建议的补丁文档抓取开关（关掉则只用 IntelItem.references 里的元数据）
    enrich_patch_fetch_enabled: bool = False
    # F2 受影响资产：主动测绘默认关闭（合规红线）。开启需显式配置并在报告标注。
    asset_scan_enabled: bool = False
    # 资产画像数据文件（Mock 来源），不存在则 exposed_assets 恒为空
    asset_inventory_path: str = "./data/assets.sample.json"
    # F6 一致性校验的仲裁优先级与数值容差
    enrich_source_priority: str = "nvd,vendor,ghsa,osv,community_rss"
    enrich_cvss_tolerance: float = 0.1
    # 冲突 badcase 归档目录（F6 产出，答辩素材）
    enrich_badcase_dir: str = "./data/badcase"
    # 质量闸门消费阈值（Y 线 DQ1 打分，见 docs/富化线详细设计.md §5.3）
    # 注意：这两个阈值同时是 DQ1 的 review / degrade 判定线（见 services/dq1.py），
    # 保留原名以免破坏既有测试与运维认知。
    enrich_min_quality_full: float = 0.7
    enrich_min_quality_partial: float = 0.4
    # ---- DQ1 数据质量闸门（脏数据不进知识底座）----
    dq1_enabled: bool = True
    dq1_gate_version: str = "1.0.0"
    # ---- 动态优先级（Y5 派单）：EPSS / KEV / CVSS 加权排序 ----
    # 权重与分档随 policy_version 版本化（见 services/triage.py），换权重必须换版本号
    triage_policy_version: str = "1.0.0"
    # 派单 Top-N：队首 N 条走详细富化（F5 给版本号/补丁链接），其余走通用模板
    triage_detail_top_n: int = 10

    # ---- 三线接口桩（S1 知识底座 / S2 事件总线 / MG1 模型网关）----
    # 桩模式：不真连外部服务，只保证边界与契约；默认关闭，避免掩盖"服务没配好"
    s1_stub_mode: bool = True
    mg1_stub_mode: bool = False

    # 演示模式：无 LLM 凭据且本地模型不可达时返回占位回答，用于离线验证 UI 与 SSE 链路。
    # 仅供 python -m scripts.demo 使用，生产必须保持 False——它会掩盖"模型没配好"这个事实。
    demo_mode: bool = False


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
