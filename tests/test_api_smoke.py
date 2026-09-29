"""API 契约冒烟测试：OpenSchema、鉴权、健康检查、路由参数。

用 SQLite 顶替 PostgreSQL（只覆盖不依赖 pgvector 列的表），
目的是让接口层错误在 CI 里就能暴露，而不是等到演示当天。
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from aiintel.api import deps, main
from aiintel.api.main import CORS_ORIGINS, app
from aiintel.db.base import Base

API = "/api/v1"


@pytest.fixture(scope="module")
def api_sessionmaker():
    """测试用内存库的 sessionmaker。

    单独抽出来是为了让用例能**往同一个库插数据**再走接口断言
    （`client` 那个 override 会开新 session，直接用它拿不到写入结果）。
    """

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # chunk 的 embedding 是 pgvector 列，SQLite 建不出来；这里只补一张同名的空表，
    # 让 count(*) 之类的查询能跑通，验证的是接口契约而不是 pgvector 本身
    Base.metadata.create_all(
        engine,
        tables=[t for name, t in Base.metadata.tables.items() if name != "chunk"],
    )
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE chunk (id TEXT PRIMARY KEY)"))
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture(scope="module")
def client(api_sessionmaker):
    def _override() -> object:
        with api_sessionmaker() as session:
            yield session

    # 不进 lifespan 上下文：真实启动会连 Redis/LLM，冒烟测试只关心路由与契约
    app.dependency_overrides[deps.db_session] = _override
    c = TestClient(app)
    yield c
    c.close()
    app.dependency_overrides.clear()


def test_openapi_generates(client):
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    # 契约要求的关键端点必须都在
    for path in (
        f"{API}/collect/sync",
        f"{API}/collect/hook/ghsa",
        f"{API}/collect/status",
        f"{API}/vulns",
        f"{API}/vulns/{{vuln_id}}",
        f"{API}/vulns/{{vuln_id}}/evidence",
        f"{API}/enrich/backfill",
        f"{API}/qa/chat",
        f"{API}/metrics/overview",
        f"{API}/alerts",
        f"{API}/reports/daily",
    ):
        assert path in paths, f"OpenAPI 缺少 {path}"


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_system_health_reports_llm_and_cost(client):
    body = client.get(f"{API}/system/health").json()
    assert body["status"] == "ok"
    assert "flash_model" in body["llm"]
    assert "daily_budget_cny" in body["cost"]


def test_vuln_list_contract(client):
    body = client.get(f"{API}/vulns", params={"page": 1, "page_size": 5}).json()
    assert set(body) >= {"items", "total", "page", "page_size"}
    assert body["page"] == 1


def test_vuln_list_rejects_bad_sort(client):
    assert client.get(f"{API}/vulns", params={"sort": "drop table"}).status_code == 422


def test_vuln_list_exposes_triage_signals(client, api_sessionmaker):
    """EPSS / KEV 必须外发。

    动态优先级（`services/triage.py`）就是按 KEV + EPSS + CVSS 加权的，
    但这两个字段此前**只落库、不外发**，前端因此看不到"为什么这条排前面"——
    排序依据不可见，等于白算。这条断言钉住接口侧不再回退。
    """

    from aiintel.db.models import Vuln

    with api_sessionmaker() as session:
        session.add_all(
            [
                Vuln(
                    id="v_with_signals",
                    cve_id="CVE-2026-90001",
                    title="有 KEV/EPSS 的条目",
                    severity="critical",
                    cvss_score=9.8,
                    epss=0.87,
                    kev=True,
                    kev_due_date="2026-10-15",
                ),
                Vuln(
                    id="v_without_signals",
                    cve_id="CVE-2026-90002",
                    title="没有 EPSS 的条目",
                    severity="high",
                    cvss_score=7.5,
                ),
            ]
        )
        session.commit()

    body = client.get(f"{API}/vulns", params={"page_size": 10}).json()
    assert body["items"], "刚插入两条，不应为空"
    by_id = {i["cve_id"]: i for i in body["items"]}
    assert "CVE-2026-90001" in by_id, "接口没返回刚写入的数据"
    item = by_id["CVE-2026-90001"]
    assert item["epss"] == 0.87
    assert item["kev"] is True, "kev 必须是真 bool"
    assert item["kev_due_date"] == "2026-10-15"
    plain = by_id["CVE-2026-90002"]
    assert plain["kev"] is False, "未列入 KEV 时必须是 False，不能是 None"


def test_vuln_list_accepts_triage_sorts(client):
    """新增的 sort 取值要真的被接受（此前只允许 published_at/cvss_score/fetched_at）。"""

    for key in ("epss", "kev"):
        res = client.get(f"{API}/vulns", params={"sort": key, "page_size": 5})
        assert res.status_code == 200, f"sort={key} 被拒: {res.status_code}"
        assert "items" in res.json()


def test_epss_sort_puts_known_values_first(client, api_sessionmaker):
    """按 EPSS 降序时，有值的条目必须排在无值（NULL）的条目前面。

    SQLite 里 NULL 在 DESC 下的位置与 PG 不同，所以实现用了
    `coalesce(epss, -1.0)`；这条断言防止有人把它改回裸 `order_by(desc())`。
    """

    items = client.get(f"{API}/vulns", params={"sort": "epss", "page_size": 100}).json()["items"]
    values = [i["epss"] for i in items]
    known = [v for v in values if v is not None]
    if not known:
        pytest.skip("测试库没有 EPSS 数据，无法验证排序")
    assert values[: len(known)] == known, f"NULL 没有排到最后: {values}"
    assert known == sorted(known, reverse=True), f"EPSS 未按降序: {known}"


def test_collect_status_contract(client):
    body = client.get(f"{API}/collect/status").json()
    assert "watermarks" in body
    assert "queue_depth" in body


def test_metrics_overview_contract(client):
    body = client.get(f"{API}/metrics/overview").json()
    for key in ("collect", "latency", "enrich", "knowledge", "agents", "cost"):
        assert key in body, f"metrics/overview 缺少 {key}"


def test_missing_vuln_returns_404(client):
    res = client.get(f"{API}/vulns/v_does_not_exist")
    assert res.status_code == 404
    assert res.json()["detail"]["error"]["code"] == "VULN_NOT_FOUND"


def test_chat_requires_question(client):
    assert client.post(f"{API}/qa/chat", json={"question": "x"}).status_code == 422


def test_cors_allows_frontend_origins(client):
    """前端用本机 IP/机器名打开时也要能用：只放行本机来源。"""

    for origin in CORS_ORIGINS:
        res = client.get(f"{API}/system/health", headers={"Origin": origin})
        assert res.headers.get("access-control-allow-origin") == origin, origin


def test_cors_blocks_foreign_origin(client):
    """别把 CORS 放开成通配符，否则任何站点都能读接口。"""

    for origin in ("http://evil.example.com", "https://evil.example.com"):
        res = client.get(f"{API}/system/health", headers={"Origin": origin})
        assert "access-control-allow-origin" not in res.headers, origin


def test_cors_origins_are_local_only():
    """放行清单只应包含本机标识，不能混进公网/任意域名。"""

    local_names = {"localhost", "127.0.0.1", "::1", socket.gethostname().lower()}
    for host in (urlparse(o).hostname or "" for o in CORS_ORIGINS):
        assert host.lower() in local_names or _is_private_ipv4(host), (
            f"CORS 不应放行非本机地址: {host}"
        )


def test_local_hosts_survive_broken_ipconfig(monkeypatch):
    """ipconfig 不可用/输出乱码时只应缩小放行范围，不能让 app 导入崩掉。

    中文 Windows 的 ipconfig 是 GBK 输出；曾经用 text=True 解码，
    在 PYTHONUTF8=1 下会在子线程里炸掉、stdout 变 None。
    """

    def _boom(*_a, **_k):
        raise OSError("no ipconfig here")

    monkeypatch.setattr(main.subprocess, "run", _boom)
    hosts = main._local_hosts()
    assert "localhost" not in hosts  # 只回机器名，至少有一个
    assert hosts


def test_local_hosts_ignores_garbled_output(monkeypatch):
    class _Proc:
        stdout = "\udcff\udcfe IPv4 Address. : not-an-ip"

    monkeypatch.setattr(
        main.subprocess,
        "run",
        lambda *a, **k: _Proc(),  # noqa: ARG005
    )
    assert main._local_hosts()


def _is_private_ipv4(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False
