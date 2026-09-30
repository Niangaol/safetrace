"""NVD 采集器回归测试。

背景：本环境实测 NVD API 对 `lastModStartDate` 的 **epoch 毫秒**格式返回
HTTP 404（空响应），同一窗口换成 ISO8601（`%2B00:00`）则正常。关键字采集用
`keywordSearch` 服务端精筛（每词一请求；NVD 多词并集不可靠，实测返回 0）。
这些用例锁死 URL 形态，防止回退到毫秒时间戳或全窗逐页扫描。
"""

from __future__ import annotations

import datetime as dt
import re
from urllib.parse import unquote

from aiintel.services.collectors.nvd import NvdCollector, _nvd_datetime


def _param(url: str, name: str) -> str:
    return url.split(f"{name}=")[1].split("&")[0]


def test_nvd_datetime_is_iso8601_not_epoch_ms() -> None:
    d = dt.datetime(2026, 6, 2, 0, 0, 0, tzinfo=dt.UTC)
    out = _nvd_datetime(d)
    assert "T" in out and out.endswith("%2B00:00")
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}%2B00:00$", out)
    assert "1780" not in out  # 不会是秒/毫秒时间戳


def test_page_url_has_keywordsearch_window_and_start_index() -> None:
    since = dt.datetime(2026, 6, 2, 0, 0, 0, tzinfo=dt.UTC)
    url = NvdCollector()._page_url("large language model", since, 4000)
    assert "keywordSearch=large%20language%20model" in url
    assert "lastModStartDate=" in url and "lastModEndDate=" in url
    assert "&startIndex=4000" in url and "resultsPerPage=2000" in url
    start = _param(url, "lastModStartDate")
    end = _param(url, "lastModEndDate")
    assert re.search(r"\.\d{3}%2B00:00$", start) and re.search(r"\.\d{3}%2B00:00$", end)


def test_page_url_narrow_to_119_days() -> None:
    c = NvdCollector()
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=200)
    url = c._page_url("ollama", old, 0)
    start = dt.datetime.fromisoformat(unquote(_param(url, "lastModStartDate")))
    assert (dt.datetime.now(dt.UTC) - start) <= dt.timedelta(days=120)


def test_is_ai_related_matches_llm_and_ollama() -> None:
    # NVD API 列表元素是 {"cve": {...}} 包装层，_is_ai_related 必须能解开
    assert NvdCollector._is_ai_related(
        {
            "cve": {
                "id": "CVE-2026-10001",
                "descriptions": [{"lang": "en", "value": "llama.cpp 越界写"}],
                "cwe": [],
            }
        }
    )
    assert NvdCollector._is_ai_related(
        {
            "cve": {
                "id": "CVE-2026-10002",
                "descriptions": [{"lang": "en", "value": "ollama 拒绝服务"}],
                "cwe": [],
            }
        }
    )
    # 直接传内层也兼容（封装前的老调用形态）
    assert NvdCollector._is_ai_related(
        {
            "id": "CVE-2026-10004",
            "descriptions": [{"lang": "en", "value": "vllm 提权"}],
            "cwe": [],
        }
    )
    assert not NvdCollector._is_ai_related(
        {
            "cve": {
                "id": "CVE-2026-10003",
                "descriptions": [{"lang": "en", "value": "postgresql 提权"}],
                "cwe": [],
            }
        }
    )
