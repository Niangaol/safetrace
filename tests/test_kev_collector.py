"""CISA KEV 官方目录采集器单测。

**不访问外网**：用内置快照走解析逻辑。真实网络可达性在接入时手工验过
（CISA 目录 HTTP 200，catalogVersion 2026.09.x），但 CI 与离线环境不能依赖它。

覆盖三件事：
1. 条目解析：`dueDate` / ransomware / requiredAction 落到 raw 里；
2. 增量水位：只放行"新入 KEV"的条目，否则全量快照会重复灌 1700+ 条；
3. 脏数据容错：非 CVE ID、异常日期都不能让整个源失败。
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from aiintel.services.collectors.kev import FEED, KevCollector

#: 真实目录的单条结构（2026-09-27 快照，字段名与顺序对齐 CISA 实际输出）
SNAPSHOT: dict = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.09.27",
    "dateReleased": "2026-09-27T21:30:35.5521Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-88772",
            "vendorProject": "Citrix",
            "product": "NetScaler",
            "vulnerabilityName": "Citrix NetScaler Improper Restriction of Operations",
            "dateAdded": "2026-09-27",
            "shortDescription": "NetScaler ADC contains an improper restriction of operations.",
            "requiredAction": "Apply mitigations in accordance with vendor instructions.",
            "dueDate": "2026-09-30",
            "knownRansomwareCampaignUse": "Unknown",
            "forensicTriage": "Yes",
            "notes": "Running the provided IOCs may help identify affected systems.",
            "cwes": ["CWE-119"],
        },
        {
            "cveID": "CVE-2026-10001",
            "vendorProject": "Acme AI",
            "product": "LLM Gateway",
            "vulnerabilityName": "Acme LLM Gateway Prompt Injection",
            "dateAdded": "2026-09-20",
            "shortDescription": "Improper input validation allows prompt injection.",
            "requiredAction": "Upgrade to 2.4.1 or later.",
            "dueDate": "2026-10-15",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-77", "CWE-20"],
        },
    ],
}


class _StubCollector(KevCollector):
    """覆写网络调用，喂快照；同时让 watermark 可注入。"""

    def __init__(self, payload: dict, since: dt.datetime | None = None) -> None:
        # 不调 super().__init__()：那会真的建 httpx 连接
        self.settings = None
        self._client = None
        self._payload = payload
        self._since = since

    def watermark(self) -> dt.datetime | None:
        return self._since

    async def _get_json(self, url: str, **kwargs) -> dict:
        assert url == FEED, f"必须直连 CISA 官方目录，实际 {url}"
        return self._payload


async def test_parses_due_date_and_required_action():
    collector = _StubCollector(SNAPSHOT)
    items = await collector.fetch("full")
    assert len(items) == 2

    kev_by_id = {item.external_id: item for item in items}
    citrix = kev_by_id["CVE-2026-88772"]
    assert citrix.raw["kev_due_date"] == "2026-09-30"
    assert citrix.raw["kev_ransomware"] is None  # Unknown 不当成 known
    assert citrix.raw["kev_forensic_triage"] == "Yes"
    assert citrix.raw["kev_cwes"] == ["CWE-119"]
    # requiredAction 是唯一含"具体怎么做"的字段，不能丢
    assert "Apply mitigations" in citrix.content_text
    assert citrix.published_at is not None


async def test_ransomware_known_is_captured():
    items = await _StubCollector(SNAPSHOT).fetch("full")
    acme = next(i for i in items if i.external_id == "CVE-2026-10001")
    assert acme.raw["kev_ransomware"] == "known"
    assert acme.raw["kev_due_date"] == "2026-10-15"
    # 后续去重要保留更早的截止日，所以越早越紧急的信息一定在
    assert acme.raw["kev_date_added"] == "2026-09-20"


async def test_incremental_filters_by_watermark():
    """全量快照下若不做水位过滤，每次轮询都会重复灌 1700+ 条。"""

    # 水位设在两条 dateAdded 之后 → 两条都应被过滤
    collector = _StubCollector(SNAPSHOT, since=dt.datetime(2026, 9, 28, tzinfo=dt.UTC))
    assert await collector.fetch("incremental") == []

    # 水位在两条之间 → 只放行较新的一条
    collector = _StubCollector(SNAPSHOT, since=dt.datetime(2026, 9, 25, tzinfo=dt.UTC))
    kept = await collector.fetch("incremental")
    assert [i.external_id for i in kept] == ["CVE-2026-88772"]


async def test_dirty_entries_do_not_break_the_source():
    payload = {
        "catalogVersion": "2026.09.27",
        "vulnerabilities": [
            {"cveID": "NOT-A-CVE", "vulnerabilityName": "脏数据"},
            {"cveID": "", "vulnerabilityName": "空 ID"},
            {"cveID": "CVE-2026-20000", "vulnerabilityName": "正常条目", "dateAdded": "2026-09-27"},
        ],
    }
    items = await _StubCollector(payload).fetch("full")
    assert [i.external_id for i in items] == ["CVE-2026-20000"]


async def test_missing_due_date_stays_none():
    """缺 dueDate 必须是 None（未知），不能糊成宽松值。"""

    payload = {
        "catalogVersion": "2026.09.27",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-30000",
                "vulnerabilityName": "无 dueDate 的条目",
                "dateAdded": "2026-09-27",
            }
        ],
    }
    items = await _StubCollector(payload).fetch("full")
    assert items[0].raw["kev_due_date"] is None


async def test_real_feed_payload_shape_is_accepted():
    """守住"我们认的字段名"与 CISA 实际输出一致。

    这里的快照是真实目录的顶层与条目字段名。字段改名时应让本测试失败。
    """

    items = await _StubCollector(json.loads(json.dumps(SNAPSHOT))).fetch("full")
    assert {i.source for i in items} == {"kev"}
    # external_id 必须是 CVE ID，这样 KEV 与 NVD/GHSA 归一到同一条 Vuln
    assert all(i.external_id.startswith("CVE-") for i in items)
    # 确定性事件 ID：同 (source, external_id) 重复抓取得同一 id，天然幂等
    assert len({i.id for i in items}) == 2
    assert items[0].id == items[0].to_dict()["id"]


@pytest.mark.parametrize("bad", [None, "", "   ", "not-a-date", 12345])
def test_due_date_normalization_rejects_garbage(bad):
    from aiintel.services.ingest.pipeline import _normalize_due_date

    assert _normalize_due_date(bad) is None


def test_due_date_normalization_accepts_iso_and_timestamps():
    from aiintel.services.ingest.pipeline import _normalize_due_date

    assert _normalize_due_date("2026-09-30") == "2026-09-30"
    assert _normalize_due_date("2026-09-30T21:30:35Z") == "2026-09-30"
