"""契约校验：CI 与本地都能跑（计划里的 `scripts/validate_contracts.py` 等价物）。

用法：
    python -m scripts.validate_contracts                    # 校验 fixtures + schema 自洽 + 冻结指纹
    python -m scripts.validate_contracts --dump             # 顺便打印一份样例，便于对齐
    python -m scripts.validate_contracts --regen-manifest   # 重新生成冻结指纹（仅在有意换版时用）

判据：退出码 0 = 全绿。纳入 `scripts/accept.py` 的静态门禁。

**冻结件保护**（P0-B）：
8 个权威 Schema 的 sha256 指纹随仓入库（`contracts/schemas/FROZEN_MANIFEST.json`），
校验时**不依赖任何外部路径**。上游路径只作为可选交叉核对（`SAFETRACE_CONTRACTS_DIR`）——
以前那种"上游不可达就静默返回 []"等于整套契约保护在别人机器上是假的。
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from scripts.contracts import SCHEMA_DIR, load_schema, validate

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures"
MANIFEST_PATH = SCHEMA_DIR / "FROZEN_MANIFEST.json"

# SafeTrace 权威冻结集（contracts/schemas/CHANGELOG.md v1.0.0，2026-09-28 冻结）。
# 这 8 个 Schema 逐字引入，禁止本仓修改；README/ROADMAP 中「7 个 JSON Schema」的说法有误，实际为 8 个。
AUTHORITATIVE_SCHEMAS = (
    "RawDoc.json",
    "IntelItem.json",
    "EnrichmentResult.json",
    "DecisionRequest.json",
    "DecisionReply.json",
    "RetrievalRequest.json",
    "RetrievalResponse.json",
    "ToolRegistration.json",
)

# 本仓自有契约件。
LOCAL_SCHEMAS = (
    "EventEnvelope.json",
    "DimensionEvidence.json",
    "LocalPayloads.json",
)

#: 扩展主题 → 内联载荷契约（`LocalPayloads.json` 的 definitions 键）。
#: 权威 10 主题的 payload 有独立 Schema 文件（见 TOPIC_PAYLOAD_SCHEMA），
#: 其余主题的形状以前只写在 events.md 的散文里，现在改成机器可校验。
LOCAL_PAYLOAD_DEFINITIONS: dict[str, str] = {
    "intel.enrich.requested": "EnrichRequest",
    "intel.alert.raised": "AlertRaised",
    "intel.report.daily": "DailyReport",
    "intel.budget.exceeded": "BudgetExceeded",
    "intel.selfheal.action": "SelfHealAction",
    "enrich.triage": "TriageOrder",
    "dq.verdicts": "QualityVerdict",
    "qa.queries": "QueryTurn",
    "qa.answers": "Answer",
    "fallback.events": "FallbackEvent",
}

#: 权威主题 → 独立 Schema 文件（payload 契约）。
TOPIC_PAYLOAD_SCHEMA: dict[str, str] = {
    "raw.docs": "RawDoc.json",
    "intel.items": "IntelItem.json",
    "enrich.items": "EnrichmentResult.json",
    "enrich.papers": "EnrichmentResult.json",
    "enrich.evidence": "DimensionEvidence.json",
    "decision.replies": "DecisionReply.json",
}


def load_local_payload(topic: str) -> dict | None:
    """取某主题的内联载荷契约（已把 `$ref` 就地解析成独立 Schema）。

    返回 `None` 表示该主题既没有独立 Schema 也没有内联定义 —— 调用方应显式报错，
    而不是"校验不到就当通过"（那正是 P0-A 的教训）。
    """

    definition = LOCAL_PAYLOAD_DEFINITIONS.get(topic)
    if not definition:
        return None
    bundle = load_schema("LocalPayloads.json")
    node = (bundle.get("definitions") or {}).get(definition)
    if node is None:
        raise KeyError(f"LocalPayloads.json 缺少 definition {definition!r}（topic={topic}）")
    resolved: dict = dict(node)
    resolved.setdefault("title", definition)
    return resolved


def payload_schema_for(topic: str) -> dict | None:
    """统一入口：按 topic 取 payload 契约（独立 Schema 优先，其次内联定义）。"""

    name = TOPIC_PAYLOAD_SCHEMA.get(topic)
    if name:
        return load_schema(name)
    return load_local_payload(topic)


# 上游交叉核对的环境变量（可选）。未配置时**只**用仓内指纹，不再静默跳过。
UPSTREAM_ENV = "SAFETRACE_CONTRACTS_DIR"

#: 当前同步到的上游契约版本与引入日期。
#: 换版时必须一起改这里（`write_manifest` 用它写 `source`），否则清单会谎报版本。
#: v1.0.0（2026-09-28）→ v1.1.3（2026-09-30）：上游 C-01/C-02 两处**纯追加**
#: （DecisionReply 增加 `human` 取值；RetrievalResponse.chunk 增加可选
#: `published_at` / `trust`），已用 `scripts/_check_upstream_sync.py` 验证
#: 无删除、无 required 变更。
DEFAULT_CONTRACT_VERSION = "v1.1.3"
DEFAULT_FROZEN_AT = "2026-09-30"

# 指纹文件本身不是 schema，别混进 schema 计数
NON_SCHEMA_FILES = frozenset({"FROZEN_MANIFEST.json"})

# fixture 文件 -> 校验用 schema（None 表示只检查 JSON 可解析）
FIXTURE_SCHEMA: dict[str, str | None] = {
    "rawdoc.sample.json": "RawDoc.json",
    "intelitem.sample.json": "IntelItem.json",
    "enrichment_paper.sample.json": "EnrichmentResult.json",
    "enrichment_cvss.sample.json": "EnrichmentResult.json",
    "enrichment_consistency.sample.json": "EnrichmentResult.json",
    "enrichment_mock.sample.json": "EnrichmentResult.json",
    "decision_reply.sample.json": "DecisionReply.json",
    "retrieval_response.sample.json": "RetrievalResponse.json",
    "evidence_ai_risk.sample.json": "DimensionEvidence.json",
    "evidence_paper.sample.json": "DimensionEvidence.json",
    "eventenvelope.sample.json": "EventEnvelope.json",
    "nvd_cve.sample.json": None,
}


def check_schemas() -> list[str]:
    problems: list[str] = []
    for name in AUTHORITATIVE_SCHEMAS + LOCAL_SCHEMAS:
        try:
            schema = load_schema(name)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            problems.append(f"schema {name} 不可用: {exc}")
            continue
        if schema.get("title") is None or (
            "properties" not in schema and "definitions" not in schema
        ):
            problems.append(f"schema {name} 缺少 title/properties")
    return problems


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest() -> dict:
    """读冻结指纹表。文件缺失/损坏时抛异常，由调用方转成明确问题项。"""

    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def write_manifest(
    version: str = DEFAULT_CONTRACT_VERSION, frozen_at: str = DEFAULT_FROZEN_AT
) -> int:
    """按当前仓内文件重算指纹（有意换版时才用）。

    版本标签**必须显式传入**：早先这两个值是写死的 `v1.0.0` / `2026-09-28`，
    于是上游升到 v1.1.x 后重算指纹，清单里仍写着 v1.0.0 —— 版本与指纹不符，
    等于把"我同步到哪一版"这件事悄悄说错了。
    """

    manifest = {
        "_comment": (
            "SafeTrace 权威冻结契约的字节级指纹（sha256）。8 个 Schema 逐字引入，本仓无权修改；"
            "改一个字节即视为私改冻结件。指纹由 scripts/validate_contracts.py --regen-manifest 生成。"
        ),
        "source": f"SafeTrace 三件套 contracts/schemas（CHANGELOG {version}，{frozen_at} 引入）",
        "frozen_at": frozen_at,
        "schemas": {name: _sha256(SCHEMA_DIR / name) for name in AUTHORITATIVE_SCHEMAS},
    }
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"已写出 {MANIFEST_PATH.name}：{len(manifest['schemas'])} 条指纹（{version}）")
    return 0


def _frozen_problems(schema_dir: Path, manifest: dict) -> list[str]:
    """纯函数：给定 schema 目录与指纹表，返回冻结校验问题列表。

    把逻辑与全局路径分开，测试才能安全地"篡改一份副本"验证保护确实生效。
    """

    problems: list[str] = []
    expected: dict[str, str] = manifest.get("schemas") or {}
    for name in AUTHORITATIVE_SCHEMAS:
        digest = expected.get(name)
        if not digest or digest.startswith("sha256:PLACEHOLDER"):
            problems.append(f"冻结指纹表缺少 {name} 的有效指纹（跑 --regen-manifest 生成）")
            continue
        path = schema_dir / name
        if not path.exists():
            problems.append(f"权威 schema 缺失: {name}")
            continue
        actual = _sha256(path)
        if actual != digest:
            problems.append(
                f"权威 schema 被本仓改动: {name}（冻结契约禁止修改；"
                f"期望 {digest[:23]}…，实际 {actual[:23]}…）"
            )
    return problems


def frozen_problems(schema_dir: Path | None = None, manifest: dict | None = None) -> list[str]:
    """仓内冻结校验（默认走本仓 schema 目录与指纹表）。测试可传入副本。"""

    target_dir = schema_dir or SCHEMA_DIR
    try:
        table = manifest if manifest is not None else load_manifest()
    except (OSError, json.JSONDecodeError) as exc:
        return [f"冻结指纹表不可用（{MANIFEST_PATH}）：{exc}"]
    return _frozen_problems(target_dir, table)


def check_authoritative_frozen() -> list[str]:
    """权威 Schema 必须与**仓内冻结指纹**一致 —— 不依赖外部路径。

    旧实现在上游目录不可达时 `return []`，等于换台机器就没有保护。
    现在指纹随仓入库，任何字节改动都会被拦下；上游目录仅作可选交叉核对。
    """

    return frozen_problems()


def check_upstream_cross_check() -> list[str]:
    """可选的交叉核对：配了 SAFETRACE_CONTRACTS_DIR 时，与 SafeTrace 原件逐字节比对。

    未配置时**不报错也不假装通过** —— 返回值里明确说明"仅用仓内指纹"，
    由 `main()` 打印出来，避免"看起来做了外部核对其实没做"。
    """

    upstream_dir = (os.getenv(UPSTREAM_ENV) or "").strip()
    if not upstream_dir:
        return []
    upstream = Path(upstream_dir)
    if not upstream.is_dir():
        return [
            f"{UPSTREAM_ENV} 指向的目录不存在: {upstream}（"
            "请改正路径或清空该变量；清空时只校验仓内指纹）"
        ]
    problems: list[str] = []
    for name in AUTHORITATIVE_SCHEMAS:
        src = upstream / name
        if not src.exists():
            problems.append(f"上游权威 schema 缺失: {src}")
            continue
        local = SCHEMA_DIR / name
        if local.read_bytes() != src.read_bytes():
            problems.append(f"与上游原件不一致: {name}")
    return problems


def check_payload_coverage() -> list[str]:
    """每个已登记主题都必须有**可解析的 payload 契约**。

    以前只有权威 4 个主题有 Schema，其余形状散落在 events.md 散文里，
    于是"载荷不合契约"能一路绿灯 —— 这条检查堵的就是这个口子。
    """

    from aiintel.core.events import ALL_TOPICS

    problems: list[str] = []
    for topic in ALL_TOPICS:
        try:
            schema = payload_schema_for(topic)
        except (KeyError, FileNotFoundError, json.JSONDecodeError) as exc:
            problems.append(f"主题 {topic} 的 payload 契约不可解析: {exc}")
            continue
        if schema is None:
            problems.append(
                f"主题 {topic} 没有登记 payload 契约（需加进 TOPIC_PAYLOAD_SCHEMA 或 LOCAL_PAYLOAD_DEFINITIONS）"
            )
    return problems


def check_fixtures() -> list[str]:
    problems: list[str] = []
    for name, schema_name in FIXTURE_SCHEMA.items():
        path = FIXTURE_DIR / name
        if not path.exists():
            problems.append(f"fixture 缺失: fixtures/{name}")
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"fixtures/{name} 不是合法 JSON: {exc}")
            continue
        if schema_name:
            for err in validate(load_schema(schema_name), payload):
                problems.append(f"fixtures/{name} 不合契约: {err}")
    return problems


def main() -> int:
    if "--regen-manifest" in sys.argv:
        return write_manifest()

    problems = (
        check_schemas()
        + check_authoritative_frozen()
        + check_upstream_cross_check()
        + check_payload_coverage()
        + check_fixtures()
    )
    if "--dump" in sys.argv:
        sample = FIXTURE_DIR / "enrichment_paper.sample.json"
        if sample.exists():
            print(sample.read_text(encoding="utf-8"))
    if problems:
        print("契约校验未通过：")
        for item in problems:
            print(f"  - {item}")
        return 1
    total = len(FIXTURE_SCHEMA)
    n_schema = len([p for p in SCHEMA_DIR.glob("*.json") if p.name not in NON_SCHEMA_FILES])
    upstream_note = (
        f"；已与上游 {os.getenv(UPSTREAM_ENV)} 交叉核对"
        if (os.getenv(UPSTREAM_ENV) or "").strip()
        else f"（仅仓内指纹；配 {UPSTREAM_ENV} 可加做上游交叉核对）"
    )
    print(
        f"契约校验通过：{n_schema} 个 schema"
        f"（权威 {len(AUTHORITATIVE_SCHEMAS)} + 本仓 {len(LOCAL_SCHEMAS)}），{total} 个 fixture"
        f"，冻结指纹 {len(AUTHORITATIVE_SCHEMAS)}/{len(AUTHORITATIVE_SCHEMAS)}{upstream_note}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
