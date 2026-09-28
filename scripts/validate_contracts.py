#!/usr/bin/env python3
"""SafeTrace 契约校验器（纯 stdlib，无第三方依赖）。

校验四层：
  1. 每个 schema 自身是合法 JSON 且结构完整（含 draft-07 关键字白名单）
  2. schema 之间无 $id 重复；$id 与文件名一致
  3. fixtures/ 下每个样本文件通过其对应 schema 的实例校验
  4. events.md 主题清单与 schemas/ 文件名映射一致

用法：python scripts/validate_contracts.py
退出码：0 全绿；1 存在失败项。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "contracts" / "schemas"
FIXTURE_DIR = ROOT / "fixtures"
EVENTS_MD = ROOT / "contracts" / "events.md"

# 本校验器支持的 draft-07 关键字白名单（超纲关键字只警告不报错）
SUPPORTED_KEYWORDS = {
    "$schema", "$id", "title", "description", "type", "enum", "const",
    "properties", "required", "additionalProperties", "items", "minItems",
    "maxItems", "minimum", "maximum", "minLength", "maxLength", "pattern",
    "format", "oneOf", "anyOf", "allOf", "not", "uniqueItems", "default",
    "examples", "deprecated",
}

# fixture 文件名 -> schema 名（None 表示该 fixture 无对应 schema，仅做 JSON 合法性检查）
FIXTURE_SCHEMA_MAP = {
    "rawdoc.sample.json": "RawDoc.json",
    "intelitem.sample.json": "IntelItem.json",
    "enrichmentresult.sample.json": "EnrichmentResult.json",
    "decisionrequest.sample.json": "DecisionRequest.json",
    "decisionreply.sample.json": "DecisionReply.json",
    "retrievalrequest.sample.json": "RetrievalRequest.json",
    "retrievalresponse.sample.json": "RetrievalResponse.json",
    "toolregistration.sample.json": "ToolRegistration.json",
    "qualityverdict.sample.json": None,
}


class Validator:
    """JSON Schema draft-07 子集校验器。"""

    def __init__(self) -> None:
        self.errors: list[str] = []

    @staticmethod
    def _fmt(path: str) -> str:
        return path or "$"

    def validate(self, instance, schema: dict, path: str = "") -> None:
        if not isinstance(schema, dict):
            self.errors.append(f"{self._fmt(path)}: schema 不是对象")
            return

        # 类型检查
        if "type" in schema:
            expected = schema["type"]
            types = expected if isinstance(expected, list) else [expected]
            if not any(self._check_type(instance, t) for t in types):
                tnames = "/".join(types)
                self.errors.append(
                    f"{self._fmt(path)}: 类型应为 {tnames}，实际 {type(instance).__name__}"
                )
                return

        # 枚举
        if "enum" in schema and instance not in schema["enum"]:
            self.errors.append(f"{self._fmt(path)}: 值 {instance!r} 不在枚举 {schema['enum']!r}")

        # 常量
        if "const" in schema and instance != schema["const"]:
            self.errors.append(f"{self._fmt(path)}: 值应为 {schema['const']!r}")

        # 字符串约束
        if isinstance(instance, str):
            if "minLength" in schema and len(instance) < schema["minLength"]:
                self.errors.append(f"{self._fmt(path)}: 字符串短于 minLength={schema['minLength']}")
            if "maxLength" in schema and len(instance) > schema["maxLength"]:
                self.errors.append(f"{self._fmt(path)}: 字符串长于 maxLength={schema['maxLength']}")
            if "pattern" in schema:
                try:
                    if not re.search(schema["pattern"], instance):
                        self.errors.append(f"{self._fmt(path)}: 字符串不匹配 pattern {schema['pattern']!r}")
                except re.error as exc:
                    self.errors.append(f"{self._fmt(path)}: pattern 非法 {schema['pattern']!r} ({exc})")

        # 数值约束
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in schema and instance < schema["minimum"]:
                self.errors.append(f"{self._fmt(path)}: 数值 {instance} < minimum={schema['minimum']}")
            if "maximum" in schema and instance > schema["maximum"]:
                self.errors.append(f"{self._fmt(path)}: 数值 {instance} > maximum={schema['maximum']}")

        # 对象
        if isinstance(instance, dict):
            props = schema.get("properties", {})
            for req in schema.get("required", []):
                if req not in instance:
                    self.errors.append(f"{self._fmt(path)}: 缺少必填字段 {req!r}")
            addl = schema.get("additionalProperties", True)
            for key, value in instance.items():
                child = f"{path}.{key}" if path else key
                if key in props:
                    self.validate(value, props[key], child)
                elif addl is False:
                    self.errors.append(f"{self._fmt(path)}: 字段 {key!r} 违反 additionalProperties:false")
                elif isinstance(addl, dict):
                    self.validate(value, addl, child)

        # 数组
        if isinstance(instance, list):
            if "minItems" in schema and len(instance) < schema["minItems"]:
                self.errors.append(f"{self._fmt(path)}: 数组长度 {len(instance)} < minItems={schema['minItems']}")
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                self.errors.append(f"{self._fmt(path)}: 数组长度 {len(instance)} > maxItems={schema['maxItems']}")
            if schema.get("uniqueItems"):
                seen = [json.dumps(x, sort_keys=True) for x in instance]
                if len(set(seen)) != len(seen):
                    self.errors.append(f"{self._fmt(path)}: 数组存在重复元素")
            items = schema.get("items")
            if isinstance(items, dict):
                for i, elem in enumerate(instance):
                    self.validate(elem, items, f"{path}[{i}]" if path else f"[{i}]")
            elif isinstance(items, list):
                for i, (elem, sub) in enumerate(zip(instance, items)):
                    self.validate(elem, sub, f"{path}[{i}]" if path else f"[{i}]")

        # 组合关键字
        for i, sub in enumerate(schema.get("allOf", [])):
            self.validate(instance, sub, f"{path}(allOf[{i}])")
        if "anyOf" in schema:
            branch_errors = []
            for i, sub in enumerate(schema["anyOf"]):
                branch = Validator()
                branch.validate(instance, sub, path)
                if not branch.errors:
                    break
                branch_errors.append((i, branch.errors))
            else:
                self.errors.append(f"{self._fmt(path)}: 不匹配任何 anyOf 分支")
        if "oneOf" in schema:
            matched = 0
            for sub in schema["oneOf"]:
                branch = Validator()
                branch.validate(instance, sub, path)
                if not branch.errors:
                    matched += 1
            if matched != 1:
                self.errors.append(f"{self._fmt(path)}: oneOf 匹配 {matched} 个分支（应为恰好 1）")
        if "not" in schema:
            branch = Validator()
            branch.validate(instance, schema["not"], path)
            if not branch.errors:
                self.errors.append(f"{self._fmt(path)}: 命中了 not 分支")

    @staticmethod
    def _check_type(instance, t: str) -> bool:
        return {
            "object": lambda v: isinstance(v, dict),
            "array": lambda v: isinstance(v, list),
            "string": lambda v: isinstance(v, str),
            "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
            "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
            "boolean": lambda v: isinstance(v, bool),
            "null": lambda v: v is None,
        }.get(t, lambda v: True)(instance)


def check_schema_self() -> list[str]:
    """第 1、2 层：schema 合法性与唯一性。"""
    problems: list[str] = []
    seen_ids: dict[str, str] = {}
    for path in sorted(SCHEMA_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"[schema] {path.name}: JSON 解析失败 {exc}")
            continue
        if not isinstance(data, dict):
            problems.append(f"[schema] {path.name}: 顶层必须是对象")
            continue
        if data.get("$schema") != "http://json-schema.org/draft-07/schema#":
            problems.append(f"[schema] {path.name}: $schema 应为 draft-07")
        if data.get("type") != "object":
            problems.append(f"[schema] {path.name}: type 应为 object")
        sid = data.get("$id", "")
        if not sid:
            problems.append(f"[schema] {path.name}: 缺少 $id")
        else:
            expect_tail = path.name
            if not sid.endswith(expect_tail):
                problems.append(f"[schema] {path.name}: $id 尾段应为 {expect_tail}")
            if sid in seen_ids:
                problems.append(f"[schema] $id 重复 {sid}（{seen_ids[sid]} 与 {path.name}）")
            seen_ids[sid] = path.name
        # 白名单检查
        def walk(node, where: str) -> None:
            if isinstance(node, dict):
                for k in node:
                    if k.startswith("$") and k not in SUPPORTED_KEYWORDS:
                        problems.append(f"[schema] {path.name}{where}: 未知关键字 {k}")
                    walk(node[k], f"{where}.{k}")
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    walk(item, f"{where}[{i}]")
        walk(data, "")
    return problems


def check_fixtures() -> list[str]:
    """第 3 层：fixtures 通过对应 schema 校验。"""
    problems: list[str] = []
    schemas = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in SCHEMA_DIR.glob("*.json")}
    checked = 0
    for rel, schema_name in sorted(FIXTURE_SCHEMA_MAP.items()):
        fpath = FIXTURE_DIR / rel
        if not fpath.exists():
            continue  # 尚未创建的 fixture 不阻塞（随线开发补齐）
        try:
            instance = json.loads(fpath.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"[fixture] {rel}: JSON 解析失败 {exc}")
            continue
        schema = schemas.get(schema_name or "", None)
        if schema is None:
            # 内联契约或无 schema 对照：只要求是合法 JSON
            checked += 1
            continue
        v = Validator()
        v.validate(instance, schema, "")
        if v.errors:
            for e in v.errors:
                problems.append(f"[fixture] {rel}: {e}")
        else:
            checked += 1
    # 其余未登记 fixture（脏样本等）只做 JSON 合法性
    for fpath in sorted(FIXTURE_DIR.rglob("*.json")):
        rel = fpath.relative_to(FIXTURE_DIR).as_posix()
        if rel in FIXTURE_SCHEMA_MAP:
            continue
        try:
            json.loads(fpath.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            problems.append(f"[fixture] {rel}: JSON 解析失败 {exc}")
    print(f"  fixtures 通过 schema 校验：{checked}")
    return problems


def check_events_consistency() -> list[str]:
    """第 4 层：events.md 主题与 schema 文件映射一致。"""
    problems: list[str] = []
    if not EVENTS_MD.exists():
        return ["[events] contracts/events.md 缺失"]
    text = EVENTS_MD.read_text(encoding="utf-8")
    required_topics = [
        "raw.docs", "intel.items", "dq.verdicts", "enrich.triage",
        "enrich.papers", "enrich.items", "qa.queries", "qa.answers",
        "decision.replies", "fallback.events",
    ]
    for topic in required_topics:
        if f"`{topic}`" not in text:
            problems.append(f"[events] 主题 {topic} 未在 events.md 登记")
    schema_files = {p.name for p in SCHEMA_DIR.glob("*.json")}
    expected = {
        "RawDoc.json", "IntelItem.json", "EnrichmentResult.json",
        "DecisionRequest.json", "DecisionReply.json",
        "RetrievalRequest.json", "RetrievalResponse.json",
        "ToolRegistration.json",
    }
    missing = expected - schema_files
    if missing:
        problems.append(f"[events] 契约文件缺失：{sorted(missing)}")
    return problems


def main() -> int:
    print("SafeTrace 契约校验（stdlib JSON Schema 子集）")
    all_problems: list[str] = []

    print("[1/4] schema 自校验 ...")
    all_problems += check_schema_self()
    print("[2/4] fixtures 校验 ...")
    all_problems += check_fixtures()
    print("[3/4] events.md 一致性 ...")
    all_problems += check_events_consistency()
    schema_count = len(list(SCHEMA_DIR.glob('*.json')))
    print(f"[4/4] 汇总：{schema_count} 个 schema 契约文件")

    if all_problems:
        print(f"\n失败 {len(all_problems)} 项：")
        for p in all_problems:
            print(f"  - {p}")
        return 1
    print("\n全部通过：契约合法、fixtures 达标、主题登记完整")
    return 0


if __name__ == "__main__":
    sys.exit(main())
