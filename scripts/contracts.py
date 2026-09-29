"""极简 JSON Schema 校验器（draft-07 子集，零第三方依赖）。

为什么不用 `jsonschema`：本项目要求"缺省依赖也能跑"（`pip install -e .` 后 CI 直接跑单测），
而 `jsonschema` 不在依赖里。这里只实现契约用到的关键字，够用且不会引入新依赖。

支持：type / required / properties / additionalProperties / items / minItems / maxItems /
enum / const / minimum / maximum / minLength / maxLength / pattern / default / allOf / if-then。

`format` 按 draft-07 语义视为纯注解，不做校验（与规范一致，避免各实现分歧）。

```python
from scripts.contracts import load_schema, validate
errors = validate(load_schema("EnrichmentResult.json"), payload)
```
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "contracts" / "schemas"

_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


def load_schema(name: str) -> dict[str, Any]:
    """按文件名加载 schema（如 `EnrichmentResult.json`）。"""

    path = SCHEMA_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"契约 schema 不存在: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _type_ok(value: Any, expected: str) -> bool:
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    py = _TYPE_MAP.get(expected)
    return isinstance(value, py) if py is not None else True


def validate(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    """返回错误信息列表；空列表表示通过。"""

    errors: list[str] = []

    if "type" in schema:
        expected = schema["type"]
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(_type_ok(value, t) for t in allowed):
            errors.append(f"{path}: 期望类型 {allowed}，实际 {type(value).__name__}")
            return errors  # 类型不符后不再深入，避免噪声

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: 期望常量 {schema['const']!r}，实际 {value!r}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: 取值 {value!r} 不在枚举 {schema['enum']} 中")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: {value} > maximum {schema['maximum']}")

    if isinstance(value, str) and "minLength" in schema and len(value) < schema["minLength"]:
        errors.append(f"{path}: 长度 {len(value)} < minLength {schema['minLength']}")

    if isinstance(value, str) and "maxLength" in schema and len(value) > schema["maxLength"]:
        errors.append(f"{path}: 长度 {len(value)} > maxLength {schema['maxLength']}")

    if (
        isinstance(value, str)
        and "pattern" in schema
        and re.search(schema["pattern"], value) is None
    ):
        errors.append(f"{path}: {value!r} 不匹配 pattern {schema['pattern']!r}")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: 缺少必需字段 `{key}`")
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in value:
                errors.extend(validate(sub, value[key], f"{path}.{key}"))
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{path}: 不允许的额外字段 `{key}`")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: 元素数 {len(value)} < minItems {schema['minItems']}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: 元素数 {len(value)} > maxItems {schema['maxItems']}")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                errors.extend(validate(item_schema, item, f"{path}[{idx}]"))

    for sub in schema.get("allOf", []):
        # if-then：条件满足才施加约束（draft-07 语义）
        if "if" in sub:
            condition_ok = not validate(sub["if"], value, path)
            if condition_ok and "then" in sub:
                errors.extend(validate(sub["then"], value, path))
            continue
        errors.extend(validate(sub, value, path))

    return errors
