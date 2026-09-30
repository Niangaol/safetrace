"""C-06 契约交叉校验单测：schema/fixture 目录 ↔ 登记集合 ↔ CHANGELOG 三方防漂。

判据：登记表（python 常量 + CHANGELOG.md）与磁盘目录必须双向一致；
任何一方"漏了"都会在 `validate_contracts` 里显式失败，而不是悄悄不校验。
"""

from __future__ import annotations

from pathlib import Path

from scripts.validate_contracts import (
    AUTHORITATIVE_SCHEMAS,
    LOCAL_SCHEMAS,
    SCHEMA_DIR,
    check_fixture_registry,
    check_schema_registry,
)


def test_real_schema_dir_is_consistent_with_registry() -> None:
    """磁盘 schema 文件 ↔ 权威 8 + 本仓 3 登记：当前仓内必须零偏差。"""

    problems = check_schema_registry()
    assert problems == [], problems


def test_changelog_lists_every_declared_schema() -> None:
    """CHANGELOG 注册表必须点名全部 11 个 schema（防文档与登记集合脱节）。"""

    changelog = (SCHEMA_DIR / "CHANGELOG.md").read_text(encoding="utf-8")
    missing = [name for name in AUTHORITATIVE_SCHEMAS + LOCAL_SCHEMAS if name not in changelog]
    assert missing == [], f"CHANGELOG 未点名: {missing}"


def test_real_fixture_dir_is_consistent_with_registry() -> None:
    problems = check_fixture_registry()
    assert problems == [], problems


def test_orphan_schema_detected_in_custom_dir(tmp_path: Path) -> None:
    """未登记 schema 文件必须被拦（反向：登记了却缺失也必须被拦）。"""

    (tmp_path / "OrphanSchema.json").write_text("{}", encoding="utf-8")
    problems = check_schema_registry(tmp_path)
    assert any("OrphanSchema.json" in p and "未登记" in p for p in problems)
    assert any("缺失" in p for p in problems)  # 反向（全目录仅孤儿文件）


def test_orphan_fixture_detected_in_custom_dir(tmp_path: Path) -> None:
    (tmp_path / "orphan.sample.json").write_text("{}", encoding="utf-8")
    problems = check_fixture_registry(tmp_path)
    assert any("orphan.sample.json" in p and "未登记" in p for p in problems)
    assert any("缺失" in p for p in problems)


def test_validate_contracts_script_still_passes_with_c06() -> None:
    """带 C-06 后 `python -m scripts.validate_contracts` 必须仍全绿（CI 门禁）。"""

    from scripts.validate_contracts import main as vc_main

    assert vc_main() == 0
