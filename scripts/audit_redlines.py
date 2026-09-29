"""红线审计：找出**疑似静默兜底**的位置。

项目红线第 3 条：「兜底必须显式 —— 降级响应必须带 `degraded_to` 与用户可见标记，
**禁止静默兜底**」。

审计思路：找出"捕获异常后返回一个默认/空值"的地方，看这些返回值**是否带上**
降级标记（`degraded_to` / `degraded_reason` / `mock` / `source_failures`）。
带标记 = 合法降级；不带 = 疑似静默兜底，须人工确认。

只做静态筛查并输出候选，不自动改代码 —— 误报要靠人看语义。
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

#: 出现这些名字就认为"这条降级是显式的"
EXPLICIT_MARKERS = {
    "degraded_to",
    "degraded_reason",
    "mock",
    "source_failures",
    "abstained",
    "abstain_reason",
    "fallback",
    "skipped",
    "error",
    "problems",
    "note",
    "caveat",
}

#: 这些返回值形状表示"给了一个空/默认值"（兜底特征）
EMPTY_LITERALS = ({}, [], None, (), "", 0, False, "0")


class ExceptVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, lines: list[str]) -> None:
        self.path = path
        self.lines = lines
        self.findings: list[dict] = []

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """检查 except 块：若其中 return/赋值 了空值，且块内没有任何显式标记，则记为候选。"""

        body_lines: list[str] = []
        for stmt in node.body:
            start = stmt.lineno - 1
            end = getattr(stmt, "end_lineno", stmt.lineno)
            body_lines.extend(self.lines[start:end])
        body_src = "\n".join(body_lines)
        has_marker = any(m in body_src for m in EXPLICIT_MARKERS)
        if has_marker:
            self.generic_visit(node)
            return

        # 找该块里的 return / return <literal>
        returns: list[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                txt = self.lines[child.lineno - 1].strip()
                returns.append(txt)
        if not returns:
            self.generic_visit(node)
            return

        exc_name = getattr(node.type, "id", None) or getattr(node.type, "attr", None) or "Exception"
        self.findings.append(
            {
                "file": str(self.path.relative_to(ROOT)),
                "line": node.lineno,
                "exception": exc_name,
                "returns": returns[:3],
                "snippet": body_src.strip().splitlines()[0][:100] if body_src.strip() else "",
            }
        )
        self.generic_visit(node)


def main() -> int:
    total = 0
    all_findings: list[dict] = []
    for path in sorted(SRC.rglob("*.py")):
        lines = path.read_text(encoding="utf-8").splitlines()
        try:
            tree = ast.parse("\n".join(lines))
        except SyntaxError as exc:
            print(f"  [!] 解析失败 {path}: {exc}")
            continue
        v = ExceptVisitor(path, lines)
        v.visit(tree)
        if v.findings:
            all_findings.extend(v.findings)
            total += len(v.findings)

    print(f"疑似静默兜底候选：{total} 处")
    print("（判据：except 块里 return 了值，但块内没有 degraded_*/mock/fallback 之类的显式标记）")
    print()
    for f in all_findings:
        print(f"  {f['file']}:{f['line']}  捕获 {f['exception']}")
        print(f"      return: {' | '.join(f['returns'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
