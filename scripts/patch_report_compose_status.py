"""逐行替换报告生成脚本里的 compose 说明（避免多行字符串拼接带来的精确匹配问题）。

定位方式：连续若干行中以 `'Docker Compose一键启动` 开头的那一行，
把它及其后 3 行一起换成新的 4 行文本。
"""

from pathlib import Path

DIR = Path(
    r'C:\Users\kkk97\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent'
    r'\work-mode-projects\6abb26ff17b11b4656d447f2'
)

START_MARK = "'Docker Compose一键启动"
SPAN = 4  # 原文占 4 行

NEW_LINES = [
    "        'Docker Compose一键启动（**实测，全栈端到端通过**）：api / postgres / redis / web / '",
    "        'prometheus / ollama 六服务全部起来，运行期冒烟 10/10 通过 —— /health 200、'",
    "        '迁移在容器内自动执行（19 张表，alembic=0003_simhash_bigint）、/api/v1/vulns total=13、'",
    "        'Redis PING 成功、web 首页 200 且 nginx 反代 /api 返回 total=13、Prometheus 抓取 '\n"
    "        'aiintel=up、问答 SSE citation=True。注：嵌入依赖（sentence-transformers/torch '\n"
    "        '约 2.5GB）默认不装 —— 本机网络下 huggingface.co 不可达、拿不到模型权重，'\n"
    "        '装了也用不上，经 INSTALL_EMBED=1 可选开启。'\n",
]


def main() -> int:
    for name in ('generate_report.py', 'generate_word.py'):
        p = DIR / name
        if not p.exists():
            continue
        lines = p.read_text(encoding='utf-8').splitlines(keepends=True)
        idx = None
        for i, line in enumerate(lines):
            if START_MARK in line:
                idx = i
                break
        if idx is None:
            print(f'  {name}: 未找到起始行')
            continue
        print(f'  {name}: 命中 L{idx + 1}，替换 {SPAN} 行')
        lines[idx:idx + SPAN] = NEW_LINES
        p.write_text(''.join(lines), encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
