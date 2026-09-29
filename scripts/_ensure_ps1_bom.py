"""给指定 .ps1 加 UTF-8 BOM（PowerShell 5.1 读无 BOM 的脚本会按 ANSI/GBK 解码中文，
把中文拆成乱码字节、个别字节被当成引号 → 报"字符串缺少终止符"这类假语法错误）。

仓库约定：.py/.md/.json 无 BOM，**.ps1 例外**（BOM 是 PowerShell 脚本的推荐做法）。
"""

import sys
from pathlib import Path

BOM = b'\xef\xbb\xbf'
changed = 0
for arg in sys.argv[1:]:
    p = Path(arg)
    if not p.exists():
        print(f'  不存在: {p}')
        continue
    raw = p.read_bytes()
    if raw.startswith(BOM):
        print(f'  已有 BOM: {p.name}')
        continue
    text = raw.decode('utf-8')  # 先确认本身是合法 UTF-8
    p.write_bytes(BOM + text.encode('utf-8'))
    print(f'  已加 BOM: {p.name}  ({len(raw)} -> {p.stat().st_size} 字节)')
    changed += 1
print(f'改动 {changed} 个文件')
