"""filter-branch 用的过滤器：从 stdin 读文本，把真实 key 换成假串，写到 stdout。

**为什么不直接用 PowerShell 做 tree-filter**：Git for Windows 的 filter-branch
用 `sh` 执行过滤器，PowerShell 语法会报
`syntax error near unexpected token '{'`（实测踩过）。
Python 在两边都能跑，且不涉及引号/代码页问题。
"""

import sys

OLD = 'sk-71a75be4461b4ff5a1620e4aa7705ac9'
NEW = 'sk-fake0123456789abcdefghijklmnopqrst'

data = sys.stdin.buffer.read()
try:
    text = data.decode('utf-8')
except UnicodeDecodeError:
    # 二进制文件：原样输出，不做替换
    sys.stdout.buffer.write(data)
    sys.exit(0)

sys.stdout.buffer.write(text.replace(OLD, NEW).encode('utf-8'))
