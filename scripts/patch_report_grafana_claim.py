"""清掉报告里"用了 Grafana"的说法 —— compose 里并没有 grafana 服务。

实测 `docker compose config --services` 只有
api / ollama / postgres / prometheus / redis / web，**没有 grafana**。
`deploy/prometheus.yml` 里挂过一个 grafana dashboards 目录，但没有 grafana 容器去读它，
所以"structlog + Prometheus + Grafana"属于不实描述。
"""

import subprocess
from pathlib import Path

DIR = Path(
    r"C:\Users\kkk97\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent"
    r"\work-mode-projects\6abb26ff17b11b4656d447f2"
)


def real_services() -> list[str]:
    out = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            r"E:\code\ai-threat-intel-demo-v1\docker-compose.yml",
            "config",
            "--services",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return sorted(out.stdout.split())


PAIRS = [
    ("'structlog + Prometheus + Grafana'", "'structlog + Prometheus'"),
    (
        "['可观测', 'structlog + Prometheus + Grafana', '核心指标 + 监控面板'],",
        "['可观测', 'structlog + Prometheus', '21 个 # HELP 指标；Grafana 未部署'],",
    ),
    (
        "['可观测', 'structlog + Prometheus + Grafana', '3个核心指标 + 1面板'],",
        "['可观测', 'structlog + Prometheus', '21 个 # HELP 指标；Grafana 未部署'],",
    ),
    ("'3个核心指标 + 1面板'", "'21 个 # HELP 指标（Grafana 未部署）'"),
]


def main() -> int:
    services = real_services()
    print(f"compose 实际服务: {services}")
    print(f"  含 grafana? {'是' if 'grafana' in services else '否'}")
    print()
    for name in ("generate_report.py", "generate_word.py", "generate_ppt.py"):
        p = DIR / name
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8")
        ok = 0
        for old, new in PAIRS:
            if old in text:
                text = text.replace(old, new)
                ok += 1
        p.write_text(text, encoding="utf-8")
        print(f"  {name}: 替换 {ok} 处")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
