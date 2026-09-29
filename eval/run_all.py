"""评测：三个指标脚本（采集延迟 / 富化准确率 / 问答准确率）。

人工标注集存放在 eval/datasets/ 下的 JSONL 中，字段与 db.models.EvalCase 对应。
所有脚本可离线复跑，结果直接进技术报告。

用法：
  python -m eval.run_all                 # 跑全部
  python -m eval.collect_latency         # 只跑采集时效
  python -m eval.enrich_accuracy         # 只跑富化准确率
  python -m eval.qa_accuracy             # 只跑问答准确率
"""

from __future__ import annotations

from eval.collect_latency import main as run_collect_latency
from eval.enrich_accuracy import main as run_enrich_accuracy
from eval.qa_accuracy import main as run_qa_accuracy

__all__ = ["run_collect_latency", "run_enrich_accuracy", "run_qa_accuracy"]


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description="AI 安全情报系统评测")
    parser.add_argument(
        "targets",
        nargs="*",
        choices=["collect", "enrich", "qa"],
        help="不指定则全部执行",
    )
    args = parser.parse_args()
    targets = args.targets or ["collect", "enrich", "qa"]

    runners = {
        "collect": run_collect_latency,
        "enrich": run_enrich_accuracy,
        "qa": run_qa_accuracy,
    }
    report: dict[str, dict] = {}
    for name in targets:
        report[name] = runners[name]()

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
