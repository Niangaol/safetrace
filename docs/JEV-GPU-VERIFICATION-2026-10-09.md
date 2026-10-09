# Open-Jev GPU 实际验收（2026-10-09）

## 已完成的真实部署

- GPU：RTX 5070 Ti Laptop，CUDA compute capability 12.0；Torch 2.9.0+cu128 / CUDA 12.8，实际 CUDA tensor 运算通过。
- 隔离 Python 3.13 环境：third_party/open-jev/.venv；没有修改全局 Python。
- 代码：80ca8e81d08992cb2a4cbb6a0caa1355ad3e5aee。
- Open-Jev-2B checkpoint：0c7aa498b1627be8da4acf34c863ff0ee0a92785。
- Qwen3.5-2B 底座：15852e8c16360a2fea060d615a32b45270f8a8fc。
- 本机 checkpoint 哈希：37c1559d6501270cd378ca4f3d4acd3d8632b624dfe65fe9aa174cfd7fd2a82f（上游按路径与内容计算，跨平台路径表示可能影响哈希）。
- 本地服务：127.0.0.1:8791。health 的 model 显示 Qwen/Qwen3.5-2B，method=lora_decision_head；并非未训练底座。不能只看 model 字符串就判断是否 Jev，需要 method、checkpoint 哈希、源码和底座版本一起验证。
- 服务启动检查全部参数都在 cuda:0，拒绝 CPU/offload 回退。标准 Torch 后端，BF16，不使用实验 fast-cuda/Triton 内核。

## 客户端修正

原先 related/unrelated 二选一没有独立弃权出口，已改为 related/unrelated/uncertain。默认 0.9 是保留门槛，不是正确率保证。

新增本机 origin 校验、禁止重定向、概率键集合/归一化/argmax 一致性与超时校验。纠正历史实现里把其他 Jev 的 ECE 数字移植到 Open-Jev 的说法，本模型校准误差仍未知。

## 两层只读对比

### 合成 sanity

fixtures/jev-paper-ab.v1.json 明确标注为人工合成，不冒充真实论文或正式基准。8 个场景 × 正常/候选顺序反转/state-blind，24 次真实 GPU 请求。

- 明显噪声相关概率低；两个正例相关概率分别约 0.5615（Log4Shell）、0.8419（Langflow），均低于 0.9，最终全部弃权。
- 顺序反转在这些样本中未改变概率；不构成所有输入都无顺序偏差的证明。
- 去掉漏洞上下文后结果变化，部分变为 uncertain；不据此宣称模型校准合格。
- 请求耗时中位约 647ms，包括 HTTP 与完整客户端流程。

### 真实 arXiv metadata

从最新 DQ 放行情报中选 log4j/langflow/chromium 产品，捕获 arXiv Atom 原文与 SHA256，保留对应 Intel 事件 ID。每个产品最多 3 个候选：9 对真实候选 × 三种条件，27 次真实 GPU 请求。

- 正常输入相关概率范围约 0.0400–0.3256，9/9 最终弃权。
- 请求耗时中位约 702ms。
- 这些真实样本未人工标注，不能计算准确率/精确率。特别是当前 Log4j 条目是 CVE-2021-4104（JMSAppender 反序列化），候选多数讨论 Log4Shell；“同产品”不等于“同漏洞”。
- 没有改 SQLite 情报、富化状态或知识投影，business_writes=0。

本地详细结果在 tmp/jev-paper-ab-result.json 与 tmp/jev-paper-live-ab-result.json；原文在 tmp/jev-paper-capture。均为忽略的本机验收产物。

## 结论与下一步

GPU 服务和端口真实贯通，但在当前 0.9 阈值下没有自动保留结果。不能宣称提高了论文覆盖率或生产准确率。保持 advisory-only，不为了覆盖率降低阈值、不自动应用建议。

第一步（部署+真实 A/B）已完成，接下来按用户确认顺序接入修复建议，再接真实资产、PoC 候选元数据和优先级。优先选择独立 typed sidecar 和独立收据，不向旧严格 EnrichmentResult schema 偷塞字段。

审查另发现：资产 CLI/watch 的历史情报读法未过滤最新 DQ，后续资产接入须先统一准入口径；Qdrant 阻塞新完整备份而非所有写入，保持维护门禁，不绕过。
