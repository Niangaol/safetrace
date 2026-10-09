# 本地 Jev 论文评审（Open-Jev）接入手册

> 2026-10-09。对应提交：`src/enrich/src/jev-paper-review.ts`（端口）、
> `src/enrich/src/stepfun-paper-review.ts`（端口类型扩展）、`src/enrich/src/index.ts`（F1 advisory 分支泛化）、
> `scripts/enrich-pending.ts`（opt-in 装配）、`src/enrich/test/jev-paper-review.test.ts`（10 条用例）。

## 为什么接它

2026-10-09 的 paper 探针实测：锚点词 + 机制词共现的启发式过滤把 48% 的条目标成
论文命中，71 篇保留论文里 **0 篇**提到对应 CVE，过半是通用词锚点的噪声
（catalyst 物理论文、internet/6G 论文……）。词重合判断不了"这篇论文是否真的在说
这个漏洞"，而 Open-Jev 的 Choice 原语正是为这类判定训练的：给 (漏洞报告, 候选论文)，
直接返回 related/unrelated 的类型化概率，天然带弃权出口。

选型事实：代码 MIT、权重 Apache-2.0（Qwen3.5-2B 底座 + LoRA + 独立 decision head）；
官方 Jev 权重闭源，这是可本地跑的开源复现。**本机 RTX 5070 Ti 12GB 可跑 2B**
（参考峰值 6.9GiB 是 H200 batch-32，batch-1 更少；9B/27B 不用考虑）。

## 端口行为（先读这个再跑）

- **advisory only**：只产 sidecar 建议（lineage `enrich.f1_openjev_advisory` +
  控制台 `f1_paper_advisory` 日志），**不改** PaperLink 分数/顺序，不改 published
  EnrichmentResult——与 StepFun 评审同口径。A/B 结论出来前不放开"应用"模式。
- **每篇候选一次请求**：state = 漏洞报告 + 论文标题 + 摘要（摘要仅来自本次 arXiv
  原始回执 `paper_records`，截断 1000 字符）；question = Choice[related, unrelated, uncertain]。
- **阈值**：P(related) ≥ 0.9 才进建议（可配 `threshold`，下限 0.8——上游对 suggested
  的 confidence 校验是 0.8，低于它没有意义）。全部低于阈值 → abstained。
- **fail-closed**：服务不可达 / 非 200 / 响应畸形（缺 answers.relevance、概率越界、
  不归一、confidence 非数字）一律**抛错**，上游转 degraded lineage + FallbackEvent，
  规则结果原样保留。禁止把"模型没说话"当成"模型说不行"。
- **注入筛查**：论文标题/摘要是外部内容，进模型前过 A-04 屏幕，不过即 abstained。
- **模型标识钉版本**：`modelId` 必填（官方别名会静默漂移），落 lineage。

## GPU 服务运行手册（本机：Windows + RTX 5070 Ti 12GB）

```powershell
# 1. 克隆并钉提交（上游 README 的 quickstart 钉的是 80ca8e8）
git clone https://github.com/Zefan-Cai/Open-Jev.git
cd Open-Jev
git checkout 80ca8e81d08992cb2a4cbb6a0caa1355ad3e5aee

# 2. Python 3.12 venv + torch（cu128 覆盖 RTX 50 系 sm_120）
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install torch==2.9.0 --index-url https://download.pytorch.org/whl/cu128
python -m pip install -e ".[train]"

# 3. 权重钉 revision 下载（2B checkpoint + Qwen3.5-2B 底座会自动按 package/model.json 的钉版拉取）
hf download ZefanCai/Open-Jev-2B --revision 0c7aa498b1627be8da4acf34c863ff0ee0a92785 --local-dir models/Open-Jev-2B

# 4. 起服务（batch-1、loopback）
python -m jev.server --checkpoint models/Open-Jev-2B/package/checkpoint --device cuda:0 --max-length 4096 --batch-size 1 --no-prefix-cache --host 127.0.0.1 --port 8791
```

验收：

```powershell
curl http://127.0.0.1:8791/health          # {"status":"ready","model":...}
curl -X POST http://127.0.0.1:8791/v1/systemone -H "Content-Type: application/json" -d @configs/example-request.json
```

## SafeTrace 侧启用

```bash
# 本地评审 + 在线富化（离线模式一律拒绝本地评审：fixture 回放必须确定）
SAFETRACE_ENRICH_OFFLINE=false SAFETRACE_ENRICH_PAPER_REVIEWER=jev JEV_BASE_URL=http://127.0.0.1:8791 JEV_MODEL_ID=Open-Jev-2B@0c7aa49 npm run enrich:pending -- --apply --dimensions=paper --limit=20
```

- `SAFETRACE_ENRICH_PAPER_REVIEWER` 只接受 `jev`；与 `SAFETRACE_ENRICH_LLM_ENABLED`（StepFun 云端评审）**互斥**，同开直接报错。
- `--apply` 仍受既有门禁约束：verified backup（需 Qdrant 在线做新备份）+ 单写 lease。
- 每条目最多 5 次本地推理。延迟须以本机真实请求记录为准，尚不能宣称单次数百毫秒。
- 不加 `--apply` 仅规划 pending，不调用模型。独立、不写业务库的实测用 `scripts/jev-paper-ab.ts`。

## A/B 怎么看

控制台每条评审打一行 `f1_paper_advisory`：`provider / status / paper_ids / probabilities / applied:false`。
对照三件事：

1. **精确率**：探针已知的假阳性（catalyst 论文 vs chromium CVE 这类）P(related) 是否 < 0.9；
2. **弃权率**：abstained 占比——弃权太多说明阈值或问法要逐题校准（铁律③）；
3. **与规则集差异**：Jev 保留 ⊂ 规则保留？差集就是噪声候选；Jev 保留 ⊄ 规则保留的
   条目要人工看是否规则漏杀。

## 纪律与已知限制（不得隐瞒）

- 独立弃权出口（uncertain，不等同 unrelated）/ 默认 0.9 保留阈值（非正确率保证）/ 阈值按问法逐题校准 /
  state-blind 基线（拿打乱 state 的请求测校准）/ MC 顺序无偏。
- 本实现和 Open-Jev 的准确率、校准误差未经该任务实测。其他 Jev 实现的指标不可直接迁移；英文输入也不保证可靠。格式合法不等于语义正确。
- 上游 `index.ts` 的 F1 advisory 分支已泛化（stage/execution 按 provider 动态生成）；
  StepFun 路径的 stage 名 `enrich.f1_stepfun_advisory` 保持不变。

## 实际 GPU 部署与独立验收（后续推进）

本机登记的 Python 3.12 路径已失效；已用 Python 3.13 隔离环境安装 Torch 2.9.0+cu128，CUDA 12.8，实际 tensor kernel 验证通过。源码固定 80ca8e8，checkpoint 固定 0c7aa49，基础模型固定 15852e8。部署目录被 third_party 忽略，不进入 Git。

```bash
third_party/open-jev/.venv/Scripts/python.exe scripts/local/jev_gpu.py prepare
third_party/open-jev/.venv/Scripts/python.exe scripts/local/jev_gpu.py serve
node --import tsx scripts/jev-paper-ab.ts
```

prepare 下载固定版本权重并生成本地清单；serve 拒绝 CPU 回退，校验参数都在 cuda:0，并在响应记录设备和 checkpoint 哈希。A/B 脚本核对实际服务端模型、code commit、base revision、checkpoint 哈希和设备；测试正常输入、候选顺序反转、state-blind 三种条件。

当前 fixture 是显式标注的人工合成 sanity 用例，并非 arXiv 原文或正式准确率评测；不可用小样本结果宣称生产准确率。结果写 tmp，业务库零写入。还需捕获真实论文原文和人工标注后扩展评测。

代理兼容修复只在下载器进程里移除 httpx 无法解析的 NO_PROXY 裸 IPv6 项，不修改系统代理。

后续链路边界：新维度优先用类型化 sidecar 保持严格旧 schema 消费者兼容；冻结契约允许受控追加，但旧 additionalProperties:false 校验器仍会拒新增 artifact。Qdrant 阻塞的是新完整备份，不是所有写入。
