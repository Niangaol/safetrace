# SafeTrace · GitHub Flow 工作流

> 历史版本 v1（D1）；D3 起的协作与分工以 [`TEAM-PLAN.md`](TEAM-PLAN.md) 为准。
> 本文保留门禁、提交格式和钩子说明；分支/PR 流程已被 TEAM-PLAN 的单线制覆盖。
> 工程原则不变：**main 永远可演示；契约先行；Fixture 优先；降级显式。**

## 一、总规则

1. **main 永远处于可演示状态**：任何时刻从 main 检出即可跑通 `npm run check` 与冒烟脚本。
2. **D3 起单线制**：新工作直接在 `main` 上完成，不新建 feature/contract/docs 分支；提交前跑门禁。
3. **不经常规 PR**：按 `TEAM-PLAN.md` 由队员协同 main；提交信息必须带台账编号。
4. **推送门禁**：本地 pre-push + CI 全绿后才推 main；被拒时 `git pull --rebase origin main`，禁止 force push。
5. **冲突停手**：尤其 `contracts/` 冲突，不猜着解；先同步三人并共同确定结果。

## 二、历史分支命名（D3 起停用）

> 以下命名仅用于追溯 D1-D2 的旧分支；D3 起按 `TEAM-PLAN.md` 直接在 `main` 单线推进。

```
<type>/<线>-<主题>
```

| type | 用途 | 示例 |
|---|---|---|
| `feat/` | 新功能/模块推进 | `feat/ingest-kev-connector` |
| `fix/` | 缺陷修复 | `fix/dq1-false-quarantine` |
| `contract/` | **契约改动**（走第五节特殊流程） | `contract/schemas-v1` |
| `exp/` | 实验能力（默认不部署） | `exp/pi-agent-core-spike` |
| `chore/` | 工程基建/CI/脚本 | `chore/github-flow` |
| `docs/` | 文档 | `docs/readme-landing` |
| `ops/` | compose/部署/自愈脚本 | `ops/compose-smoke` |
| `test/` | 只加/改测试 | `test/golden-qa-seed` |

<线> = `ingest` / `enrich` / `qa` / `gateway` / `shared`（底座写 shared 或 gateway）。

**D1-D2 旧操作示例（D3 起停用）**：

```bash
scripts/new-branch.sh feat ingest kev-connector
```

## 三、提交信息（Conventional Commits，hook 强制）

```
<type>(<scope>): <subject>

type: feat|fix|contract|docs|test|refactor|chore|ops|perf|build|ci|release
scope: 模块/线名，如 ingest / gateway / qa / contracts
```

示例：`feat(ingest): KEV 连接器 + Y2 适配器回归 fixture (E-01)`；提交须追加台账编号。

契约提交必须显式写影响面，例如：`contract(schemas): IntelItem 增加 aliases 字段（只追加不改语义）`

## 四、D3 起的 main 提交门禁

D3 起本项目按 `TEAM-PLAN.md` 单线制协作，不走常规 PR。每个提交必须带对应台账编号；提交前执行 `npm run typecheck && npm test`，契约改动另跑 `python scripts/validate_contracts.py`。CI 失败不得推送。契约冻结签核、两人同意和 CHANGELOG 要求以 `TEAM-PLAN.md` 为准。

## 五、契约改动流程（TEAM-PLAN 当前口径）

1. D6（10/3）完成 v1.1 冻结和三线 sign-off；D3 起直接在 `main` 协作，不单独开 `contract/` 分支。
2. 每次改动先看 `contracts/schemas/CHANGELOG.md`，写清字段影响面、生产者→消费者、破坏性评估和迁移动作。
3. D6 后只允许追加新字段或将旧字段标记 deprecated，禁止改语义、改枚举、删字段；须获另外两位成员各一个明确同意，并追加 CHANGELOG。
4. 每个改动同步 fixture、类型、校验器和回归测试；冲突时暂停并与三线共同确认。

## 六、远端仓库限制（D1-D2 历史设置；D3 单线制不走 PR）

> **平台限制（2026-09-28 实测）**：私有仓库 + 个人 Free 账号无法开启分支保护规则
> （`gh api .../protection` 返回 403：Upgrade to GitHub Pro or make this repository public）。
> 当前以**本地 pre-push 钩子**（typecheck + test + 契约校验，与 CI 同口径）作为合并前门禁；
> 若日后升级 Pro 或将仓库转公开，按下节清单补上保护规则。仓库已建：
> `https://github.com/Niangaol/safetrace`（private，main 为默认分支，CI 已接通）。

```bash
gh repo create Niangaol/safetrace --private --source=. --remote=origin --push
```

当前 TEAM-PLAN 单线制不使用 PR 分支保护；若队内以后恢复 PR 流程，须先修订 TEAM-PLAN 再重新评估此设置清单。现行门禁是本地 pre-push + GitHub CI。

> **仓库可见性：private**。源码按「公开层（文档/契约/评测/脱敏样例）+ 核心层（实现代码）」两域管理，交件只走企业平台审阅（02-report 硬规则 3）。

## 七、本地钩子（随仓库分发，clone 后每人执行一次）

> **2026-09-29（D2）实测修正**：原文写「本仓库已配置，clone 后执行一次即可」，与实际不符——
> `core.hooksPath` 是**每 clone 一次的本地 git config，不随仓库分发**，且 `.githooks/` 下两个脚本
> 入库时**没有可执行位**（`100644`），即使配了 `hooksPath` 也不会执行。此前 20+ 个提交是在
> 无本地门禁状态下进入 main 的。现按下面两步走，缺一不可：

```bash
git config core.hooksPath .githooks   # 1) 每 clone 一次；或 npm run hooks:install
chmod +x .githooks/commit-msg .githooks/pre-push   # 2) 补可执行位（已在入库版本中修正为 100755）
```

验证钩子真的生效：故意提交一条不合规信息，应被 `commit-msg` 拒绝并返回 exit 1。

| 钩子 | 时机 | 行为 |
|---|---|---|
| `commit-msg` | 每次提交 | 校验 Conventional Commits 格式，不合规拒提交（`--no-verify` 可跳过，不鼓励） |
| `pre-push` | 推送前 | 跑 typecheck + test + 契约校验（与 CI 同口径），失败即阻断 push |

## 八、里程碑与标签

| 节点 | 动作 |
|---|---|
| D6（10/3） | 契约 v1.1 冻结；后续只追加字段或标 deprecated，须另两人同意 |
| D20（10/17） | 打 tag `submission-v1`，功能冻结，只修 S1 级缺陷 |
| D22（10/19） | 24:00 前交件；回执双人复核 |
| 决赛前 | tag `submission-v1` 起只做增量分支，main 保持可复现 |

## 九、紧急情况

- 演示前发现 main 坏了：`git revert` 坏提交（不删历史），跑全门禁后按 TEAM-PLAN 推送。
- 需要绕过钩子：仅限「演示现场救急」，事后必须补本地/CI 复核，并在周会说明。
