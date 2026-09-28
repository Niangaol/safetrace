# SafeTrace · GitHub Flow 工作流

> 版本 v1（2026-09-28，D1）｜适用范围：三名队员全部代码改动
> 原则来自 03-roadmap 第 7.1 节：**main 永远可演示；契约先行；Fixture 优先；降级显式。**

## 一、总规则

1. **main 永远处于可演示状态**：任何时刻从 main 检出即可跑通 `npm run check` 与冒烟脚本。
2. **所有改动走 PR**：不允许直推 main（远端仓库开启分支保护，见第六节）。
3. **分支短命**：一个分支只干一件事，合入后立即删除；原则上不超过 3 天。
4. **PR 合并方式**：Squash merge（保持 main 历史线性，PR 标题即 Conventional Commit）。
5. **冲突就近解**：合入 main 前先 `git fetch && git rebase origin/main`，不把解决冲突的成本留给别人。

## 二、分支命名（强制）

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

**一键开分支**（自动校验类型并从最新 main 切出）：

```bash
scripts/new-branch.sh feat ingest kev-connector
```

## 三、提交信息（Conventional Commits，hook 强制）

```
<type>(<scope>): <subject>

type: feat|fix|contract|docs|test|refactor|chore|ops|perf|build|ci|release
scope: 模块/线名，如 ingest / gateway / qa / contracts
```

示例：`feat(ingest): KEV 连接器 + Y2 适配器回归 fixture`

契约提交必须显式写影响面，例如：`contract(schemas): IntelItem 增加 aliases 字段（只追加不改语义）`

## 四、PR 规则

1. PR 用仓库模板（`.github/pull_request_template.md`）逐项打勾。
2. **CI 全绿才允许合并**（契约校验 + typecheck + 单测）。
3. 至少 1 名其他队员 review；`contract/` 与 `exp/` 晋升 main 需三线一致。
4. 合并后删分支；远端可在仓库设置里开自动删除。

## 五、契约改动流程（D6 冻结后仍然有效）

1. 分支必须 `contract/` 前缀；改动前先看 `contracts/schemas/CHANGELOG.md`。
2. **只允许「新字段追加 + 旧字段标 deprecated」**，禁止改语义、改枚举、删字段。
3. PR 描述写清：哪些字段、生产者→消费者、破坏性评估、迁移动作。
4. 三线负责人在 PR 上 sign-off（队长/甲/乙），缺一不合并。
5. 合并后当天在群里通报；各线按新契约补 fixture 回归。

## 六、远端仓库设置清单（建仓后由队长一次性完成）

> **平台限制（2026-09-28 实测）**：私有仓库 + 个人 Free 账号无法开启分支保护规则
> （`gh api .../protection` 返回 403：Upgrade to GitHub Pro or make this repository public）。
> 当前以**本地 pre-push 钩子**（typecheck + test + 契约校验，与 CI 同口径）作为合并前门禁；
> 若日后升级 Pro 或将仓库转公开，按下节清单补上保护规则。仓库已建：
> `https://github.com/Niangaol/safetrace`（private，main 为默认分支，CI 已接通）。

```bash
gh repo create Niangaol/safetrace --private --source=. --remote=origin --push
```

GitHub 网页设置（Settings → Branches → Add rule，分支 `main`）：

- [ ] Require a pull request before merging（含 1 approval）
- [ ] Require status checks to pass：选 `check / check`（CI job 名）
- [ ] Require conversation resolution before merging
- [ ] Automatically delete head branches

> **仓库可见性：private**。源码按「公开层（文档/契约/评测/脱敏样例）+ 核心层（实现代码）」两域管理，交件只走企业平台审阅（02-report 硬规则 3）。

## 七、本地钩子（随仓库分发，无需每人配）

```bash
git config core.hooksPath .githooks   # 本仓库已配置，clone 后执行一次即可
```

| 钩子 | 时机 | 行为 |
|---|---|---|
| `commit-msg` | 每次提交 | 校验 Conventional Commits 格式，不合规拒提交（`--no-verify` 可跳过，不鼓励） |
| `pre-push` | 推送前 | 跑 typecheck + test + 契约校验（与 CI 同口径），失败即阻断 push |

## 八、里程碑与标签

| 节点 | 动作 |
|---|---|
| D8 后 | 契约冻结，`contract/` 分支仅允许追加 |
| D20（10/17） | 打 tag `submission-v1`，功能冻结，只修 S1 级缺陷 |
| D22（10/19） | 24:00 前交件；回执双人复核 |
| 决赛前 | tag `submission-v1` 起只做增量分支，main 保持可复现 |

## 九、紧急情况

- 演示前发现 main 坏了：`git revert` 坏提交（不删历史），PR 照走。
- 需要绕过钩子：仅限「演示现场救急」，事后必须补 PR 与 CI 复核，并在周会说明。
