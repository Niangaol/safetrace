# PR 检查单（GitHub Flow）

> main 永远可演示；所有改动经本 PR 合入。契约改动另见 docs/TUTORIAL.md §8。

## 基本信息
- 类型：<!-- feat / fix / contract / exp / chore / docs / test / refactor / ops -->
- 关联：D<编号> 任务 / issue：
- 负责人与线：<!-- 丙问答+编排 / 甲监测+运维 / 乙富化 -->

## 必过项（CI 同口径）
- [ ] `npm run check` 本地全绿（typecheck + test + validate_contracts）
- [ ] 新增/修改的行为有对应单测；fixture 优先，不依赖真实源
- [ ] 若改 `contracts/`：分支前缀 `contract/`、已更新 `contracts/schemas/CHANGELOG.md`、**三线 sign-off 完成**、只允许「新字段追加 + 旧字段标 deprecated」

## 工程红线（03-roadmap 五条）
- [ ] 无静默兜底：新增降级点均带 `degraded_to` 标记并产生 `FallbackEvent`
- [ ] 无脏数据进底座：Y 线出口产物经 DQ1 判定方可入 S1
- [ ] 无 provider SDK import：模型调用一律经 MG1（role 名，不见厂商）
- [ ] Mock 已写进报告「已知限制」，未把演示态写成完成态

## 脱敏与提交纪律
- [ ] 无密钥 / 真实单位名 / 人名 / 内网地址（PPT 与演示材料同标准）
- [ ] 提交信息符合 Conventional Commits（commit-msg hook 已强制）
- [ ] 演示/录屏类大文件未入库（*.mp4 已被 .gitignore）
