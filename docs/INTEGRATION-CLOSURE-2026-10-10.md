# SafeTrace 接线续修与验收边界（2026-10-10 晚间）

> 本文保留前序发现作为历史记录。工单原子性/检查点/问答身份等已于后续轮继续修复，当前结论以 [2026-10-11修复与质量验收](REPAIR-QA-QUALITY-2026-10-11.md) 为准，不能将下面旧待办或旧测试数当当前状态。

本轮续修针对生产入口未接线与自愈误销档，不改冻结公共契约，不操作正式数据库，不启动付费模型或 72h 挂机。

## 本轮已验证

- A-02：实际启动入口 [qa-decision-server.ts](<../scripts/qa-decision-server.ts>) 注入与事件总线共用的 SQLite ticketStore；[stepfun-decision.ts](<../src/qa/src/ladder/stepfun-decision.ts>) 将该选项传到阶梯。
- [HTTP 集成回归](<../src/qa/test/decision-ticket-http.test.ts>) 4 项：真实 loopback HTTP → 未决工单落 SQLite → 重开库 → 接单/人工决单 → decision.replies 留存；规则已决/非法请求不入队；工单存储失败 HTTP 503；启动脚本注入的静态守护。测试没有启动长期生产进程，最后一项只是源码装配检查。
- HTTP 响应仍是原 DecisionReply，没有追加 ticket_id；工单 ID 为 ticket_<decision_id>，可用 human:queue 查询。本轮仅证明工单不重复入队、不重新打开，**不证明回复事件端到端幂等**。
- A-06：总线 redeliver 无实际消费者时返回 false，保留死信；退订后的空消费者集合也不能触发销档。真实消费者全部成功后才清除死信，不重复追加事件。
- [死信重投回归](<../src/shared/test/dead-letter-redelivery.test.ts>) 3 项覆盖内存/SQLite、独立总线无人消费、退订、守护单拍恢复计数与真实消费成功后清理。
- npm run check exit 0：typecheck、全量 **766/766（0 失败/0 跳过）**、契约校验、Web 安装/构建/前端 smoke 全过。新增 7 项。Web 大包警告仍存在，不影响本次构建通过。

## 必须保留的未闭环边界

“九项修复已有代码和测试”不等于“生产全链路九项全部验收”。此前总结中的「全部修完」口径过宽，当前按以下边界解读：

1. **A-02 并发决单一致性（优先继续修）**：现有人工决单先 publish 后竞争销单；竞争失败者的结果可能已发布到总线。需原子提交/条件占用与持久回执，不能仅靠 CLI/单线程测试宣布闭环。
2. **A-02 回复语义**：已 resolved 的 decision_id 重发，工单不会重开，但仍可能收到 abstain。需按请求身份核验已有回执，再返回既有人工结果；不能把工单级幂等写成请求级幂等。
3. **A-02 入队部分失败**：当前未决回复先发布再入队，入队失败虽 HTTP 503，仍可能留下未关联工单的回复事件；需事务/可恢复 outbox。questions/kind/trace 冲突重用 decision_id 也待核查。
4. **A-06 跨进程恢复**：EventBus 订阅仅在当前进程内有效。独立守护脚本只有 fallback 订阅，既不会自动获得其他进程的消费者，也不会自动收到其他进程新发布的 fallback。此次仅防止无消费者误销档；业务消费者应与恢复逻辑同进程装配，或另建明确的跨进程传递机制。
5. **P-03/P-05**：版本判定/来源冲突的本地演示接线与模板能力已经测试，但 live-intel-server 的冲突持久回放及版本入口不能视为全部验收。
6. **A-01 / E-07**：检查点基础测试通过不等于并发恢复安全、图版本绑定及所有业务恢复入口均已验收；72h 运行证据仍未产生。
7. **向量链**：此前本机 bge-m3 + Qdrant 验证成功只是链路证据；默认 cache 配置仍不提供语义能力。服务按用户要求保持停止；人工标注准确率、长时间保鲜与模型切换等仍需专项验证。

三线 sign-off 必须由真实成员确认。本轮不追加契约；P-05 source_conflicts 的登记版本是 [CHANGELOG v1.2.2](<../contracts/schemas/CHANGELOG.md>)，不是此前回复误写的 v1.1.2。

## 工单操作入口

服务与 CLI 使用同一 SQLITE_PATH：

~~~bash
npm run qa:decision:serve
npm run human:queue -- list --status pending
npm run human:queue -- claim ticket_<decision_id> <reviewer>
npm run human:queue -- decide ticket_<decision_id> <reviewer> --choice <option> --reason <rationale>
~~~

启动决策服务可能加载本机环境配置；本轮验收仅用无模型调用的临时 SQLite 与短期 loopback 测试服务，不启动上述常驻服务。
