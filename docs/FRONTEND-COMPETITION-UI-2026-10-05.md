# 赛题重点前端与模型设置 / 实时拟物工作台（2026-10-05）

> 本轮改动围绕赛题九三条主线：多源可核对监测、富化质量与证据、可引用问答与 Agent 过程；另加真实处理事件驱动的拟物工作台。默认不调用云模型、不下载模型、不动正式富化/向量/采集。

## 1. 页面与信息架构

顶栏已改用赛题口径（[TopNav.vue](D:/AgentPrograms/safetrace/web/src/components/TopNav.vue)：工作台、富化与证据、多源采集、证据问答、设置）。页面横幅按后端返回的 data_mode 与 qa_mode 显示，不写死任何模式：

- 正式库只读视图：读当前已放行情报及有来源证明的富化工件；旧记录未核验不算成功。
- 检索 BM25；问答模式如实显示为规则模板 / 云端 / 本地 / 失败回退模板。
- 资产匹配与 PoC 自动复现、真实准确率与多轮语义显示为未实现或尚未验收，不用数字美化。
- [CompetitionFocus.vue](D:/AgentPrograms/safetrace/web/src/components/CompetitionFocus.vue) 把三模块工作流与当前可信缺口放页首，弱化误导性装饰指标。

新增[模型设置页](D:/AgentPrograms/safetrace/web/src/views/SettingsView.vue)与[独立客户端](D:/AgentPrograms/safetrace/web/src/settings-api.ts)。页面明确：保存草稿、测试连接、明确启用三件事互相独立；测试只访问 /models，不生成回答。

## 2. 模型设置：安全与真实接线

存储层 [runtime-settings-store.ts](D:/AgentPrograms/safetrace/src/gateway/src/runtime-settings-store.ts) 负责私密 AES-GCM 加密本地草稿、激活快照与版本；空 api_key 保留旧密钥，换 Base URL 自动清密钥；拒绝本机地址、内网、IP、明文 http、URL 带令牌或查询串的云端地址。

传输层 [settings-transport.ts](D:/AgentPrograms/safetrace/src/gateway/src/settings-transport.ts) 只允许访问已保存 Base URL 的 /models 与 /chat/completions；密钥只以 Authorization 头发往该 origin；云端默认公网 DNS 解析加 TLS 绑定并拒绝重定向；本机只接受字面 loopback，并明确禁止访问 6333/8000/5173/19387 管理端口。

控制面 [model-settings-controller.ts](D:/AgentPrograms/safetrace/scripts/model-settings-controller.ts) 对 GET 不要求令牌；写操作需同页内存 CSRF 令牌、JSON、同源 Origin 与本机 Host；启用云端要求 confirm_cloud_usage 为 true；本地受管模式必须就绪且文件与参数与激活快照一致；模型输出只能做逐字引用，逐字校验失败即整条失败回退模板。

敏感本地数据 var/runtime-settings/（含加密密钥）已加入 .gitignore。密钥不写浏览器存储、不回显、不写日志；清除密钥会同时强制停止云端模式。真实出网或真实加载必须由用户显式测试或启用触发，不会随保存、启动、采集自动调用。

## 3. 本地 GGUF：受控运行时

[local-model-runtime.ts](D:/AgentPrograms/safetrace/src/gateway/src/local-model-runtime.ts) 只从服务端可信根目录内枚举已有 .gguf（深度与数量有界，只读 4 字节 magic），不上传、不下载；启动限于 llama-server(.exe) 绝对路径、固定别名 safetrace-local-chat、上下文 512 至 16384、GPU 层 0 至 99，shell:false、非 detach、仅监听 127.0.0.1。

- 只管理自己 spawn 的子进程；端口已被别的服务占用显示外部或未托管，不接管、不杀别人进程。
- 就绪判定需 health.status 为 ok 且 /v1/models 返回固定别名；加载上限 120 秒，之后标失败。
- 本轮实测连接本机已有 llama 服务并真实读到模型 ID；未再启动第二份 GGUF（当时内存仅剩约 1.2GB，不强行加载 7B）。加载与停止的生命周期在隔离测试中覆盖。

## 4. 实时拟物工作台

[ActivityBoard.vue](D:/AgentPrograms/safetrace/web/src/components/ActivityBoard.vue) 与 [activity-api.ts](D:/AgentPrograms/safetrace/web/src/activity-api.ts) 以 SSE 订阅[真实处理事件流](D:/AgentPrograms/safetrace/scripts/activity-stream.ts)。来源只有两个：持久 lineage 记录与本轮真实问答事件；都不伪造数据包，不用循环动画冒充实时。

- 卡片按 trace_id 与 intel_id 聚合；纸张、胶带、印章与工位动画只在收到新事件时触发；一次最多 8 卡，500 条详情上限，超出显式提示不再展示旧详情，累计计数仍保留。
- 真实字段（source_id / source_type / elapsed_ms / artifact_count / reason）走 hover、focus 与移动端展开；intel_id 为 null 明确标为来源批次。
- 历史回放与实时新增严格区分；断线、游标过期、积压超 500 显式 reset；无事件时显示等待真实活动落纸，不编造。
- 隔离、降级、失败各有对应印章（通过、待复核、拒收、降级、失败），并尊重 prefers-reduced-motion。

实测证据：在真实浏览器对本机后端发起一次真实问答，工作台实时收到 3 条 origin 为 live 的新事件（问答接收、检索、问答出站），累计计数由 26 历史升到 29；卡片字段与后端返回 JSON 逐字一致。

## 5. 安全审查与回归

独立审查提出 4 项 P1，全部修复并补了负例：

1. 官方 URL 加任意 64 位 hash 不能把未验证来源自动升级为可信；必须与当前已证明证据逐字段逐哈希匹配。
2. 模型输出只能做逐字引用；把证据 9.8 说成 0.0 这类新结论会被拒绝并回退模板，不会携带官方引用与置信度。
3. 未 apply 的新模型不能替换已启用快照；active 与 runtime 文件 ID 或加载参数不一致直接拒绝。
4. 缺 Host 校验可被 DNS rebinding 同源读取；现要求字面 loopback 加端口匹配，恶意 Host 实测 403。

同时补齐：断开重连的大积压显式 reset 且不标 live、坏 JSON 不推进游标、DB 恢复后初始历史不会冒充 live、模型失败回路仍如实累计 model_attempts，不再用最终 answer_mode 反推。

## 6. 验证与边界

- npm run check：562 项测试，0 失败 0 跳过；typecheck、8 个 schema、12 个 fixture、前端构建（含清依赖后的 npm ci --prefix web）通过。
- npm run smoke、npm run smoke:activity --prefix web、npm run smoke:data-source --prefix web 全部通过。
- 浏览器验收使用真实后端：工作台、设置页、云端与本地测试连接、保存与明确启用、真实本地模型回答与失败回退均实测；完成后已恢复默认离线模板，不保持任何模型自动调用。
- 未验证或未实现：云模型真实生成答案（未配置真实云端凭据）、第二份本地 7B 托管加载与压力、多轮语义问答、真实准确率人工盲测、资产定位与 PoC 自动复现。
- 日志：.tmp/competition-ui-delivery-gates.log、.tmp/competition-ui-delivery-smoke.log、.tmp/competition-ui-delivery-activity.log、.tmp/competition-ui-delivery-web.log。
- 用户其它文档改动（README / PROJECT-INTRO / ROADMAP / TASKS）未并入本批改动，仍留在工作区。
工作台与设置页实测截图：[.tmp/ui-preview/workbench.png](D:/AgentPrograms/safetrace/.tmp/ui-preview/workbench.png)、[.tmp/ui-preview/settings.png](D:/AgentPrograms/safetrace/.tmp/ui-preview/settings.png)。
