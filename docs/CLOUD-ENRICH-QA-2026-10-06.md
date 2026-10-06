# 云端模型接入、富化补批与问答展示改造（2026-10-06）

> 本轮目标：连上云端模型并实测；富化继续做实；问答展示加动画；回答结果支持 Markdown 渲染与链接点击跳转。

## 1. 云端模型：真实连通并验证

通过设置页同一条链路完成（保存草稿、测试连接、明确启用），未改动任何凭据存储方式：

- 凭据来自本机 .env.local（TOKENDANCE，OpenAI 兼容中转，HTTPS）。密钥只存在于服务端加密草稿，不在前端、日志、URL 或响应里出现。
- /models 实测返回 100 个可选模型；选用 glm-4.7。
- 一次真实问答实测：answer_mode=cloud、model=glm-4.7、model_calls=1、abstained=false、3 条引用、回答含官方链接。

修掉的两个真实缺陷（都是本轮联调暴露的）：

1. 传输层 socket 超时写死 10 秒，而该云端模型响应约 15 秒，请求被掐断后网关静默回落 cache。现改为可配置且有界（1 至 120 秒夹取），云端回答通道传 70 秒，回答角色自带 60 秒上限作为第一道闸。
2. 回答角色原先配 10 秒超时，同样偏短；已改为 60 秒。

失败时会明确回落到规则模板，并在界面标注“模型未可用 - 规则模板兜底”，不是假成功。

## 2. 富化：又一批“有原文证明”的评分发布

- 先建并独立验证备份（.tmp/verified-backups/safetrace-XtzQCs：9 张表、5237 向量、6 个原始 payload、missing_raw_refs=0），再执行离线复核。
- 新增复核并发布 50 条 NIST 主 CVE v3.1 评分（累计 50 条不同情报有可证明工件；此前 10 条因超过 24 小时刷新窗口被重新复核并发布新事件，属预期行为，无丢失）。
- 全程 network_calls=0、model_calls=0、vector_writes=0；未验证原文不能借用其它来源的证明，已有已验证论文/EPSS 会被保留并原子重绑。
- 复核后抽查 4 个 CVE 的问法，均能给出带官方链接引用的回答（问法触发“需澄清”时按门禁拒答，不硬答）。
- 第三条维度（修复建议）在只读接口可见：来源为 CISA KEV / Ubuntu USN，标注 readonly-source-derived 与“厂商/机构声明，非已验证修复”，并带证据链。

## 3. 问答展示：Markdown 渲染 + 链接跳转 + 动画

- 新增安全 Markdown 渲染（web/src/markdown.ts）：标题、列表、引用、代码块、分割线、粗斜体、行内代码、链接；不使用 v-html，链接只允许 http/https（拒绝 javascript:、data:、vbscript:、大小写混淆与控制字符），空源码与超长输入都有明确降级。
- 回答区改为 Markdown 渲染：标题层级、引用块（逐字证据）、列表、代码块都有样式；回答里的“原文链接”可点击，target=_blank 且 rel=noreferrer noopener。
- 引用列表逐条错落入场，并显示来源域名（如 services.nvd.nist.gov），点击新窗口打开原文。
- 生成过程中显示光标；回答容器首次出现时淡入；全部尊重“减少动态效果”与设置页动效开关。

## 4. 验证

- 全量门禁：npm run check 562/562（0 失败 0 跳过，含 typecheck、8 schema / 12 fixture、清理依赖后的 web 构建）；npm run smoke 全段通过。
- 前端冒烟：smoke:effects 13 项、smoke:markdown 41 组 / 219 项断言（含真实 SSR 渲染）、smoke:activity 11 项、smoke:data-source 8 项，全部通过。
- 真实浏览器（Tabbit + 真实后端）终验：云端模式标识、Markdown 标题 5 处 / 引用块 7 处 / 列表 1 处、回答内 3 条可点击原文链接（target=_blank、rel=noreferrer noopener）、3 条引用带来源域名标签、回答容器 fx-rise 入场、引用 fx-slide-in 逐条入场、生成中光标与阶段条均实测可见。
- 修复建议维度接口抽查：来源 CISA KEV，标注 readonly-source-derived 与“厂商/机构声明，非已验证修复”。

## 4.1 新增文件

- web/src/markdown.ts：安全 Markdown 解析（纯函数，零依赖，不产出 HTML 字符串）
- web/src/components/MarkdownBlock.vue：Vue 渲染层（零 v-html，链接仅 http/https）
- web/scripts/smoke-markdown.mjs：解析 + SSR 组件 + 安全降级回归
- src/gateway/src/settings-transport.ts：可配置有界传输超时（修复 10 秒硬编码导致云端回落）
- scripts/model-settings-controller.ts：回答角色 60 秒超时、云端通道 70 秒传输预算
- web/src/views/QaView.vue：Markdown 回答、可点击引用与域名、逐条入场与生成中光标
- docs/CLOUD-ENRICH-QA-2026-10-06.md：本文件
