# P-10 本地验证与单页入库

## 无网络验证
- `npm run page:demo`：模拟网页→规则→DQ1→SQLite→证据块→BM25，输出 `mock: true`。
- `npm run pilot:doctor`：只读 loopback GET，不生成 embedding、不代替真实模型验收。

## 授权域名单页预览
PowerShell：先以实际授权域名/URL替换示例，默认不开 DQ1 入库。
```powershell
$env:FIRECRAWL_ENABLED = "true"
$env:FIRECRAWL_ALLOWED_HOSTS = "vendor.example"
$env:PAGE_INGEST_ENABLED = "false"
npm run crawl:page -- https://vendor.example/advisory
```
始终执行 HTTPS/精确域名/robots/重定向安全门禁。Firecrawl key 未配置时不走云抓取，设置 key 后兜底可能按页收费。

## 显式 DQ1 入库
操作方须核对元数据文件，日期不能用抓取时间代替，评级 0.9 仅是示例。尖括号须手动替换。
```json
{
  "source": {
    "source_id": "authorized_vendor_id",
    "source_type": "vendor_advisory",
    "url": "https://vendor.example/advisory",
    "status": "active",
    "poll_interval_s": 3600,
    "rate_per_min": 5,
    "requires_api_key": false
  },
  "published_at": "<实际首次发布日期，ISO8601且带时区>",
  "source_reliability": 0.9
}
```
```powershell
$env:PAGE_INGEST_ENABLED = "true"
$env:PAGE_INGEST_METADATA = "<本地元数据JSON文件路径>"
npm run crawl:page -- https://vendor.example/advisory
```
缺失文件、非法JSON、缺元数据或URL不匹配在联网前拒绝并留溯源记录。stale、待复核、证据不符或DQ1 review/quarantine不自动发布。CLI只接规则抽取，A-03/A-04通过前不接真实网页LLM。
操作方的单页来源声明不会修改全局SourceRegistry，也不会启用定时任务。成功输出accepted/dq_verdict/source_chunks，但index_status仍为not_indexed：不发问答、不调用embedding、不写Qdrant。原文通过EventBus的sqlite-page哈希快照读取，文件式富化仍待适配。

## 审计与剩余限制
```powershell
npm run review:queue -- list
npm run trace:lineage -- <trace_id>
```
保持各进程SQLITE_PATH一致。人工决定只更新审核状态，不自动产生IntelItem。历史原文不被最新缓存覆盖，但SQLite不是WORM，部署需制定备份/保留策略。
默认配置仍cache/hash；2026-09-30 已以用户提供的 Tokendance 服务单文本验证 qwen3.7-text-embedding，API和MG1均返回1024维且无降级。本地Qdrant仍不可达，写入重启读取、引用与语义质量检查尚未验收。运行 `npm run embedding:verify -- --live` 会加载忽略的 .env.local 并发一条可能计费的合成 embedding 请求；不传 --live 不调用模型。doctor只做本地GET，不探测云端，因此它的 skipped 不能否定这次显式API实测。来源向量入库有独立SAFETRACE_INDEX_QDRANT开关，拒绝离线/fixture降级。
