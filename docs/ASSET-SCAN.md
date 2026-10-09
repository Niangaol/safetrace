# 本地资产扫描（A 线）· 设计与使用

> 2026-10-09 落地。对应诉求：「扫描本地项目/git 仓库，建立技术栈快照，每当有相关漏洞被发现时，创建一个提醒」。
> 这条线同时补上 F2 资产定位最大的 Mock 缺口——PROJECT-INTRO 的核心场景「Ollama 漏洞影响我们哪些在跑的服务？」从此有真实本地资产可答。

## 1. 一句话原理

扫本机仓库 → 解析依赖清单 → 和本地情报库做确定性匹配 → 命中就落一条提醒。

    config/assets-scan.json（扫描根/限制）
            │
            ▼
    scanner.ts 遍历目录
      - 发现 git 仓库（有 .git）/ 非 git 项目（有 manifest）
      - 读 manifest：package.json / requirements.txt / pyproject.toml /
        go.mod / Cargo.toml / pom.xml / composer.json / Gemfile /
        Dockerfile / docker-compose / .github/workflows
      - git 元信息：remote（脱敏）/ branch / HEAD（本地只读子命令）
            │  Component{ecosystem, name, version, 约束原文}
            ▼
    store.ts → var/assets.sqlite
      - scan_runs / repos / components / alerts / meta
      - 告警 UNIQUE(component_key, cve_id)：同一组件同一 CVE 只提醒一次，
        重复扫描/重复匹配天然幂等
            │
            ▼
    matcher.ts（复用 F2 f2-assets 的版本比较原语）
      - 产品名归一 → 版本解析 → 版本区间判定
      - affected / not_affected / unknown 三态，不猜结论
            │  affected → alerts 表（status=new）
            ▼
    触达用户的三个出口
      ① Web：TopNav 铃铛角标 + /assets 页提醒列表
      ② CLI：npm run assets:scan 打印报告
      ③ watch 常驻：新情报入库后自动匹配（15 分钟节流）

## 2. 合规边界（与项目红线一致）

| 红线 | 本线的落实 |
|---|---|
| 不扫未授权目标 | 只读本地文件与 git 本地元信息（remote get-url / rev-parse / log 都是本地子命令），零网络探测、零目标探测 |
| 不猜影响结论 | 版本无法解析、情报缺版本区间、版本只是范围下界且未命中 → 一律 unknown，不产生"不受影响"的假结论 |
| 降级必须显式 | git 全部不可用 → degraded_to=git_unavailable；超时 → timeout；目录不可读 → read_error；触顶 → repo_limit/component_limit。全部落库并在 UI/CLI 可见 |
| 脏数据不进底座 | 资产库是独立的 var/assets.sqlite，不碰情报事件库的表与契约；*.sqlite 已被 .gitignore 覆盖 |
| 厂商身份 | 本地扫描不携带厂商身份 ⇒ 所有结论 vendor_unverified=true，理由文案必须带上 |

## 3. 版本语义（最要紧的设计决策）

manifest 里的约束分三种，匹配行为不同：

| 约束原文 | version 字段 | version_is_range_floor | 匹配行为 |
|---|---|---|---|
| 1.7.2 / ==3.0.0 / v1.9.1 / 20-alpine | 字面量 | false | 正常三态判定 |
| ^3.5.0 / ~5.7.0 / >=2.0 | 下界字面量 | true | 命中 → affected 且理由带「实际安装版本可能更高」；未命中 → unknown（不猜实际版本） |
| * / 1.x / Maven 属性占位 / 空 | 空 | true | 直接 unknown「组件未锁定具体版本」 |

为什么未命中要降级成 unknown：^1.0.0 的实际安装版可能是 1.9.0，advisory 的受影响窗口 1.2.0–1.4.0 正好落在下界之外——这时说 not_affected 就是猜。宁可 unknown，不可错报。

## 4. 数据从哪来、提醒为什么现在可能是空的

提醒匹配的情报来自本地已入库的 IntelItem（var/safetrace.sqlite 的 intel.items 事件）。
2026-10-09 排查发现一个采集侧历史缺口：NVD 适配器此前把 entities.version_range 写死为空数组，
导致 9280 条已入库情报没有一条带版本区间——没有区间，匹配器只能给出 unknown，提醒自然为空。

本轮已修复 NVD 适配器（src/ingest/src/adapters/nvd.ts）：
从 configurations[].nodes[].cpeMatch[] 的 versionStart/EndIncluding/Excluding 与 version 提取区间，
格式与 cveorg/OSV 适配器一致（如 ">=1.0 <2.0"、"<=2.14.1"、裸版本），F2 的 parseRange 可直接解析；
提不出时不臆造，置空并留 warning。

存量 9280 条不会自动变出新区间（事件库 append-only）。刷新方式（需要 NVD key、会写事件库，执行前先备份）：

    npm run backup:intel                                              # 先备份
    node --import tsx src/ingest/src/cli/watch.ts -- --source nvd_cve --once   # 重跑 NVD 源

## 5. 怎么用

### 5.1 命令行

    npm run assets:scan                        # 扫描所有启用分组 + 匹配 + 落库
    npm run assets:scan -- --group safetrace   # 只扫指定分组（见 §6.2）
    npm run assets:scan -- --json              # 机器可读输出
    npm run assets:scan -- --no-match          # 只扫描不匹配

### 5.2 Web

- 导航栏「本地资产」→ /assets：扫描摘要、立即扫描按钮、漏洞提醒 / 仓库快照 / 组件清单三个页签。
- 顶栏铃铛显示未读提醒数（15s 轮询 /api/v1/assets/overview），点击进入资产页。
- 提醒可单条/全部标记已读；已读后同一 CVE 再次命中不会复活（去重键不变）。

### 5.3 常驻自动匹配

node --import tsx src/ingest/src/cli/watch.ts 启动时立刻匹配一次（幂等），
之后每轮采集有新增（merged > 0）且距上次匹配超过 15 分钟时自动匹配。
匹配失败只记日志、不打断采集；没有快照时明说「先执行一次扫描」。

### 5.4 API（live-intel-server，:8000）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | /api/v1/assets/groups | 分组列表 + 实时统计（未读/仓库/组件/最近扫描） |
| GET | /api/v1/assets/overview?group_id= | 摘要 + 未读数 + 最新 20 条新提醒（缺省全部组聚合） |
| GET | /api/v1/assets/repos?group_id= | 仓库列表（缺省所有分组最新快照） |
| GET | /api/v1/assets/components?group_id=&ecosystem=&q=&limit=&offset= | 组件清单 |
| GET | /api/v1/assets/alerts?group_id=&status=new 或 seen | 提醒列表（severity/title 由实时视图富化） |
| POST | /api/v1/assets/scan，body {group_id?: "all" 或分组 id} | 触发扫描+匹配（要求本机页面来源 localOrigin） |
| POST | /api/v1/assets/groups，body {group_id, name, roots, enabled?, note?} | 新建/更新分组（localOrigin） |
| POST | /api/v1/assets/groups/delete，body {group_id} | 删除分组定义，历史留痕（localOrigin） |
| POST | /api/v1/assets/alerts/read，body {ids?} 或 {group_id?} | 标记已读（localOrigin） |

## 6. 配置与多文件夹分组监控（config/assets-scan.json）

    {
      "groups": [
        { "id": "safetrace", "name": "SafeTrace 本仓库", "roots": ["."], "enabled": true, "note": "竞赛主工程" },
        { "id": "agentprograms", "name": "AgentPrograms 项目群", "roots": [".."], "enabled": true, "note": "本机其他项目聚集地" }
      ],
      "limits": { "maxDepth": 6, "maxRepos": 400, "maxComponents": 5000, "manifestDepth": 5, "timeoutMs": 120000 },
      "skipDirNames": []
    }

- roots 支持相对仓库根与绝对路径；同一目录可出现在多个分组（各自独立快照与提醒）。
- 兼容旧平铺格式 { "roots": [...] }：自动包装为单个 default 分组。
- 完全没有配置时播种两个默认组：SafeTrace 本仓库 + 上一级目录。
- 环境变量 SAFETRACE_SCAN_ROOTS（PATH 分隔符）仅在无配置文件时生效。

### 6.1 分组是运行时数据，不只是配置

分组定义的运行时真相源是 var/assets.sqlite 的 groups 表：config/assets-scan.json 只在 groups 表为空时播种一次，之后以 Web 资产页「分组管理」/ API 为准（增删改、停用都不碰 git 仓库里的配置文件）。每次扫描轮次、每个仓库、每个组件、每条告警都带 group_id，按组隔离：

- scan_runs/repos/components：各组只读自己最新一轮快照；
- 告警去重键是 group_id + component_key + cve_id——同一组件同一 CVE 在每个分组各提醒一次（分组即监控边界）；
- 停用（enabled=false）的分组不参与「扫描全部组」与 watch 常驻自动匹配，历史数据保留。

### 6.2 分组的用法

    npm run assets:scan -- --list-groups     # 列分组（含仓库/组件/未读统计）
    npm run assets:scan -- --group safetrace # 只扫指定分组
    npm run assets:scan                      # 扫所有启用分组
    npm run assets:scan -- --json            # 机器可读输出

Web：/assets 页顶部分组下拉（全部组 + 各分组，带未读角标）→「分组管理」面板可新增/编辑/停用/删除。API：GET /api/v1/assets/groups（列表+统计）、POST /api/v1/assets/groups（增改）、POST /api/v1/assets/groups/delete、各只读接口都支持 ?group_id= 过滤。

## 7. 已知限制（诚实清单）

1. 存量情报无版本区间：见 §4，刷新 NVD 源后提醒才会大量激活；当前匹配逻辑本身已被 32 个单测 + 合成情报端到端验证。
2. 多产品 CVE 的区间混合：一条情报的 cpeMatch 可能覆盖多个产品，区间按 OR 合并（cveorg 适配器同款限制）；产品名精确匹配 + 厂商未核实已尽量收敛误报。
3. npm 作用域包：@scope/name 会同时尝试去掉作用域匹配（advisory 常记裸名）。
4. 不在问答链路：快照暂未投影进 Qdrant 知识底座（components 表可直接投影）；问答答「影响我们哪些服务」需要那次投影，列为后续项。
5. 扫描范围默认本机：roots 配什么扫什么，敏感目录不要配进来；远程地址凭据已脱敏，但路径本身会落库（库文件不进 git）。

## 8. 测试与门禁

- src/assets/test/：manifests / scanner / matcher / store 四组共 32 条（fixture 驱动、注入 gitRunner、零网络）。
- src/ingest/test/adapters.test.ts：新增 2 条 NVD 区间提取用例。
- 全量 npm test 620/620、npm run typecheck、npm run validate:contracts、web build + smoke 全过。
