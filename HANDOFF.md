# 首页 → 大屏的跳转（原「地球过场动画」已删除）

> 分支 `demo-v1-python`，仓库 `https://github.com/KKK9747human/safetrace.git`
> 前端在 `web/`。门禁命令均在 `web/` 下运行。

---

## 一、现状（2026-10-01 定稿）

首页点「进入态势大屏」→ **直接 `router.push('/dashboard')`**。
大屏用**静态网格背景**（`.dash-grid`）。

**不再有任何过场动画。** `GlobeZoom.vue` 与 `globeTransition.ts` 已删除。

---

## 二、为什么把过场删掉（试过两版，都有实测结论）

### 版本 A：three.js 地球推进 + 地面网格着色器接力

目标是让动画最后那层"地面网格"与大屏的 `.dash-grid` **逐像素重合**、做到无缝。
逐帧截图量化后发现：

| 检查项 | 实测 |
| --- | --- |
| 相机与网格是否工作 | **正常**（构建产物注入日志：`ground.visible=true`、`uOpacity=1`、`uDilate` 20.91→**1**、`uCenter`→**0**） |
| 网格是否**看得见** | **看不见** —— 线/底对比只有 **2/255**（对照：地球那一帧 35.67、大屏 216） |
| 大屏 `.dash-grid` 自身 | 也是 `rgba(…,0.13/0.16)` → 同样 2/255 |

**即：那条路线在为一个肉眼看不见的网格做逐像素对齐。** 观感必然是
"后半段一片黑、然后突然跳到大屏"。

### 版本 B：克隆 2D 地球 canvas，等比放大；大屏在其上浮现

比 A 简单得多（矢量重绘、放大不糊），但仍踩了一串坑：

1. 放大倍数写死 → 球"放大到一半就停"；叠加带硬边的 `mask-image` →
   外圈被切掉，观感是"**瞬间变小**"。正解：倍数按球实际显示直径算、**不要 mask**。
2. `fixed + z-index` 的浮层若从不退场 → **永远压在 `<main>` 上，点哪都被挡**。
3. 状态只置真不复位 → **返回首页后按钮失效**。
4. 位置在 `appendChild` **之前**量 → 布局未稳、量到偏差 → 球**不居中**。
5. `transition: opacity calc(var(--x) * 0.45)` —— `calc()` 里用变量代入时长是
   **无效值**，逗号列表里一项无效 → **整条 `transition` 作废**，缩放直接跳终态。
6. 更根本的：`transform: … scale(var(--s))` 里 **CSS 自定义属性默认不可插值**，
   变量一变就是瞬时切换 → `transition` 看不到中间值。
   正解：transform / opacity **由脚本直接写字符串**。
7. 导航发生在动画中途（420ms）→ `HomeView` 卸载 → **源 canvas 离 DOM** →
   `getBoundingClientRect()` 全 0 → 放大倍数退化成 1 → **地球不再放大、停在原地**。
   正解：几何量在源还在时**缓存**。
8. 常驻后仍在跑 rAF → 每帧 `drawImage` 一次，**拖慢大屏**。
   正解：常驻时 `cancelAnimationFrame`。
9. 想让背景**持续自转**做不到：`ThreatGlobe` 在 `onBeforeUnmount` 里
   `cancelAnimationFrame`，而导航会卸载 `HomeView`，源随之冻结。
   要解决必须把 `ThreatGlobe` 从 `HomeView` 提到 `App`（不随路由卸载）——
   属于结构性改动。

**用户最终决定：删掉过场，改静态网格。**

---

## 三、大屏的静态网格背景（`.dash-grid`）

`DashboardView.vue` 里：

```css
.dash-grid {
  position: fixed; inset: 0; z-index: -1; pointer-events: none;
  background-image:
    linear-gradient(rgba(56, 189, 248, 0.20) 1px, transparent 1px),   /* 粗层 */
    linear-gradient(90deg, rgba(56, 189, 248, 0.20) 1px, transparent 1px),
    linear-gradient(rgba(125, 211, 252, 0.10) 1px, transparent 1px),  /* 细层 */
    linear-gradient(90deg, rgba(125, 211, 252, 0.10) 1px, transparent 1px);
  background-size: 168px 168px, 168px 168px, 42px 42px, 42px 42px;
  background-position: center center;
  mask-image: radial-gradient(ellipse 120% 90% at 50% 45%, #000 30%, rgba(0,0,0,.35) 62%, transparent 88%);
}
```

**亮度是刻意调的。** 旧值（`0.13 / 0.16`）是为了与动画终态逐像素对齐而压暗的，
实测线/底对比只有 **2/255**（几乎看不见）—— 这正是当初"没有网格背景"的原因。
现在没有对齐包袱，调到 **0.20 / 0.10**，实测对比 **209**。

> ⚠️ 若将来重新引入过场动画，**这组数值就是新的对齐基准**，
> 不要再去迁就别的参数。

---

## 四、容易犯错的点

### 实现

1. **`display: none` 无法过渡** —— 若要收起元素用 `max-height + overflow`。
2. **CSS 变量默认不可插值** —— 用变量驱动 `transform` 时，`transition` 看不到
   中间值；要么用 `@property` 注册类型，要么**直接写字符串**。
3. **`calc()` 里不要用变量代入时长**，会让整条 `transition` 作废。

### 验证环境（这部分最耗时间，先读能省几小时）

4. **替换 `requestAnimationFrame` 会冻死页面** —— Vue/Vite 也依赖它，
   换成"只有我调用才跑"的私有队列后 `page.goto` 连 `domcontentloaded` 都超时。
   正解：保留浏览器自己的 rAF，只接管 `performance.now()`。
5. **虚拟时钟会让动画进度与真实计时器脱钩** —— 我据此一度误判
   "动画 600ms 就结束了"并去找不存在的 bug。**正解：按真实时间截图。**
6. **不要用 `--virtual-time-budget`** —— `performance.now()` 会跳到几万毫秒，
   `elapsed` 直接越过整段动画。
7. **要点对按钮** —— `.panel-go`（"进入态势大屏 →"）是**纯 `RouterLink`**，
   直接跳转、不播动画；触发过场的是 `.hero-btn.primary`。
8. **`page.screenshot()` 能拍到 WebGL，`readPixels` 不能** —— 后者在渲染后
   缓冲区已被清空（`preserveDrawingBuffer` 默认假），读到全 0 属**正常**。
9. 无头 Edge **WebGL 可用**：`--headless=new --enable-unsafe-swiftshader
   --use-angle=swiftshader`；用 `playwright-core` 的 `channel: 'msedge'`，
   **不需要下载浏览器**。
10. 装 `playwright-core` 请装到**仓库之外**（如 `%TEMP%`），
    不要往 `web/package.json` 加依赖 —— 会脏了别人的 lockfile。
11. 在构建产物里注入日志读内部状态是**有效**手段
    （`window.__elog` / `__glog`），但**事后必须 `npm run build` 还原**。
12. **想量化"看不看得见"，用线/底亮度对比（p99 − p50）**，
    比人眼看截图可靠得多。网格这类细线的对比低于 ~10 就是白做。

---

## 五、验收标准（现状）

- 点「进入态势大屏」**直接跳转**，无卡顿、无残留浮层；
- 大屏有**可见的静态网格背景**；
- 反复进出、从大屏返回后**按钮始终可用**；
- 无控制台错误。

门禁（`web/` 下）：`npm run build`、`npm run check:answer-format`、
`npm run smoke:data-source`、`npm run check:ascii-flow`。

---

## 六、如果你还想做过场

走过的路都已记录在上面。若要做，建议顺序：

1. **先决定要不要"地球持续自转"** —— 要的话必须先把 `ThreatGlobe` 提到 `App`，
   这是前置条件（否则源会被路由卸载，克隆体只能拿到最后一帧）。
2. **用真实时间截图逐帧验证**，别用虚拟时钟。
3. 每加一个效果就量一次**线/底对比**或**尺寸/球心**，不要靠肉眼。
