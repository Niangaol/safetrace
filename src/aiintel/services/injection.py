"""A-04 注入防护：检测外部文本里的**提示注入**迹象。

## 为什么需要它

采集来的内容是**外部可控文本**（厂商公告、社区帖、PoC 仓库 README），
它们会进检索、再进 LLM 的上下文。攻击者可以在里面埋"忽略以上指令"这类文字，
让模型把注入内容当指令执行 —— 这就是提示注入。

本仓此前的状态：`injection_guard.screened` **恒为 False**，
契约明说"缺省 = 未筛查，禁止当作已筛查且干净"。本模块把 `screened` 翻成 `True`。

## 口径来源

十类枚举**不是我自己定的**，是上游契约 `QualityVerdict.injection_flags` 定义的
（`contracts/events.md` 内联契约 + `LocalPayloads.json`）：
`instruction_override` / `role_confusion` / `zero_width_chars` / `base64_hidden` /
`html_entity_encoded` / `comment_embedded` / `exfil_instruction` /
`fake_system_prompt` / `citation_spoof` / `multi_stage`。

本仓独立实现检测，但**枚举取值与上游逐条对齐**，将来两边可比对。

## 设计原则：宁漏不误

**这不是"尽量多抓"的任务。** 本仓语料是安全公告与攻击技术论文，
里面天然充满 `ignore`、`system prompt`、`base64`、`<!-- -->`、shell 命令
这类字眼 —— 一个宽松的规则会把正常公告全部标红，然后所有人学会忽略告警。

所以每条规则都**要求共现或结构特征**，而不是命中单个关键词：
- `instruction_override` 必须是"祈使动词 + 指令对象"共现；
- `base64_hidden` 要求长 base64 段**且**伴随解码类动词；
- `exfil_instruction` 要求外发动词**且**伴随可达地址或敏感对象。

误报代价（把正常内容标成可疑）**高于**漏报代价（少标一条），
因为前者会让整个信号失真。这个取舍写在这里，便于日后调阈值时有依据。

## 评分

`injection_score` 取**命中规则中的最大权重**（不是求和）：
求和会让"命中 5 条轻微规则"胜过"命中 1 条决定性规则"，
而后者才是真正危险的。封顶 1.0，契约要求落在 [0, 1]。
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any

#: 十类注入迹象的权重。权重反映"这条证据本身有多强"，
#: 而不是"这个手法多常见"—— 常见的手法（如指令覆盖）恰恰容易误报。
FLAG_WEIGHTS: dict[str, float] = {
    "instruction_override": 0.9,
    "fake_system_prompt": 0.9,
    "exfil_instruction": 0.85,
    "role_confusion": 0.7,
    "citation_spoof": 0.6,
    "multi_stage": 0.6,
    "base64_hidden": 0.55,
    "html_entity_encoded": 0.45,
    "comment_embedded": 0.4,
    "zero_width_chars": 0.4,
}

#: 判定为"可疑"的评分阈值。低于它只登记 flags，不改 verdict。
SUSPICIOUS_THRESHOLD = 0.5

# ---------------------------------------------------------------- 规则

#: ① 指令覆盖：祈使动词 + 指令对象**共现**。
#: 只写 `ignore` 会命中"ignores the lock"这类正常描述；只写 `instructions`
#: 会命中满篇的"installation instructions"。必须两者同现。
_INSTRUCTION_VERBS = r"(?:ignore|disregard|forget|override|bypass|skip)"
#: 指令对象。`all`/`any`/`the` 等限定词必须**可选且可重复**：
#: 早期写成 `(?:all\s+)?(?:previous|...)` 只允许 "all previous" 一种顺序，
#: 于是 "ignore the previous instructions" 这类常见写法全部漏检
#: —— 由反向/正向测试抓出来（`test_instruction_override` 失败）。
_INSTRUCTION_OBJECTS = (
    r"(?:all\s+|any\s+|the\s+|these\s+|those\s+|your\s+)*"
    r"(?:previous|prior|above|earlier|preceding|foregoing|system|initial|original)"
    r"\s+(?:instruction|prompt|rule|direction|command|message|context)s?"
)
_INSTRUCTION_OVERRIDE_RE = re.compile(
    rf"\b{_INSTRUCTION_VERBS}\b[^.\n]{{0,40}}\b{_INSTRUCTION_OBJECTS}\b"
    rf"|\b{_INSTRUCTION_OBJECTS}\b[^.\n]{{0,20}}\b(?:are|is)\s+(?:no\s+longer|void|invalid)",
    re.I,
)

#: ② 角色混淆：对话模板标记（ChatML / Llama / 通用分隔符）出现在**外部文本**里。
#: 正常公告不会带 `<|im_start|>` 这类 token。
_ROLE_TAGS = (
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|user|>",
    "<|assistant|>",
    "[INST]",
    "[/INST]",
    "<<SYS>>",
    "<</SYS>>",
)
_ROLE_CONFUSION_RE = re.compile(
    "|".join(re.escape(t) for t in _ROLE_TAGS)
    + r"|^\s*(?:system|assistant)\s*:\s*you\s+(?:are|must|will)\b",
    re.I | re.M,
)

#: ③ 零宽字符：正常文本不该出现。U+200B/200C/200D/2060/FEFF
_ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")

#: ④ base64 藏内容：长 base64 段 **且**伴随解码类动词。
_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_B64_VERBS_RE = re.compile(
    r"\b(?:base64|b64|decode|decoding|decode\s+and\s+(?:run|execute)|atob)\b", re.I
)

#: ⑤ HTML 实体编码：成串的实体（5 个以上）—— 单个 `&amp;` 是正常转义。
_HTML_ENTITY_RE = re.compile(r"(?:&#\d{2,5};|&#x[0-9a-f]{2,4};|&[a-z]{2,8};)", re.I)

#: ⑥ 注释里藏指令：HTML/代码注释 **且**注释内容含指令性措辞。
_COMMENT_RE = re.compile(r"<!--(.*?)-->|/\*(.*?)\*/", re.S)
_COMMENT_INSTRUCTION_RE = re.compile(
    r"\b(?:ignore|instruction|prompt|system|assistant|execute|run|you\s+must|do\s+not\s+tell)\b",
    re.I,
)

#: ⑦ 外发指令：外发动词 **且**伴随**外部**地址/敏感对象。
_EXFIL_VERBS = r"(?:send|post|upload|exfiltrate|transmit|forward|curl|wget|fetch)"
#: ⚠️ `https?://` 单独用会误报：PoC README 里 "curl -X POST http://localhost:8000/..."
#: 是**复现步骤**，不是外发。（实测被反向测试抓出来。）
#: 因此地址部分排除本地/内网，只认真正的外部目的地。
_EXFIL_HOSTS = (
    r"https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]"
    r"|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)
_EXFIL_TARGETS = (
    rf"(?:{_EXFIL_HOSTS}"
    r"|to\s+(?:my|this|the|an?\s+external)\s+(?:server|endpoint|url|address)"
    r"|\.env\b|api[_\s-]?key|token|credential|password|secret|ssh\s+key)"
)
_EXFIL_RE = re.compile(rf"\b{_EXFIL_VERBS}\b[^.\n]{{0,60}}\b{_EXFIL_TARGETS}\b", re.I)

#: ⑧ 伪造系统提示：出现"新的系统提示"这类宣告。
_FAKE_SYSTEM_RE = re.compile(
    r"\b(?:new|updated|revised|real|actual)\s+(?:system\s+)?(?:prompt|instructions?)\b"
    r"|\byour\s+(?:new\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are)\b"
    r"|\bfrom\s+now\s+on\s+you\s+(?:are|will|must)\b",
    re.I,
)

#: ⑨ 引用伪造：要求引用一个不存在的来源，或直接给出"引用编号"当证据。
#: 只匹配"要求伪造"的祈使语境 —— 论文里讨论 citation 是正常学术内容。
_CITATION_SPOOF_RE = re.compile(
    r"\b(?:cite|reference|quote)\s+(?:this|the\s+following|a\s+fake|an?\s+invented)\b"
    r"|\b(?:make\s+up|invent|fabricate)\s+(?:a\s+)?(?:citation|reference|source)\b"
    r"|\b(?:fabricate|invent)\s+(?:evidence|proof)\b",
    re.I,
)

#: ⑩ 多阶段：把注入拆成步骤（"第一步…第二步…忽略…"）。
#: ⚠️ 这里**不能用 `[^.\n]`**：多阶段注入天然跨句
#: （"First read the question**.** Then**.** ignore the guard"），
#: 按句号截断就永远匹配不到。改用 `.` + `re.S`，并靠断言关键词收敛误报面。
_MULTI_STAGE_RE = re.compile(
    r"\b(?:first|step\s*1|1\))\b.{0,80}?\b(?:then|second|step\s*2|2\))\b"
    r".{0,120}?\b(?:ignore|override|disregard)\b\s+(?:the\s+)?"
    r"(?:guard|safety|rule|instruction|prompt|above|previous|system)",
    re.I | re.S,
)


@dataclass(slots=True)
class InjectionReport:
    """一次筛查的结果。"""

    flags: list[str] = field(default_factory=list)
    score: float = 0.0
    #: 每条命中的简短说明（不复制原文，避免把注入内容二次传播到日志/事件里）
    details: dict[str, str] = field(default_factory=dict)

    @property
    def suspicious(self) -> bool:
        return self.score >= SUSPICIOUS_THRESHOLD

    @property
    def screened(self) -> bool:
        """本模块跑过就是 True —— 与契约的 `screened` 语义一致。"""

        return True


def _has_many_html_entities(text: str) -> bool:
    return len(_HTML_ENTITY_RE.findall(text)) >= 5


def _looks_like_base64(blob: str) -> bool:
    """能真解码且解出可见文本，才算"藏内容"。

    只按字符集判断会把长哈希、JWT 片段、URL-safe token 全当成 base64。
    """

    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:  # noqa: BLE001 - 不是 base64 就当没命中
        return False
    if len(raw) < 16:
        return False
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    # 可打印字符占比高才算"藏了可读内容"
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    return printable / len(decoded) > 0.9


def detect(text: str) -> InjectionReport:
    """筛查一段外部文本，返回命中的迹象与评分。

    传空文本返回空报告（score 0、无 flags），但**仍视为已筛查**
    （`screened=True`）—— "这段没内容"与"没筛查过"是两回事。
    """

    if not text:
        return InjectionReport()

    flags: list[str] = []
    details: dict[str, str] = {}

    def hit(flag: str, note: str) -> None:
        if flag not in flags:
            flags.append(flag)
            details[flag] = note

    if _INSTRUCTION_OVERRIDE_RE.search(text):
        hit("instruction_override", "出现「忽略/绕过 + 先前指令」类共现")

    if _ROLE_CONFUSION_RE.search(text):
        hit("role_confusion", "外部文本中夹杂对话模板标记或角色宣告")

    if _ZERO_WIDTH_RE.search(text):
        found = sorted({hex(ord(c)) for c in _ZERO_WIDTH_RE.findall(text)})
        hit("zero_width_chars", f"含零宽字符 {found}")

    if _B64_VERBS_RE.search(text):
        for blob in _B64_BLOB_RE.findall(text):
            if _looks_like_base64(blob):
                hit("base64_hidden", "长 base64 段可解码且伴随解码类动词")
                break

    if _has_many_html_entities(text):
        hit("html_entity_encoded", "成串 HTML 实体编码（≥5 个）")

    for m in _COMMENT_RE.finditer(text):
        inner = (m.group(1) or m.group(2) or "").strip()
        if inner and _COMMENT_INSTRUCTION_RE.search(inner):
            hit("comment_embedded", "注释内含指令性措辞")
            break

    if _EXFIL_RE.search(text):
        hit("exfil_instruction", "外发动词与敏感对象/地址共现")

    if _FAKE_SYSTEM_RE.search(text):
        hit("fake_system_prompt", "宣告新的系统提示或角色")

    if _CITATION_SPOOF_RE.search(text):
        hit("citation_spoof", "要求编造引用或来源")

    if _MULTI_STAGE_RE.search(text):
        hit("multi_stage", "分步叙述中出现覆盖指令")

    score = max((FLAG_WEIGHTS.get(f, 0.5) for f in flags), default=0.0)
    return InjectionReport(flags=flags, score=round(min(score, 1.0), 4), details=details)


def screen_items(
    items: list[dict[str, Any]], *, text_keys: tuple[str, ...] = ("content",)
) -> dict[str, Any]:
    """批量筛查一组条目（如检索到的证据），汇总成契约的 `injection_guard` 形状。

    返回的 `screened` 恒为 True（本模块确实跑过），
    与 `services/qa/freshness.py::assess_injection_guard`（无检测器时的
    `screened=False`）形成互补：**能检测就说 True，不能就如实说 False**。
    """

    all_flags: list[str] = []
    worst = 0.0
    flagged = 0
    for item in items:
        blob = "\n".join(str(item.get(k) or "") for k in text_keys)
        report = detect(blob)
        if report.flags:
            flagged += 1
            worst = max(worst, report.score)
            for f in report.flags:
                if f not in all_flags:
                    all_flags.append(f)
    return {
        "screened": True,
        "max_score": round(worst, 4),
        "flags": sorted(all_flags),
        "flagged_items": flagged,
    }
