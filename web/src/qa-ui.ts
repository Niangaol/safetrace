/** Strict atomic server-hydrated evidence. No model-defined DOM or actions. */
export interface UiItem { id: string; doc_type: string; text: string; url: string; cve_id: string | null }
export interface UiBlock { id: string; type: 'evidence' | 'comparison' | 'checklist'; items: UiItem[] }
export interface UiDocument { version: 1; source: 'model' | 'rules'; blocks: UiBlock[] }
export interface UiStatus { status: 'accepted' | 'fallback' | 'skipped'; reason: string }
function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
}
function keys(value: Record<string, unknown>, allowed: string[]): boolean {
  const actual = Object.keys(value)
  return actual.length === allowed.length && actual.every(key => allowed.includes(key))
}
function bounded(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(value)
}
export function safeUiUrl(value: string): string | null {
  if (!value || value.length > 2048 || /[\s\u0000-\u001f\u007f\u200b-\u200f\ufeff\\]/u.test(value) || !/^https?:\/\//i.test(value)) return null
  try { const url = new URL(value); return url.hostname && !url.username && !url.password && ['http:', 'https:'].includes(url.protocol) ? value : null } catch { return null }
}
export function readUiEvent(value: unknown): UiDocument | null {
  if (!record(value) || !keys(value, ['event', 'document']) || value.event !== 'ui') return null
  const document = value.document
  if (!record(document) || !keys(document, ['version', 'source', 'blocks']) || document.version !== 1 || !['model', 'rules'].includes(document.source as string) || !Array.isArray(document.blocks) || document.blocks.length < 1 || document.blocks.length > 4) return null
  const blockIds = new Set<string>(), itemIds = new Set<string>()
  const blocks: UiBlock[] = []
  for (const block of document.blocks) {
    if (!record(block) || !keys(block, ['id', 'type', 'items']) || !bounded(block.id, 160) || blockIds.has(block.id) || !['evidence', 'comparison', 'checklist'].includes(block.type as string) || !Array.isArray(block.items) || block.items.length < 1 || block.items.length > 5) return null
    blockIds.add(block.id)
    const items: UiItem[] = []
    for (const item of block.items) {
      if (!record(item) || !keys(item, ['id', 'doc_type', 'text', 'url', 'cve_id']) || !bounded(item.id, 160) || itemIds.has(item.id) || !bounded(item.doc_type, 64) || !bounded(item.text, 1200) || typeof item.url !== 'string' || (item.url !== '' && !safeUiUrl(item.url)) || (item.cve_id !== null && (typeof item.cve_id !== 'string' || !/^CVE-\d{4}-\d{4,19}$/.test(item.cve_id)))) return null
      itemIds.add(item.id)
      items.push({ id: item.id, doc_type: item.doc_type, text: item.text, url: item.url, cve_id: item.cve_id as string | null })
    }
    blocks.push({ id: block.id, type: block.type as UiBlock['type'], items })
  }
  return { version: 1, source: document.source as UiDocument['source'], blocks }
}
export function readUiStatus(value: unknown): UiStatus | null {
  if (!record(value) || !keys(value, ['status', 'reason']) || !['accepted', 'fallback', 'skipped'].includes(value.status as string) || typeof value.reason !== 'string' || value.reason.length > 1200) return null
  return { status: value.status as UiStatus['status'], reason: value.reason }
}
/** Never infer CVEs from prose: null is explicitly unbound evidence. */
export function groupComparison(items: UiItem[]): { cve: string | null; items: UiItem[] }[] {
  const groups = new Map<string | null, UiItem[]>()
  for (const item of items) groups.set(item.cve_id, [...(groups.get(item.cve_id) ?? []), item])
  return [...groups].map(([cve, items]) => ({ cve, items }))
}
export function shouldSendOnEnter(event: { key: string; shiftKey: boolean; isComposing: boolean; keyCode?: number }, composing: boolean): boolean {
  return event.key === 'Enter' && !event.shiftKey && !event.isComposing && !composing && event.keyCode !== 229
}
export function isNearBottom(scroll: { scrollHeight: number; scrollTop: number; clientHeight: number }): boolean {
  return scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 72
}
