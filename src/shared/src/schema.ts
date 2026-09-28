/**
 * 运行期契约校验（轻量子集，与 scripts/validate_contracts.py 同口径）。
 * 覆盖：type/required/enum/properties/additionalProperties/pattern/minLength/
 * minimum/maximum/minItems/format(date-time)。复杂组合（oneOf 等）走 python 校验器。
 */
import type { QualityVerdict } from "./types.js";

export interface SchemaLike {
  type?: string;
  required?: string[];
  enum?: string[];
  properties?: Record<string, SchemaLike>;
  additionalProperties?: boolean;
  pattern?: string;
  minLength?: number;
  minimum?: number;
  maximum?: number;
  minItems?: number;
  format?: string;
}

export function validateInstance(value: unknown, schema: SchemaLike, path = "$"): string[] {
  const errors: string[] = [];
  if (schema.type) {
    const t = schema.type;
    const ok =
      (t === "object" && typeof value === "object" && value !== null && !Array.isArray(value)) ||
      (t === "array" && Array.isArray(value)) ||
      (t === "string" && typeof value === "string") ||
      (t === "number" && typeof value === "number") ||
      (t === "integer" && Number.isInteger(value)) ||
      (t === "boolean" && typeof value === "boolean") ||
      (t === "null" && value === null);
    if (!ok) {
      errors.push(`${path}: 类型应为 ${t}`);
      return errors;
    }
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${path}: 短于 minLength ${schema.minLength}`);
    }
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: 不匹配 pattern ${schema.pattern}`);
    }
    if (schema.format === "date-time") {
      const t = Date.parse(value);
      if (Number.isNaN(t) || !/^\d{4}-\d{2}-\d{2}T/.test(value)) {
        errors.push(`${path}: 非法 date-time（须 ISO-8601）`);
      }
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: < minimum`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: > maximum`);
  }
  if (Array.isArray(value) && schema.minItems !== undefined && value.length < schema.minItems) {
    errors.push(`${path}: 少于 minItems ${schema.minItems}`);
  }
  if (schema.enum && !schema.enum.includes(value as string)) {
    errors.push(`${path}: 不在枚举 ${JSON.stringify(schema.enum)}`);
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    for (const req of schema.required ?? []) {
      if (!(req in obj)) errors.push(`${path}: 缺必填字段 ${req}`);
    }
    for (const [k, v] of Object.entries(obj)) {
      const sub = schema.properties?.[k];
      if (sub) {
        errors.push(...validateInstance(v, sub, `${path}.${k}`));
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}.${k}: additionalProperties:false 违规`);
      }
    }
  }
  return errors;
}

/** IntelItem 入站最小校验（关键字段 + 双时钟可解析）。 */
export function assertIntelItemBasics(item: Record<string, unknown>): string[] {
  const errors: string[] = [];
  for (const f of ["intel_id", "cve_ids", "source_ids", "title", "first_seen_at", "entities", "raw_refs"]) {
    if (!(f in item)) errors.push(`IntelItem 缺字段 ${f}`);
  }
  for (const f of ["published_at", "first_seen_at"]) {
    const v = item[f];
    if (typeof v === "string" && Number.isNaN(Date.parse(v))) errors.push(`IntelItem.${f} 非法时间`);
  }
  return errors;
}
