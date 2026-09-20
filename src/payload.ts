import {
  redactText,
  type RedactionReport,
  type RedactionRule,
} from "./redactor.js";

export interface PayloadRedactionResult extends RedactionReport {
  payload: unknown;
}

type SanitizedValue =
  string | number | boolean | bigint | symbol | object | null | undefined;

export function redactPayload(
  payload: unknown,
  rules: readonly RedactionRule[],
): PayloadRedactionResult {
  const report: RedactionReport = { count: 0, categories: {} };
  const seen = new WeakMap<object, SanitizedValue>();
  const sanitized = visit(payload, rules, report, seen);
  return { payload: sanitized, ...report };
}

function visit(
  value: unknown,
  rules: readonly RedactionRule[],
  report: RedactionReport,
  seen: WeakMap<object, SanitizedValue>,
): SanitizedValue {
  if (typeof value === "string") {
    if (isBinaryString(value)) return value;
    const result = redactText(value, rules);
    mergeReport(report, result);
    return result.value;
  }

  if (
    value === null ||
    value === undefined ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint" ||
    typeof value === "symbol" ||
    typeof value === "function"
  ) {
    return value;
  }

  if (Array.isArray(value)) {
    const existing = seen.get(value);
    if (existing) return existing;
    const copy: SanitizedValue[] = [];
    seen.set(value, copy);
    for (const item of value) copy.push(visit(item, rules, report, seen));
    return copy;
  }

  if (!isPlainObject(value)) return value;
  const existing = seen.get(value);
  if (existing) return existing;

  const copy: Record<string, SanitizedValue> = {};
  seen.set(value, copy);
  for (const [key, item] of Object.entries(value)) {
    copy[key] = isImageData(value, key, item)
      ? item
      : visit(item, rules, report, seen);
  }
  return copy;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isImageData(
  parent: Record<string, unknown>,
  key: string,
  value: unknown,
): value is string {
  if (typeof value !== "string") return false;
  if (value.startsWith("data:image/")) return true;
  return parent.type === "image" && (key === "data" || key === "source");
}

function isBinaryString(value: string): boolean {
  if (value.startsWith("data:image/")) return true;
  if (value.length < 1024 || value.length % 4 !== 0) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function mergeReport(target: RedactionReport, source: RedactionReport): void {
  target.count += source.count;
  for (const [category, count] of Object.entries(source.categories)) {
    target.categories[category] = (target.categories[category] ?? 0) + count;
  }
}
