import { createHash } from "node:crypto";
import {
  redactText,
  REDACTION,
  type RedactionReport,
  type RedactionRule,
} from "./redactor.js";

export interface PayloadRedactionOptions {
  /** Preserve provider authentication values for transport. Default true. */
  preserveCredentialHeaders?: boolean;
}

const CREDENTIAL_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "api-key",
  "x-goog-api-key",
]);

export interface PayloadRedactionResult extends RedactionReport {
  payload: unknown;
  /** SHA-256 fingerprints of original redacted spans; raw values are omitted. */
  fingerprints: string[];
}

type SanitizedValue =
  string | number | boolean | bigint | symbol | object | null | undefined;

export function redactPayload(
  payload: unknown,
  rules: readonly RedactionRule[],
  options: PayloadRedactionOptions = {},
): PayloadRedactionResult {
  const report: RedactionReport = { count: 0, categories: {} };
  const fingerprints = new Set<string>();
  const seen = new WeakMap<object, SanitizedValue>();
  const sanitized = visit(
    payload,
    rules,
    report,
    fingerprints,
    seen,
    false,
    options.preserveCredentialHeaders !== false,
  );
  return {
    payload: sanitized,
    fingerprints: [...fingerprints].sort(),
    ...report,
  };
}

function visit(
  value: unknown,
  rules: readonly RedactionRule[],
  report: RedactionReport,
  fingerprints: Set<string>,
  seen: WeakMap<object, SanitizedValue>,
  headerContainer: boolean,
  preserveCredentialHeaders: boolean,
): SanitizedValue {
  if (typeof value === "string") {
    if (isBinaryString(value)) return value;
    const result = redactText(value, rules, (span) => {
      fingerprints.add(createHash("sha256").update(span).digest("hex"));
    });
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
    for (const item of value) {
      copy.push(
        visit(
          item,
          rules,
          report,
          fingerprints,
          seen,
          false,
          preserveCredentialHeaders,
        ),
      );
    }
    return copy;
  }

  if (!isPlainObject(value)) return value;
  const existing = seen.get(value);
  if (existing) return existing;

  const copy: Record<string, SanitizedValue> = {};
  seen.set(value, copy);
  for (const [key, item] of Object.entries(value)) {
    if (headerContainer && CREDENTIAL_HEADERS.has(key.toLowerCase())) {
      copy[key] = preserveCredentialHeaders
        ? (item as SanitizedValue)
        : REDACTION;
      continue;
    }
    copy[key] = isImageData(value, key, item)
      ? item
      : visit(
          item,
          rules,
          report,
          fingerprints,
          seen,
          key.toLowerCase() === "headers" && isPlainObject(item),
          preserveCredentialHeaders,
        );
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
