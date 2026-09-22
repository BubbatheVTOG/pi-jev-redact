import safeRegex from "safe-regex2";

export const REDACTION = "<-REDACTED->";

export interface RedactionRule {
  category: string;
  expression: RegExp;
}

export interface RedactionReport {
  count: number;
  categories: Record<string, number>;
}

export interface RedactionResult extends RedactionReport {
  value: string;
}

interface Match {
  start: number;
  end: number;
  category: string;
}

const CORE_SECRET_RULES: readonly RedactionRule[] = [
  {
    category: "private-key",
    expression:
      /-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?)PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----/g,
  },
  {
    category: "anthropic-key",
    expression: /sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}/g,
  },
  {
    category: "openai-key",
    expression: /sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}/g,
  },
];

const PLATFORM_SECRET_RULES: readonly RedactionRule[] = [
  {
    category: "github-token",
    expression: /(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g,
  },
  {
    category: "slack-token",
    expression: /xox[baprs]-[A-Za-z0-9-]{20,}/g,
  },
  {
    category: "google-api-key",
    expression: /AIza[A-Za-z0-9_-]{30,}/g,
  },
  {
    category: "jwt",
    expression: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
];

const PII_RULES: readonly RedactionRule[] = [
  {
    category: "email",
    expression: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    category: "phone-number",
    expression:
      /(?<!\d)(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\d)/g,
  },
  {
    category: "us-ssn",
    expression: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    category: "payment-card",
    expression: /\b(?:\d[ -]*?){13,19}\b/g,
  },
];

const NETWORK_RULES: readonly RedactionRule[] = [
  {
    category: "ipv4-address",
    expression:
      /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
  {
    category: "mac-address",
    expression: /\b(?:[A-F0-9]{2}[:-]){5}[A-F0-9]{2}\b/gi,
  },
];

const AGGRESSIVE_RULES: readonly RedactionRule[] = [
  {
    category: "bearer-token",
    expression: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi,
  },
  {
    category: "url-credential",
    expression: /https?:\/\/[^\s/@:]+:[^\s/@]+@/gi,
  },
  {
    category: "generic-secret-assignment",
    expression:
      /\b(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY)\s*[:=]\s*["']?[^\s"']{8,}["']?/gi,
  },
];

function cloneRules(rules: readonly RedactionRule[]): RedactionRule[] {
  return rules.map(({ category, expression }) => ({
    category,
    expression: new RegExp(expression.source, expression.flags),
  }));
}

export function getCoreSecretRules(): RedactionRule[] {
  return cloneRules(CORE_SECRET_RULES);
}

/** All secret built-ins; preserves the pre-threshold public API. */
export function getBuiltinRules(): RedactionRule[] {
  return cloneRules([...CORE_SECRET_RULES, ...PLATFORM_SECRET_RULES]);
}

export function getPiiRules(): RedactionRule[] {
  return cloneRules(PII_RULES);
}

export function getNetworkRules(): RedactionRule[] {
  return cloneRules(NETWORK_RULES);
}

export function getAggressiveRules(): RedactionRule[] {
  return cloneRules(AGGRESSIVE_RULES);
}

export function literalRule(category: string, literal: string): RedactionRule {
  if (literal.length < 4) {
    throw new Error(
      `Literal rule ${category} must contain at least 4 characters`,
    );
  }

  return {
    category,
    expression: new RegExp(escapeRegExp(literal), "g"),
  };
}

export function patternRule(
  category: string,
  pattern: string,
  flags = "",
): RedactionRule {
  validatePattern(pattern, flags);
  const normalizedFlags = flags.includes("g") ? flags : `${flags}g`;
  const expression = new RegExp(pattern, normalizedFlags);
  if (expression.test("")) {
    throw new Error(`Pattern rule ${category} must not match an empty string`);
  }
  expression.lastIndex = 0;
  return { category, expression };
}

export function redactText(
  value: string,
  rules: readonly RedactionRule[],
  onSpan?: (original: string) => void,
): RedactionResult {
  const matches = collectMatches(value, rules);
  if (matches.length === 0) {
    return { value, count: 0, categories: {} };
  }

  const merged = mergeOverlaps(matches);
  const categories: Record<string, number> = {};
  let cursor = 0;
  let redacted = "";

  for (const match of merged) {
    redacted += value.slice(cursor, match.start);
    redacted += REDACTION;
    onSpan?.(value.slice(match.start, match.end));
    cursor = match.end;
    for (const category of match.categories) {
      categories[category] = (categories[category] ?? 0) + 1;
    }
  }
  redacted += value.slice(cursor);

  return { value: redacted, count: merged.length, categories };
}

function collectMatches(
  value: string,
  rules: readonly RedactionRule[],
): Match[] {
  const matches: Match[] = [];

  for (const rule of rules) {
    const flags = rule.expression.flags.includes("g")
      ? rule.expression.flags
      : `${rule.expression.flags}g`;
    const expression = new RegExp(rule.expression.source, flags);
    for (const match of value.matchAll(expression)) {
      const text = match[0];
      if (!text || match.index === undefined) continue;
      matches.push({
        start: match.index,
        end: match.index + text.length,
        category: rule.category,
      });
    }
  }

  return matches.sort(
    (left, right) => left.start - right.start || right.end - left.end,
  );
}

function mergeOverlaps(matches: readonly Match[]): Array<{
  start: number;
  end: number;
  categories: Set<string>;
}> {
  const merged: Array<{ start: number; end: number; categories: Set<string> }> =
    [];

  for (const match of matches) {
    const previous = merged.at(-1);
    if (previous && match.start < previous.end) {
      previous.end = Math.max(previous.end, match.end);
      previous.categories.add(match.category);
      continue;
    }
    merged.push({
      start: match.start,
      end: match.end,
      categories: new Set([match.category]),
    });
  }

  return merged;
}

function validatePattern(pattern: string, flags: string): void {
  if (pattern.length === 0 || pattern.length > 512) {
    throw new Error("Regex patterns must contain between 1 and 512 characters");
  }
  if (!/^[imsuy]*$/.test(flags) || new Set(flags).size !== flags.length) {
    throw new Error(
      "Regex flags may contain each of i, m, s, u, and y at most once",
    );
  }
  if (!safeRegex(pattern)) {
    throw new Error("Potentially unsafe regular expressions are not supported");
  }
  if (/\\[1-9]/.test(pattern) || /\(\?<([=!])/.test(pattern)) {
    throw new Error("Backreferences and lookbehind are not supported");
  }
  if (/\((?:[^()]|\\.)*[+*}](?:[^()]|\\.)*\)[+*{]/.test(pattern)) {
    throw new Error("Nested quantifiers are not supported");
  }

  try {
    new RegExp(pattern, flags);
  } catch (error) {
    throw new Error(`Invalid regex pattern: ${String(error)}`, {
      cause: error,
    });
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
