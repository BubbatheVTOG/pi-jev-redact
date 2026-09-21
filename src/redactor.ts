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

const BUILTIN_RULES: readonly RedactionRule[] = [
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

export function getBuiltinRules(): RedactionRule[] {
  return BUILTIN_RULES.map(({ category, expression }) => ({
    category,
    expression: new RegExp(expression.source, expression.flags),
  }));
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
