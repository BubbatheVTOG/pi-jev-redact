import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";
import {
  getBuiltinRules,
  literalRule,
  patternRule,
  type RedactionRule,
} from "./redactor.js";

const MAX_CONFIG_BYTES = 64 * 1024;

interface PatternConfig {
  pattern: string;
  flags?: string;
}

interface ConfigFile {
  enabled?: boolean;
  builtins?: boolean;
  notify?: boolean;
  env?: string[];
  literals?: string[];
  patterns?: PatternConfig[];
}

export interface LoadedConfig {
  enabled: boolean;
  notify: boolean;
  blocked: boolean;
  rules: RedactionRule[];
  warnings: string[];
}

export interface ConfigLocations {
  global: string;
  project: string;
}

export function configLocations(cwd: string): ConfigLocations {
  return {
    global: join(getAgentDir(), "pi-redact.json"),
    project: join(cwd, CONFIG_DIR_NAME, "pi-redact.json"),
  };
}

export async function loadConfig(
  cwd: string,
  projectTrusted: boolean,
  environment: NodeJS.ProcessEnv = process.env,
  locations: ConfigLocations = configLocations(cwd),
): Promise<LoadedConfig> {
  const warnings: string[] = [];
  const global = await readOptionalConfig(locations.global, warnings);
  const project = projectTrusted
    ? await readOptionalConfig(locations.project, warnings)
    : undefined;
  const configs = [global, project].filter(
    (config): config is ConfigFile => config !== undefined,
  );

  const enabled = latest(configs, "enabled") ?? true;
  const builtins = latest(configs, "builtins") ?? true;
  const notify = latest(configs, "notify") ?? true;
  const rules = builtins ? getBuiltinRules() : [];

  for (const config of configs) {
    for (const name of config.env ?? []) {
      validateEnvironmentName(name);
      const value = environment[name];
      if (!value || value.length < 4) {
        warnings.push(`Environment variable ${name} is unset or too short`);
        continue;
      }
      rules.push(literalRule("configured-env", value));
    }
    for (const literal of config.literals ?? []) {
      rules.push(literalRule("configured-literal", literal));
    }
    for (const pattern of config.patterns ?? []) {
      rules.push(
        patternRule("configured-pattern", pattern.pattern, pattern.flags),
      );
    }
  }

  return { enabled, notify, blocked: warnings.length > 0, rules, warnings };
}

async function readOptionalConfig(
  path: string,
  warnings: string[],
): Promise<ConfigFile | undefined> {
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    if (isNotFound(error)) return undefined;
    warnings.push(
      `Could not read ${path}; custom rules from that file are inactive`,
    );
    return undefined;
  }

  if (Buffer.byteLength(contents) > MAX_CONFIG_BYTES) {
    warnings.push(
      `Ignored ${path} because it exceeds ${MAX_CONFIG_BYTES} bytes`,
    );
    return undefined;
  }

  try {
    return parseConfig(contents);
  } catch {
    warnings.push(`Ignored invalid configuration at ${path}`);
    return undefined;
  }
}

export function parseConfig(contents: string): ConfigFile {
  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch (error) {
    throw new Error("Configuration must be valid JSON", { cause: error });
  }
  if (!isRecord(value)) throw new Error("Configuration must be a JSON object");
  const allowed = new Set([
    "enabled",
    "builtins",
    "notify",
    "env",
    "literals",
    "patterns",
  ]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`Unknown configuration key: ${key}`);
  }

  optionalBoolean(value.enabled, "enabled");
  optionalBoolean(value.builtins, "builtins");
  optionalBoolean(value.notify, "notify");
  const env = optionalStringArray(value.env, "env");
  env?.forEach(validateEnvironmentName);
  const literals = optionalStringArray(value.literals, "literals");
  literals?.forEach((literal) => {
    if (literal.length < 4) {
      throw new Error("Literal values require at least 4 characters");
    }
  });
  const patterns = optionalObjectArray(
    value.patterns,
    "patterns",
    parsePattern,
  );

  return {
    ...(typeof value.enabled === "boolean" ? { enabled: value.enabled } : {}),
    ...(typeof value.builtins === "boolean"
      ? { builtins: value.builtins }
      : {}),
    ...(typeof value.notify === "boolean" ? { notify: value.notify } : {}),
    ...(env ? { env } : {}),
    ...(literals ? { literals } : {}),
    ...(patterns ? { patterns } : {}),
  };
}

function parsePattern(value: Record<string, unknown>): PatternConfig {
  assertExactKeys(value, ["pattern", "flags"]);
  if (typeof value.pattern !== "string") {
    throw new Error("Pattern rules require a string pattern field");
  }
  if (value.flags !== undefined && typeof value.flags !== "string") {
    throw new Error("Pattern flags must be a string");
  }
  patternRule("validation", value.pattern, value.flags);
  return {
    pattern: value.pattern,
    ...(typeof value.flags === "string" ? { flags: value.flags } : {}),
  };
}

function validateEnvironmentName(name: string): void {
  if (!/^[A-Z_][A-Z0-9_]*$/.test(name)) {
    throw new Error(`Invalid environment variable name: ${name}`);
  }
}

function latest(
  configs: readonly ConfigFile[],
  key: "enabled" | "builtins" | "notify",
): boolean | undefined {
  for (let index = configs.length - 1; index >= 0; index -= 1) {
    const value = configs[index]?.[key];
    if (value !== undefined) return value;
  }
  return undefined;
}

function optionalBoolean(value: unknown, key: string): void {
  if (value !== undefined && typeof value !== "boolean") {
    throw new Error(`${key} must be a boolean`);
  }
}

function optionalStringArray(
  value: unknown,
  key: string,
): string[] | undefined {
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string")
  ) {
    throw new Error(`${key} must be an array of strings`);
  }
  return value;
}

function optionalObjectArray<T>(
  value: unknown,
  key: string,
  parser: (item: Record<string, unknown>) => T,
): T[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) throw new Error(`${key} must be an array`);
  return value.map((item) => {
    if (!isRecord(item)) throw new Error(`${key} entries must be objects`);
    return parser(item);
  });
}

function assertExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): void {
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key)))
    throw new Error("Unknown rule property");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNotFound(error: unknown): boolean {
  return isRecord(error) && error.code === "ENOENT";
}
