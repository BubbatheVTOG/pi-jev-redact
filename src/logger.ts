import { appendFile, mkdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";
import type { RedactionReport } from "./redactor.js";

export const DEFAULT_LOG_DIR = "/tmp/pi-redact";
export const DEFAULT_LOG_MAX_BYTES = 16 * 1024 * 1024;

export type LogMode = "report" | "payload";

export interface LogConfig {
  mode: LogMode | null;
  dir: string;
  maxBytes: number;
  warnings: string[];
}

export interface LogConfigLocations {
  global: string;
  project: string;
}

export interface LogEntryInput {
  session: string;
  cwd: string;
  count: number;
  categories: RedactionReport["categories"];
  payload: unknown;
}

export interface LogEntry {
  ts: string;
  session: string;
  cwd: string;
  count: number;
  categories: RedactionReport["categories"];
  mode: LogMode;
  payloadBytes: number;
  payload?: unknown;
}

const LOG_KEYS = ["log", "logDir", "logMaxBytes"] as const;
type LogKey = (typeof LOG_KEYS)[number];

/**
 * Resolve the settings files the `piRedact` block is read from. The global
 * path mirrors Pi's own `getSettingsPath()`; the project file is only read
 * for trusted projects (callers decide that).
 */
export function logConfigLocations(cwd: string): LogConfigLocations {
  return {
    global: join(getAgentDir(), "settings.json"),
    project: join(cwd, CONFIG_DIR_NAME, "settings.json"),
  };
}

/**
 * Load the `piRedact` logging configuration from Pi's settings files.
 * Logging is disabled by default. Invalid values degrade to the default with
 * a warning and never throw: a logging misconfiguration must not block
 * provider requests.
 */
export async function loadLogConfig(
  cwd: string,
  projectTrusted: boolean,
  locations: LogConfigLocations = logConfigLocations(cwd),
): Promise<LogConfig> {
  const warnings: string[] = [];
  const globalBlock = await readLogBlock(locations.global, warnings);
  const projectBlock = projectTrusted
    ? await readLogBlock(locations.project, warnings)
    : undefined;

  const merged: Partial<Record<LogKey, unknown>> = {};
  for (const key of LOG_KEYS) {
    if (globalBlock && key in globalBlock) merged[key] = globalBlock[key];
    if (projectBlock && key in projectBlock) merged[key] = projectBlock[key];
  }

  return {
    mode: parseMode(merged.log, warnings),
    dir: parseLogDir(merged.logDir, warnings),
    maxBytes: parseLogMaxBytes(merged.logMaxBytes, warnings),
    warnings,
  };
}

/**
 * Append redaction log entries for a single session, one JSON line per
 * provider request. Concurrent writes are serialized per logger so the
 * per-session file cap is enforced exactly: when an entry would push the
 * file past `maxBytes`, a single marker line is written and further entries
 * are skipped for the life of this process. All failures (including failures
 * inside `onError`) are reported at most once and never thrown into the
 * request path.
 */
export class SessionLogger {
  private dirReady = false;
  private capped = false;
  private warned = false;
  private tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly config: LogConfig,
    private readonly path: string,
    private readonly onError: (message: string) => void,
  ) {}

  async log(input: LogEntryInput): Promise<void> {
    const mode = this.config.mode;
    if (mode === null) return;

    const work = this.tail.then(() => this.write(mode, input));
    this.tail = work.catch(() => undefined);
    await work;
  }

  private async write(mode: LogMode, input: LogEntryInput): Promise<void> {
    if (this.capped) return;

    try {
      const line = `${JSON.stringify(this.buildEntry(mode, input))}\n`;
      if (!this.dirReady) {
        await mkdir(this.config.dir, { recursive: true, mode: 0o700 });
        this.dirReady = true;
      }
      const size = await fileSize(this.path);
      // Buffer.byteLength, not line.length: the cap is a byte budget and
      // multibyte content encodes larger than its string length.
      if (this.exceedsCap(size, Buffer.byteLength(line))) {
        await this.appendMarker();
        return;
      }
      await appendFile(this.path, line, { mode: 0o600 });
    } catch (error) {
      if (!this.warned) {
        this.warned = true;
        try {
          this.onError(
            `pi-jev-redact: could not write the redaction log: ${describeError(error)}`,
          );
        } catch {
          // A failure reporting a failure must not break the request path.
        }
      }
    }
  }

  private buildEntry(mode: LogMode, input: LogEntryInput): LogEntry {
    const base: LogEntry = {
      ts: new Date().toISOString(),
      session: input.session,
      cwd: input.cwd,
      count: input.count,
      categories: input.categories,
      mode,
      payloadBytes: Buffer.byteLength(JSON.stringify(input.payload)),
    };
    return mode === "payload" ? { ...base, payload: input.payload } : base;
  }

  private exceedsCap(current: number, lineBytes: number): boolean {
    if (this.config.maxBytes <= 0) return false;
    return (
      current >= this.config.maxBytes ||
      current + lineBytes > this.config.maxBytes
    );
  }

  private async appendMarker(): Promise<void> {
    if (this.capped) return;
    this.capped = true;
    const marker = {
      ts: new Date().toISOString(),
      note: "log size limit reached; logging stopped for this session",
    };
    await appendFile(this.path, `${JSON.stringify(marker)}\n`, { mode: 0o600 });
  }
}

/** Compose the per-session log path from a sanitized session id. */
export function logPathFor(config: LogConfig, sessionId: string): string {
  return join(config.dir, `${safeSessionFileBase(sessionId)}.jsonl`);
}

export function safeSessionFileBase(sessionId: string): string {
  if (!/[A-Za-z0-9_-]/.test(sessionId)) return "unknown";
  return sessionId.replace(/[^A-Za-z0-9_-]/g, "_");
}

async function readLogBlock(
  path: string,
  warnings: string[],
): Promise<Record<string, unknown> | undefined> {
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    if (isNotFound(error)) return undefined;
    warnings.push(`Could not read ${path}; its piRedact settings are ignored`);
    return undefined;
  }

  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch {
    warnings.push(`Invalid JSON in ${path}; its piRedact settings are ignored`);
    return undefined;
  }
  if (!isRecord(value)) {
    warnings.push(
      `${path} must contain a JSON object; its piRedact settings are ignored`,
    );
    return undefined;
  }

  const block = value.piRedact;
  if (block === undefined) return undefined;
  if (!isRecord(block)) {
    warnings.push(
      `The piRedact setting in ${path} must be an object; it is ignored`,
    );
    return undefined;
  }

  const unknown = Object.keys(block).filter(
    (key) => !(LOG_KEYS as readonly string[]).includes(key),
  );
  if (unknown.length > 0) {
    warnings.push(
      `Unknown piRedact setting keys ignored: ${unknown.join(", ")}`,
    );
  }
  return block;
}

function parseMode(value: unknown, warnings: string[]): LogMode | null {
  if (value === undefined || value === false) return null;
  if (value === "report" || value === "payload") return value;
  warnings.push(
    'The piRedact log setting must be "report", "payload", or false; logging is disabled',
  );
  return null;
}

function parseLogDir(value: unknown, warnings: string[]): string {
  if (value === undefined) return DEFAULT_LOG_DIR;
  if (typeof value === "string" && value.length > 0) return value;
  warnings.push("piRedact logDir must be a non-empty path; using the default");
  return DEFAULT_LOG_DIR;
}

function parseLogMaxBytes(value: unknown, warnings: string[]): number {
  if (value === undefined) return DEFAULT_LOG_MAX_BYTES;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  warnings.push(
    "piRedact logMaxBytes must be a non-negative integer (0 disables the limit); using the default",
  );
  return DEFAULT_LOG_MAX_BYTES;
}

async function fileSize(path: string): Promise<number> {
  try {
    return (await stat(path)).size;
  } catch (error) {
    if (isNotFound(error)) return 0;
    throw error;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNotFound(error: unknown): boolean {
  return isRecord(error) && error.code === "ENOENT";
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
