import { randomUUID } from "node:crypto";
import { mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";

export const DECISION_KEYS = ["decisionDir"] as const;
export const MAX_DECISION_ENTRIES = 10_000;

export type SendDecision = "approved" | "denied";

interface DecisionEntry {
  decision: SendDecision;
  updatedAt: string;
  categories: string[];
}

interface DecisionDocument {
  version: 1;
  entries: Record<string, DecisionEntry>;
}

export interface DecisionConfig {
  dir: string;
  warnings: string[];
}

export interface DecisionConfigLocations {
  global: string;
  project: string;
}

export function defaultDecisionDir(
  platform = process.platform,
  environment: NodeJS.ProcessEnv = process.env,
  home = homedir(),
): string {
  if (platform === "darwin")
    return join(home, "Library", "Caches", "pi-jev-redact");
  if (platform === "win32") {
    return join(
      environment.LOCALAPPDATA || join(home, "AppData", "Local"),
      "pi-jev-redact",
    );
  }
  return join(
    environment.XDG_CACHE_HOME || join(home, ".cache"),
    "pi-jev-redact",
  );
}

export function decisionConfigLocations(cwd: string): DecisionConfigLocations {
  return {
    global: join(getAgentDir(), "settings.json"),
    project: join(cwd, CONFIG_DIR_NAME, "settings.json"),
  };
}

export async function loadDecisionConfig(
  cwd: string,
  projectTrusted: boolean,
  locations: DecisionConfigLocations = decisionConfigLocations(cwd),
): Promise<DecisionConfig> {
  const warnings: string[] = [];
  const globalBlock = await readPiRedactBlock(locations.global, warnings);
  const projectBlock = projectTrusted
    ? await readPiRedactBlock(locations.project, warnings)
    : undefined;
  const value = projectBlock?.decisionDir ?? globalBlock?.decisionDir;
  if (value === undefined) return { dir: defaultDecisionDir(), warnings };
  if (typeof value === "string" && value.trim().length > 0) {
    return { dir: value, warnings };
  }
  warnings.push(
    "piRedact decisionDir must be a non-empty path; using the default",
  );
  return { dir: defaultDecisionDir(), warnings };
}

/**
 * A small privacy-preserving cache: keys are SHA-256 fingerprints supplied by
 * the redactor, never the original secret or PII. Each read refreshes the
 * in-memory view. Writes are serialized in-process, merged under a cross-process
 * lock, and atomically replace the JSON document with mode 0600.
 */
export class DecisionStore {
  private warned = false;
  private readonly entries = new Map<string, DecisionEntry>();
  private tail: Promise<void> = Promise.resolve();
  private readonly path: string;

  constructor(
    dir: string,
    private readonly onError: (message: string) => void = () => undefined,
  ) {
    this.path = join(dir, "decisions.json");
  }

  async decisionsFor(
    fingerprints: readonly string[],
  ): Promise<Map<string, SendDecision>> {
    await this.tail;
    await this.reload();
    const result = new Map<string, SendDecision>();
    for (const fingerprint of fingerprints) {
      const entry = this.entries.get(fingerprint);
      if (entry) result.set(fingerprint, entry.decision);
    }
    return result;
  }

  async record(
    fingerprints: readonly string[],
    decision: SendDecision,
    categories: readonly string[],
  ): Promise<void> {
    const work = this.tail.then(() =>
      this.withLock(async () => {
        await this.reload();
        const updatedAt = new Date().toISOString();
        for (const fingerprint of fingerprints) {
          this.entries.set(fingerprint, {
            decision,
            updatedAt,
            categories: [...new Set(categories)].sort((left, right) =>
              left.localeCompare(right),
            ),
          });
        }
        this.prune();
        await this.persist();
      }),
    );
    this.tail = work.catch(() => undefined);
    try {
      await work;
    } catch (error) {
      this.report(error);
    }
  }

  private async reload(): Promise<void> {
    this.entries.clear();
    let contents: string;
    try {
      contents = await readFile(this.path, "utf8");
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT") return;
      this.report(error);
      return;
    }
    try {
      const parsed: unknown = JSON.parse(contents);
      if (
        !isRecord(parsed) ||
        parsed.version !== 1 ||
        !isRecord(parsed.entries)
      ) {
        throw new Error("invalid decisions document");
      }
      for (const [fingerprint, value] of Object.entries(parsed.entries)) {
        if (!/^[a-f0-9]{64}$/.test(fingerprint) || !isDecisionEntry(value))
          continue;
        this.entries.set(fingerprint, value);
      }
      this.prune();
    } catch (error) {
      this.report(error);
      this.entries.clear();
    }
  }

  private prune(): void {
    if (this.entries.size <= MAX_DECISION_ENTRIES) return;
    const oldest = [...this.entries.entries()].sort((left, right) =>
      left[1].updatedAt.localeCompare(right[1].updatedAt),
    );
    for (const [fingerprint] of oldest.slice(
      0,
      this.entries.size - MAX_DECISION_ENTRIES,
    )) {
      this.entries.delete(fingerprint);
    }
  }

  private async withLock(operation: () => Promise<void>): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const lockPath = `${this.path}.lock`;
    let lock: Awaited<ReturnType<typeof open>> | undefined;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        lock = await open(lockPath, "wx", 0o600);
        break;
      } catch (error) {
        if (!isNodeError(error) || error.code !== "EEXIST") throw error;
        await delay(50);
      }
    }
    if (!lock) throw new Error("timed out waiting for decision cache lock");
    try {
      await operation();
    } finally {
      await lock.close().catch(() => undefined);
      await rm(lockPath, { force: true }).catch(() => undefined);
    }
  }

  private async persist(): Promise<void> {
    const document: DecisionDocument = {
      version: 1,
      entries: Object.fromEntries(this.entries),
    };
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, {
        mode: 0o600,
        flag: "wx",
      });
      await rename(temporary, this.path);
    } finally {
      await rm(temporary, { force: true }).catch(() => undefined);
    }
  }

  private report(error: unknown): void {
    if (this.warned) return;
    this.warned = true;
    try {
      this.onError(
        `pi-jev-redact: decision cache unavailable; decisions will not persist (${describeError(error)})`,
      );
    } catch {
      // Failure reporting must never break the provider request path.
    }
  }
}

async function readPiRedactBlock(
  path: string,
  warnings: string[],
): Promise<Record<string, unknown> | undefined> {
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    warnings.push(`Could not read ${path}; its piRedact settings are ignored`);
    return undefined;
  }
  try {
    const root: unknown = JSON.parse(contents);
    if (!isRecord(root)) throw new Error("settings root must be an object");
    if (root.piRedact === undefined) return undefined;
    if (!isRecord(root.piRedact)) throw new Error("piRedact must be an object");
    return root.piRedact;
  } catch {
    warnings.push(`Invalid piRedact settings in ${path}; they are ignored`);
    return undefined;
  }
}

function isDecisionEntry(value: unknown): value is DecisionEntry {
  return (
    isRecord(value) &&
    (value.decision === "approved" || value.decision === "denied") &&
    typeof value.updatedAt === "string" &&
    Array.isArray(value.categories) &&
    value.categories.every((category) => typeof category === "string")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
