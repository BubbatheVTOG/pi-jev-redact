import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { REDACTION } from "../src/redactor.js";
import {
  DEFAULT_LOG_DIR,
  DEFAULT_LOG_MAX_BYTES,
  loadLogConfig,
  logPathFor,
  safeSessionFileBase,
  SessionLogger,
  type LogConfig,
  type LogEntryInput,
} from "../src/logger.js";

async function workspace(): Promise<{
  root: string;
  global: string;
  project: string;
}> {
  const root = await mkdtemp(join(tmpdir(), "pi-redact-log-"));
  return {
    root,
    global: join(root, "global.json"),
    project: join(root, "project.json"),
  };
}

async function readLines(path: string): Promise<string[]> {
  return (await readFile(path, "utf8")).trimEnd().split("\n");
}

function testConfig(
  dir: string,
  overrides: Partial<LogConfig> = {},
): LogConfig {
  return {
    mode: "report",
    dir,
    maxBytes: DEFAULT_LOG_MAX_BYTES,
    warnings: [],
    ...overrides,
  };
}

const INPUT: LogEntryInput = {
  session: "s1",
  cwd: "/project",
  count: 1,
  categories: { "configured-literal": 1 },
  payload: { secret: "top-secret-value" },
};

describe("loadLogConfig", () => {
  it("defaults to disabled with standard locations when no settings exist", async () => {
    const { root } = await workspace();
    const config = await loadLogConfig(root, true, {
      global: join(root, "missing-global.json"),
      project: join(root, "missing-project.json"),
    });
    expect(config).toEqual({
      mode: null,
      dir: DEFAULT_LOG_DIR,
      maxBytes: DEFAULT_LOG_MAX_BYTES,
      warnings: [],
    });
  });

  it("ignores settings files without a piRedact block", async () => {
    const { root, global } = await workspace();
    await writeFile(global, JSON.stringify({ model: "x", other: 1 }));
    const config = await loadLogConfig(root, true, {
      global,
      project: join(root, "missing-project.json"),
    });
    expect(config.mode).toBeNull();
    expect(config.warnings).toEqual([]);
  });

  it("honors an explicit log: false without warnings", async () => {
    const { root, global } = await workspace();
    await writeFile(global, JSON.stringify({ piRedact: { log: false } }));
    const config = await loadLogConfig(root, true, {
      global,
      project: join(root, "missing-project.json"),
    });
    expect(config.mode).toBeNull();
    expect(config.warnings).toEqual([]);
  });

  it("enables report and payload modes and honors overrides", async () => {
    const { root, global, project } = await workspace();
    await writeFile(global, JSON.stringify({ piRedact: { log: "report" } }));
    await writeFile(
      project,
      JSON.stringify({
        piRedact: { log: "payload", logDir: "/custom", logMaxBytes: 123 },
      }),
    );

    const trusted = await loadLogConfig(root, true, { global, project });
    expect(trusted).toEqual({
      mode: "payload",
      dir: "/custom",
      maxBytes: 123,
      warnings: [],
    });

    const untrusted = await loadLogConfig(root, false, { global, project });
    expect(untrusted).toEqual({
      mode: "report",
      dir: DEFAULT_LOG_DIR,
      maxBytes: DEFAULT_LOG_MAX_BYTES,
      warnings: [],
    });
  });

  it.each([
    ["log: true", { log: true }],
    ['log: "full"', { log: "full" }],
    ["log: 1", { log: 1 }],
  ])("warns and disables for %s", async (_name, block) => {
    const { root, global } = await workspace();
    await writeFile(global, JSON.stringify({ piRedact: block }));
    const config = await loadLogConfig(root, true, {
      global,
      project: join(root, "missing-project.json"),
    });
    expect(config.mode).toBeNull();
    expect(config.warnings).toEqual([
      'The piRedact log setting must be "report", "payload", or false; logging is disabled',
    ]);
  });

  it("degrades invalid per-key values to defaults while keeping logging enabled", async () => {
    const cases: Array<[string, Record<string, unknown>, "dir" | "maxBytes"]> =
      [
        ['logDir: ""', { log: "report", logDir: "" }, "dir"],
        ["logDir: 5", { log: "report", logDir: 5 }, "dir"],
        ["logMaxBytes: -1", { log: "report", logMaxBytes: -1 }, "maxBytes"],
        ["logMaxBytes: 1.5", { log: "report", logMaxBytes: 1.5 }, "maxBytes"],
        ['logMaxBytes: "x"', { log: "report", logMaxBytes: "x" }, "maxBytes"],
      ];

    for (const [name, block, which] of cases) {
      const { root, global } = await workspace();
      await writeFile(global, JSON.stringify({ piRedact: block }));
      const config = await loadLogConfig(root, true, {
        global,
        project: join(root, "missing-project.json"),
      });
      expect(config.mode, name).toBe("report");
      if (which === "dir") {
        expect(config.dir, name).toBe(DEFAULT_LOG_DIR);
      } else {
        expect(config.maxBytes, name).toBe(DEFAULT_LOG_MAX_BYTES);
      }
      expect(config.warnings, name).toHaveLength(1);
    }
  });
  it("warns on unknown piRedact keys but keeps valid keys active", async () => {
    const { root, global } = await workspace();
    await writeFile(
      global,
      JSON.stringify({ piRedact: { log: "report", bogus: 1 } }),
    );
    const config = await loadLogConfig(root, true, {
      global,
      project: join(root, "missing-project.json"),
    });
    expect(config.mode).toBe("report");
    expect(config.warnings).toEqual([
      "Unknown piRedact setting keys ignored: bogus",
    ]);
  });

  it.each([
    ["invalid JSON", "{ not json", "Invalid JSON in"],
    ["non-object top level", "[1, 2]", "must contain a JSON object"],
    [
      "non-object piRedact",
      JSON.stringify({ piRedact: "report" }),
      "must be an object; it is ignored",
    ],
  ])("warns and disables for %s", async (_name, contents, fragment) => {
    const { root, global } = await workspace();
    await writeFile(global, contents);
    const config = await loadLogConfig(root, true, {
      global,
      project: join(root, "missing-project.json"),
    });
    expect(config.mode).toBeNull();
    expect(config.warnings.join(" ")).toContain(fragment);
  });
});

describe("SessionLogger", () => {
  it("writes a report entry without the payload or its content", async () => {
    const { root } = await workspace();
    const dir = join(root, "logs");
    const path = logPathFor(testConfig(dir), "s1");
    const logger = new SessionLogger(testConfig(dir), path, vi.fn());

    await logger.log(INPUT);

    const [line] = await readLines(path);
    expect(line).toBeDefined();
    const entry = JSON.parse(line as string) as Record<string, unknown>;
    expect(entry).toMatchObject({
      session: "s1",
      cwd: "/project",
      mode: "report",
      count: 1,
      categories: { "configured-literal": 1 },
      payloadBytes: Buffer.byteLength(JSON.stringify(INPUT.payload)),
    });
    expect(typeof entry.ts).toBe("string");
    expect(entry).not.toHaveProperty("payload");
    expect(await readFile(path, "utf8")).not.toContain("top-secret-value");
  });

  it("includes the redacted payload only in payload mode", async () => {
    const { root } = await workspace();
    const dir = join(root, "logs");
    const payload = {
      messages: [{ role: "user", content: REDACTION }],
    };
    const path = logPathFor(testConfig(dir, { mode: "payload" }), "s1");
    const logger = new SessionLogger(
      testConfig(dir, { mode: "payload" }),
      path,
      vi.fn(),
    );

    await logger.log({ ...INPUT, payload });

    const [line] = await readLines(path);
    const entry = JSON.parse(line as string) as Record<string, unknown>;
    expect(entry.payload).toEqual(payload);
    expect(entry.payloadBytes).toBe(Buffer.byteLength(JSON.stringify(payload)));
  });

  it("writes one marker and stops when the size cap is reached", async () => {
    const { root } = await workspace();
    const dir = join(root, "logs");
    const path = logPathFor(testConfig(dir, { maxBytes: 1000 }), "s1");
    const logger = new SessionLogger(
      testConfig(dir, { maxBytes: 1000 }),
      path,
      vi.fn(),
    );
    const input = {
      ...INPUT,
      // Bulk the entry with a field that IS serialized in report mode; the
      // 400-byte payload alone would not appear in the file at all.
      cwd: "B".repeat(400),
      payload: "A".repeat(400),
    };

    await logger.log(input);
    expect(await readLines(path)).toHaveLength(1);

    await logger.log(input);
    const lines = await readLines(path);
    expect(lines).toHaveLength(2);
    const marker = JSON.parse(lines[1] as string) as {
      note?: string;
      payload?: unknown;
    };
    expect(marker.note).toContain("size limit");
    expect(marker).not.toHaveProperty("payload");

    await logger.log(input);
    expect(await readLines(path)).toHaveLength(2);
  });

  it("serializes concurrent writes so the cap is enforced exactly once", async () => {
    const { root } = await workspace();
    const dir = join(root, "logs");
    const path = logPathFor(testConfig(dir, { maxBytes: 1000 }), "s1");
    const logger = new SessionLogger(
      testConfig(dir, { maxBytes: 1000 }),
      path,
      vi.fn(),
    );
    const input = {
      ...INPUT,
      cwd: "B".repeat(400),
      payload: "A".repeat(400),
    };

    await Promise.all([
      logger.log(input),
      logger.log(input),
      logger.log(input),
      logger.log(input),
      logger.log(input),
    ]);

    const lines = await readLines(path);
    expect(lines).toHaveLength(2);
    const entry = JSON.parse(lines[0] as string) as Record<string, unknown>;
    expect(entry).toHaveProperty("payloadBytes");
    const marker = JSON.parse(lines[1] as string) as { note?: string };
    expect(marker.note).toContain("size limit");
  });

  it("measures the cap in bytes, not characters", async () => {
    const { root } = await workspace();
    const dir = join(root, "logs");
    const path = logPathFor(testConfig(dir, { maxBytes: 1000 }), "s1");
    const logger = new SessionLogger(
      testConfig(dir, { maxBytes: 1000 }),
      path,
      vi.fn(),
    );
    // 200 CJK characters: 200 UTF-16 units but 600 UTF-8 bytes each line.
    const input = { ...INPUT, cwd: "中".repeat(200), payload: "A".repeat(400) };

    await logger.log(input);
    expect(await readLines(path)).toHaveLength(1);

    await logger.log(input);
    const lines = await readLines(path);
    expect(lines).toHaveLength(2);
    const marker = JSON.parse(lines[1] as string) as { note?: string };
    expect(marker.note).toContain("size limit");
  });

  it("treats maxBytes 0 as unlimited", async () => {
    const { root } = await workspace();
    const dir = join(root, "logs");
    const path = logPathFor(testConfig(dir, { maxBytes: 0 }), "s1");
    const logger = new SessionLogger(
      testConfig(dir, { maxBytes: 0 }),
      path,
      vi.fn(),
    );

    await logger.log(INPUT);
    await logger.log(INPUT);

    expect(await readLines(path)).toHaveLength(2);
  });

  it("writes nothing when disabled", async () => {
    const { root } = await workspace();
    const dir = join(root, "never");
    const path = logPathFor(testConfig(dir, { mode: null }), "s1");
    const logger = new SessionLogger(
      testConfig(dir, { mode: null }),
      path,
      vi.fn(),
    );

    await expect(logger.log(INPUT)).resolves.toBeUndefined();

    await expect(stat(dir)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("reports write failures once without throwing", async () => {
    const { root } = await workspace();
    const blocker = join(root, "blocker");
    await writeFile(blocker, "file, not a directory");
    const dir = join(blocker, "sub");
    const onError = vi.fn();
    const logger = new SessionLogger(
      testConfig(dir),
      logPathFor(testConfig(dir), "s1"),
      onError,
    );

    await expect(logger.log(INPUT)).resolves.toBeUndefined();
    await logger.log(INPUT);

    expect(onError).toHaveBeenCalledTimes(1);
    expect(onError.mock.calls[0]?.[0]).toContain("could not write");
  });

  it("creates files and directories without group or other access", async () => {
    const { root } = await workspace();
    const dir = join(root, "logs");
    const path = logPathFor(testConfig(dir), "s1");
    const logger = new SessionLogger(testConfig(dir), path, vi.fn());

    await logger.log(INPUT);

    const file = await stat(path);
    const parent = await stat(dir);
    expect(file.mode & 0o777 & 0o077).toBe(0);
    expect(parent.mode & 0o777 & 0o077).toBe(0);
  });

  it("sanitizes session ids for use as filenames", () => {
    const root = "/somewhere";
    const path = logPathFor(
      testConfig(join(root, "logs")),
      "2025-01-01T00/abc:1",
    );
    expect(path).toBe(join(root, "logs", "2025-01-01T00_abc_1.jsonl"));
  });
});

describe("safeSessionFileBase", () => {
  it("keeps safe characters and replaces everything else", () => {
    expect(safeSessionFileBase("2025-01-01T00-00-00/abc:123")).toBe(
      "2025-01-01T00-00-00_abc_123",
    );
    expect(safeSessionFileBase("ok-1_2")).toBe("ok-1_2");
    expect(safeSessionFileBase("")).toBe("unknown");
    expect(safeSessionFileBase("///")).toBe("unknown");
  });
});
