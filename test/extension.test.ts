import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { registerPiRedact } from "../src/index.js";
import { DEFAULT_LOG_DIR, type LogConfig } from "../src/logger.js";
import { literalRule, REDACTION } from "../src/redactor.js";

interface FakeContext {
  cwd: string;
  hasUI: boolean;
  isProjectTrusted(): boolean;
  sessionManager: { getSessionId(): string };
  ui: {
    notify(message: string, level: string): void;
    confirm?(title: string, message: string): Promise<boolean>;
  };
}

type Handler = (event: { payload?: unknown }, context: FakeContext) => unknown;

function disabledLogConfig(): Promise<LogConfig> {
  return Promise.resolve({
    mode: null,
    dir: DEFAULT_LOG_DIR,
    maxBytes: 0,
    warnings: [],
  });
}

function fakePi(): { handlers: Map<string, Handler>; pi: ExtensionAPI } {
  const handlers = new Map<string, Handler>();
  const pi = {
    on(name: string, handler: Handler) {
      handlers.set(name, handler);
    },
  } as unknown as ExtensionAPI;
  return { handlers, pi };
}

describe("pi-jev-redact extension", () => {
  it("replaces the final provider payload and emits only safe metadata", async () => {
    const { handlers, pi } = fakePi();
    const notify = vi.fn();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: true,
      isProjectTrusted: () => true,
      sessionManager: { getSessionId: () => "test-session" },
      ui: { notify },
    };
    const secret = "extension-secret";

    registerPiRedact(
      pi,
      () =>
        Promise.resolve({
          enabled: true,
          notify: true,
          confirmIntent: false,
          threshold: 5,
          blocked: false,
          rules: [literalRule("configured-literal", secret)],
          warnings: [],
        }),
      disabledLogConfig,
    );

    const sessionStart = handlers.get("session_start");
    const beforeRequest = handlers.get("before_provider_request");
    expect(sessionStart).toBeDefined();
    expect(beforeRequest).toBeDefined();
    await sessionStart?.({}, context);

    const original = { messages: [{ role: "user", content: secret }] };
    const result = await beforeRequest?.({ payload: original }, context);

    expect(result).toEqual({
      messages: [{ role: "user", content: REDACTION }],
    });
    expect(original.messages[0]?.content).toBe(secret);
    expect(notify).toHaveBeenCalledWith(
      "pi-jev-redact replaced 1 sensitive value (configured-literal)",
      "warning",
    );
    expect(JSON.stringify(notify.mock.calls)).not.toContain(secret);
  });

  it("fails closed when configuration loading fails", async () => {
    const { handlers, pi } = fakePi();
    const notify = vi.fn();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: true,
      isProjectTrusted: () => true,
      sessionManager: { getSessionId: () => "test-session" },
      ui: { notify },
    };

    registerPiRedact(
      pi,
      () => Promise.reject(new Error("contains-sensitive-details")),
      disabledLogConfig,
    );
    await handlers.get("session_start")?.({}, context);

    await expect(
      handlers.get("before_provider_request")?.(
        { payload: { text: "must-not-leave" } },
        context,
      ),
    ).resolves.toEqual({});
    expect(JSON.stringify(notify.mock.calls)).not.toContain(
      "contains-sensitive-details",
    );
    expect(JSON.stringify(notify.mock.calls)).not.toContain("must-not-leave");
  });

  it("does not return a replacement when no rule matches", async () => {
    const { handlers, pi } = fakePi();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: false,
      isProjectTrusted: () => false,
      sessionManager: { getSessionId: () => "test-session" },
      ui: { notify: vi.fn() },
    };

    registerPiRedact(
      pi,
      () =>
        Promise.resolve({
          enabled: true,
          notify: true,
          confirmIntent: false,
          threshold: 5,
          blocked: false,
          rules: [literalRule("configured-literal", "not-present")],
          warnings: [],
        }),
      disabledLogConfig,
    );
    await handlers.get("session_start")?.({}, context);

    await expect(
      handlers.get("before_provider_request")?.(
        { payload: { text: "safe" } },
        context,
      ),
    ).resolves.toBeUndefined();
  });

  it("logs a report entry per request when enabled and announces the dir once", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pi-redact-ext-"));
    const { handlers, pi } = fakePi();
    const notify = vi.fn();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: true,
      isProjectTrusted: () => true,
      sessionManager: { getSessionId: () => "test-session" },
      ui: { notify },
    };
    const secret = "extension-secret";

    registerPiRedact(
      pi,
      () =>
        Promise.resolve({
          enabled: true,
          notify: true,
          confirmIntent: false,
          threshold: 5,
          blocked: false,
          rules: [literalRule("configured-literal", secret)],
          warnings: [],
        }),
      () =>
        Promise.resolve({
          mode: "report" as const,
          dir,
          maxBytes: 0,
          warnings: [],
        }),
    );
    await handlers.get("session_start")?.({}, context);

    const original = { messages: [{ role: "user", content: secret }] };
    await handlers.get("before_provider_request")?.(
      { payload: original },
      context,
    );
    await handlers.get("before_provider_request")?.(
      { payload: original },
      context,
    );

    const contents = await readFile(join(dir, "test-session.jsonl"), "utf8");
    const lines = contents.trimEnd().split("\n");
    expect(lines).toHaveLength(2);
    const entry = JSON.parse(lines[0] as string) as Record<string, unknown>;
    expect(entry).toMatchObject({
      session: "test-session",
      cwd: "/project",
      mode: "report",
      count: 1,
      categories: { "configured-literal": 1 },
    });
    expect(entry).not.toHaveProperty("payload");
    expect(contents).not.toContain(secret);

    const infoCalls = notify.mock.calls.filter((call) => call[1] === "info");
    expect(infoCalls).toHaveLength(1);
    expect(infoCalls[0]?.[0]).toContain(dir);
  });

  it("logs requests with no matches when logging is enabled", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pi-redact-ext-"));
    const { handlers, pi } = fakePi();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: false,
      isProjectTrusted: () => false,
      sessionManager: { getSessionId: () => "test-session" },
      ui: { notify: vi.fn() },
    };

    registerPiRedact(
      pi,
      () =>
        Promise.resolve({
          enabled: true,
          notify: true,
          confirmIntent: false,
          threshold: 5,
          blocked: false,
          rules: [literalRule("configured-literal", "not-present")],
          warnings: [],
        }),
      () =>
        Promise.resolve({
          mode: "report" as const,
          dir,
          maxBytes: 0,
          warnings: [],
        }),
    );
    await handlers.get("session_start")?.({}, context);

    await expect(
      handlers.get("before_provider_request")?.(
        { payload: { text: "safe" } },
        context,
      ),
    ).resolves.toBeUndefined();

    const contents = await readFile(join(dir, "test-session.jsonl"), "utf8");
    const entry = JSON.parse(
      contents.trimEnd().split("\n")[0] as string,
    ) as Record<string, unknown>;
    expect(entry.count).toBe(0);
    expect(entry.categories).toEqual({});
    expect(entry).not.toHaveProperty("payload");
  });
});

describe("sensitive-send decisions", () => {
  it("asks once for a new chunk and remembers an approval", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pi-redact-approval-"));
    const { handlers, pi } = fakePi();
    const confirm = vi.fn().mockResolvedValue(true);
    const notify = vi.fn();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: true,
      isProjectTrusted: () => true,
      sessionManager: { getSessionId: () => "approval-session" },
      ui: { notify, confirm },
    };
    const sensitive = "sensitive-chunk-value";

    registerPiRedact(
      pi,
      () =>
        Promise.resolve({
          enabled: true,
          notify: true,
          confirmIntent: true,
          threshold: 5,
          blocked: false,
          rules: [literalRule("configured-literal", sensitive)],
          warnings: [],
        }),
      disabledLogConfig,
      () => Promise.resolve({ dir, warnings: [] }),
    );
    await handlers.get("session_start")?.({}, context);

    const payload = { text: sensitive };
    const results = await Promise.all([
      handlers.get("before_provider_request")?.({ payload }, context),
      handlers.get("before_provider_request")?.({ payload }, context),
    ]);
    expect(results).toEqual([{ text: REDACTION }, { text: REDACTION }]);
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(confirm.mock.calls)).not.toContain(sensitive);
  });

  it("censors a denied chunk and silently blocks it if it reappears", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pi-redact-denial-"));
    const { handlers, pi } = fakePi();
    const confirm = vi.fn().mockResolvedValue(false);
    const notify = vi.fn();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: true,
      isProjectTrusted: () => true,
      sessionManager: { getSessionId: () => "denial-session" },
      ui: { notify, confirm },
    };
    const sensitive = "another-sensitive-chunk";

    registerPiRedact(
      pi,
      () =>
        Promise.resolve({
          enabled: true,
          notify: true,
          confirmIntent: true,
          threshold: 5,
          blocked: false,
          rules: [literalRule("configured-literal", sensitive)],
          warnings: [],
        }),
      disabledLogConfig,
      () => Promise.resolve({ dir, warnings: [] }),
    );
    await handlers.get("session_start")?.({}, context);

    const payload = { text: sensitive };
    await expect(
      handlers.get("before_provider_request")?.({ payload }, context),
    ).resolves.toEqual({});
    await expect(
      handlers.get("before_provider_request")?.({ payload }, context),
    ).resolves.toEqual({});
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith(
      "pi-jev-redact censored the provider request at the user's direction",
      "error",
    );
  });
});
