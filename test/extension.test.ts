import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { describe, expect, it, vi } from "vitest";
import { registerPiRedact } from "../src/index.js";
import { literalRule } from "../src/redactor.js";

interface FakeContext {
  cwd: string;
  hasUI: boolean;
  isProjectTrusted(): boolean;
  ui: { notify(message: string, level: string): void };
}

type Handler = (event: { payload?: unknown }, context: FakeContext) => unknown;

describe("pi-jev-redact extension", () => {
  it("replaces the final provider payload and emits only safe metadata", async () => {
    const handlers = new Map<string, Handler>();
    const pi = {
      on(name: string, handler: Handler) {
        handlers.set(name, handler);
      },
    } as unknown as ExtensionAPI;
    const notify = vi.fn();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: true,
      isProjectTrusted: () => true,
      ui: { notify },
    };
    const secret = "extension-secret";

    registerPiRedact(pi, () =>
      Promise.resolve({
        enabled: true,
        notify: true,
        blocked: false,
        rules: [literalRule("configured-literal", secret)],
        warnings: [],
      }),
    );

    const sessionStart = handlers.get("session_start");
    const beforeRequest = handlers.get("before_provider_request");
    expect(sessionStart).toBeDefined();
    expect(beforeRequest).toBeDefined();
    await sessionStart?.({}, context);

    const original = { messages: [{ role: "user", content: secret }] };
    const result = await beforeRequest?.({ payload: original }, context);

    expect(result).toEqual({ messages: [{ role: "user", content: "*****" }] });
    expect(original.messages[0]?.content).toBe(secret);
    expect(notify).toHaveBeenCalledWith(
      "pi-jev-redact replaced 1 sensitive value (configured-literal)",
      "warning",
    );
    expect(JSON.stringify(notify.mock.calls)).not.toContain(secret);
  });

  it("fails closed when configuration loading fails", async () => {
    const handlers = new Map<string, Handler>();
    const pi = {
      on(name: string, handler: Handler) {
        handlers.set(name, handler);
      },
    } as unknown as ExtensionAPI;
    const notify = vi.fn();
    const context: FakeContext = {
      cwd: "/project",
      hasUI: true,
      isProjectTrusted: () => true,
      ui: { notify },
    };

    registerPiRedact(pi, () =>
      Promise.reject(new Error("contains-sensitive-details")),
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
    const handlers = new Map<string, Handler>();
    const pi = {
      on(name: string, handler: Handler) {
        handlers.set(name, handler);
      },
    } as unknown as ExtensionAPI;
    const context: FakeContext = {
      cwd: "/project",
      hasUI: false,
      isProjectTrusted: () => false,
      ui: { notify: vi.fn() },
    };

    registerPiRedact(pi, () =>
      Promise.resolve({
        enabled: true,
        notify: true,
        blocked: false,
        rules: [literalRule("configured-literal", "not-present")],
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
  });
});
