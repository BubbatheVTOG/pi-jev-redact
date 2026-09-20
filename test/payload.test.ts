import { describe, expect, it } from "vitest";
import { redactPayload } from "../src/payload.js";
import { literalRule } from "../src/redactor.js";

const SECRET = "super-secret-value";
const rules = [literalRule("configured", SECRET)];

describe("redactPayload", () => {
  it("redacts strings recursively without mutating the provider payload", () => {
    const payload = {
      system: `system ${SECRET}`,
      messages: [
        { role: "user", content: `user ${SECRET}` },
        { role: "tool", content: [{ type: "text", text: `tool ${SECRET}` }] },
      ],
    };

    const result = redactPayload(payload, rules);

    expect(result.payload).toEqual({
      system: "system *****",
      messages: [
        { role: "user", content: "user *****" },
        { role: "tool", content: [{ type: "text", text: "tool *****" }] },
      ],
    });
    expect(payload.system).toContain(SECRET);
    expect(result.count).toBe(3);
  });

  it("preserves image and long base64 data", () => {
    const base64 = "A".repeat(1024);
    const payload = {
      image: { type: "image", data: SECRET },
      dataUri: `data:image/png;base64,${SECRET}`,
      blob: base64,
      text: SECRET,
    };

    const result = redactPayload(payload, rules);
    expect(result.payload).toEqual({
      image: { type: "image", data: SECRET },
      dataUri: `data:image/png;base64,${SECRET}`,
      blob: base64,
      text: "*****",
    });
    expect(result.count).toBe(1);
  });

  it("handles cycles without mutating the original graph", () => {
    const payload: { text: string; self?: unknown } = { text: SECRET };
    payload.self = payload;

    const result = redactPayload(payload, rules);
    const copy = result.payload as typeof payload;
    expect(copy).not.toBe(payload);
    expect(copy.text).toBe("*****");
    expect(copy.self).toBe(copy);
  });
});
