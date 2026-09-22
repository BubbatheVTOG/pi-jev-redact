import { describe, expect, it } from "vitest";
import { redactPayload } from "../src/payload.js";
import { literalRule, REDACTION } from "../src/redactor.js";

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
      system: `system ${REDACTION}`,
      messages: [
        { role: "user", content: `user ${REDACTION}` },
        {
          role: "tool",
          content: [{ type: "text", text: `tool ${REDACTION}` }],
        },
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
      text: REDACTION,
    });
    expect(result.count).toBe(1);
  });

  it("handles cycles without mutating the original graph", () => {
    const payload: { text: string; self?: unknown } = { text: SECRET };
    payload.self = payload;

    const result = redactPayload(payload, rules);
    const copy = result.payload as typeof payload;
    expect(copy).not.toBe(payload);
    expect(copy.text).toBe(REDACTION);
    expect(copy.self).toBe(copy);
  });
});

it("preserves outbound credential headers while redacting other fields", () => {
  const payload = {
    headers: {
      Authorization: `Bearer ${SECRET}`,
      "x-api-key": SECRET,
      "x-trace-note": SECRET,
    },
    body: { text: SECRET },
  };

  const result = redactPayload(payload, rules);
  expect(result.payload).toEqual({
    headers: {
      Authorization: `Bearer ${SECRET}`,
      "x-api-key": SECRET,
      "x-trace-note": REDACTION,
    },
    body: { text: REDACTION },
  });
  expect(result.count).toBe(2);
});

it("forcibly redacts credential headers for logging", () => {
  const result = redactPayload(
    {
      headers: {
        Authorization: `Bearer ${SECRET}`,
        "x-api-key": SECRET,
      },
    },
    [],
    { preserveCredentialHeaders: false },
  );
  expect(result.payload).toEqual({
    headers: {
      Authorization: REDACTION,
      "x-api-key": REDACTION,
    },
  });
});

it("returns stable fingerprints without exposing original values", () => {
  const first = redactPayload({ text: SECRET }, rules);
  const second = redactPayload({ nested: [SECRET] }, rules);
  expect(first.fingerprints).toHaveLength(1);
  expect(first.fingerprints).toEqual(second.fingerprints);
  expect(first.fingerprints[0]).toMatch(/^[a-f0-9]{64}$/);
  expect(JSON.stringify(first.fingerprints)).not.toContain(SECRET);
});
