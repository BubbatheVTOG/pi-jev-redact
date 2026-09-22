import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, parseConfig } from "../src/config.js";
import { redactText, REDACTION } from "../src/redactor.js";

describe("parseConfig", () => {
  it("accepts the documented configuration shape", () => {
    expect(
      parseConfig(
        JSON.stringify({
          enabled: true,
          builtins: true,
          pii: false,
          notify: false,
          confirmIntent: true,
          threshold: 7,
          env: ["MY_SECRET"],
          literals: ["private.example.test"],
          patterns: [{ pattern: "SECRET-[A-Z0-9]{12}" }],
        }),
      ),
    ).toEqual({
      enabled: true,
      builtins: true,
      pii: false,
      notify: false,
      confirmIntent: true,
      threshold: 7,
      env: ["MY_SECRET"],
      literals: ["private.example.test"],
      patterns: [{ pattern: "SECRET-[A-Z0-9]{12}" }],
    });
  });

  it("rejects malformed JSON and unknown keys", () => {
    expect(() => parseConfig("{")).toThrow(/valid JSON/);
    expect(() => parseConfig('{"surprise": true}')).toThrow(
      /Unknown configuration key/,
    );
  });

  it("rejects malformed custom rules and threshold values", () => {
    expect(() => parseConfig('{"literals":["abc"]}')).toThrow();
    expect(() => parseConfig('{"patterns":[{"pattern":"(a+)+"}]}')).toThrow();
    expect(() => parseConfig('{"threshold":0}')).toThrow(
      /integer from 1 to 10/,
    );
    expect(() => parseConfig('{"threshold":7.5}')).toThrow(
      /integer from 1 to 10/,
    );
  });
});

describe("loadConfig", () => {
  it("merges global and trusted project rules and resolves environment values", async () => {
    const directory = await mkdtemp(join(tmpdir(), "pi-redact-"));
    const global = join(directory, "global.json");
    const project = join(directory, "project.json");
    await writeFile(
      global,
      JSON.stringify({ env: ["MY_SECRET"], notify: false }),
    );
    await writeFile(
      project,
      JSON.stringify({
        builtins: false,
        literals: ["private.example.test"],
      }),
    );

    const config = await loadConfig(
      directory,
      true,
      { MY_SECRET: "environment-secret" },
      { global, project },
    );

    expect(config.notify).toBe(false);
    expect(config.blocked).toBe(false);
    expect(
      redactText("environment-secret private.example.test", config.rules).value,
    ).toBe(`${REDACTION} ${REDACTION}`);
  });

  it("does not read project configuration for untrusted projects", async () => {
    const directory = await mkdtemp(join(tmpdir(), "pi-redact-"));
    const project = join(directory, "project.json");
    await writeFile(
      project,
      JSON.stringify({
        literals: ["private.example.test"],
      }),
    );

    const config = await loadConfig(
      directory,
      false,
      {},
      {
        global: join(directory, "missing"),
        project,
      },
    );
    expect(redactText("private.example.test", config.rules).value).toBe(
      "private.example.test",
    );
  });

  it("warns without exposing invalid configuration contents", async () => {
    const directory = await mkdtemp(join(tmpdir(), "pi-redact-"));
    const global = join(directory, "global.json");
    await writeFile(global, '{"literals":["top-secret"],"extra":true}');

    const config = await loadConfig(
      directory,
      false,
      {},
      {
        global,
        project: join(directory, "missing"),
      },
    );
    expect(config.warnings).toHaveLength(1);
    expect(config.blocked).toBe(true);
    expect(config.warnings.join(" ")).not.toContain("top-secret");
    expect(config.rules.length).toBeGreaterThan(0);
  });
});

describe("threshold tiers", () => {
  async function configFor(value: Record<string, unknown>) {
    const directory = await mkdtemp(join(tmpdir(), "pi-redact-tier-"));
    const global = join(directory, "global.json");
    await writeFile(global, JSON.stringify(value));
    return loadConfig(
      directory,
      false,
      {},
      {
        global,
        project: join(directory, "missing"),
      },
    );
  }

  it("defaults to threshold 5 with all established secret rules and no PII", async () => {
    const config = await configFor({});
    expect(config.threshold).toBe(5);
    expect(config.confirmIntent).toBe(true);
    expect(redactText("person@example.com", config.rules).count).toBe(0);
    expect(
      redactText(
        ["ghp", "abcdefghijklmnopqrstuvwxyz123456"].join("_"),
        config.rules,
      ).count,
    ).toBe(1);
  });

  it("uses core secrets at low levels and adds PII at level 7", async () => {
    const low = await configFor({ threshold: 2 });
    expect(
      redactText(
        ["ghp", "abcdefghijklmnopqrstuvwxyz123456"].join("_"),
        low.rules,
      ).count,
    ).toBe(0);
    expect(
      redactText(
        ["sk-proj", "abcdefghijklmnopqrstuvwxyz123456"].join("-"),
        low.rules,
      ).count,
    ).toBe(1);

    const pii = await configFor({ threshold: 7 });
    expect(redactText("person@example.com 555-867-5309", pii.rules).count).toBe(
      2,
    );
  });

  it("adds network and aggressive rules at level 9 with explicit overrides", async () => {
    const high = await configFor({ threshold: 9 });
    expect(
      redactText("Bearer abcdefghijklmnop 203.0.113.10", high.rules).count,
    ).toBe(2);

    const overridden = await configFor({
      threshold: 9,
      builtins: false,
      pii: false,
    });
    expect(
      redactText("Bearer abcdefghijklmnop 203.0.113.10", overridden.rules)
        .count,
    ).toBe(0);
  });
});
