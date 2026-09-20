import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, parseConfig } from "../src/config.js";
import { redactText } from "../src/redactor.js";

describe("parseConfig", () => {
  it("accepts the documented configuration shape", () => {
    expect(
      parseConfig(
        JSON.stringify({
          enabled: true,
          builtins: true,
          notify: false,
          env: ["MY_SECRET"],
          literals: ["private.example.test"],
          patterns: [{ pattern: "SECRET-[A-Z0-9]{12}" }],
        }),
      ),
    ).toEqual({
      enabled: true,
      builtins: true,
      notify: false,
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

  it("rejects malformed custom rules", () => {
    expect(() => parseConfig('{"literals":["abc"]}')).toThrow();
    expect(() => parseConfig('{"patterns":[{"pattern":"(a+)+"}]}')).toThrow();
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
    ).toBe("***** *****");
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
