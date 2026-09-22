import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

const readmeUrl = new URL("../README.md", import.meta.url);

describe("README public contract", () => {
  it("documents how to disable redaction near the top", async () => {
    const readme = await readFile(readmeUrl, "utf8");
    const disableSection = readme.indexOf("## Disable or pause redaction");
    const installSection = readme.indexOf("## Install");
    expect(disableSection).toBeGreaterThan(0);
    expect(disableSection).toBeLessThan(installSection);
    expect(readme).toContain('"enabled": false');
    expect(readme).toContain("pi config");
    expect(readme).toContain("/reload");
  });

  it("documents every redaction configuration key", async () => {
    const readme = await readFile(readmeUrl, "utf8");
    for (const key of [
      "enabled",
      "threshold",
      "builtins",
      "pii",
      "notify",
      "confirmIntent",
      "env",
      "literals",
      "patterns",
      "patterns[].pattern",
      "patterns[].flags",
    ]) {
      expect(readme).toContain(`\`${key}\``);
    }
    expect(readme).toMatch(/1–10/);
    expect(readme).toMatch(/64 KiB/);
  });

  it("documents every settings.json key and persistence guarantee", async () => {
    const readme = await readFile(readmeUrl, "utf8");
    for (const key of ["log", "logDir", "logMaxBytes", "decisionDir"]) {
      expect(readme).toContain(`\`${key}\``);
    }
    expect(readme).toMatch(/10,000 entries/);
    expect(readme).toMatch(/cross-process lock\/reload\/merge/);
    expect(readme).toMatch(/credential-header values.*forcibly replaced/is);
  });

  it("documents the real Pi authentication-header integration test", async () => {
    const readme = await readFile(readmeUrl, "utf8");
    expect(readme).toContain("npm run test:integration:auth");
    expect(readme).toMatch(/transport credential arrives\s+unchanged/i);
    expect(readme).toMatch(
      /key-shaped value placed in prompt content is replaced/i,
    );
  });
});
