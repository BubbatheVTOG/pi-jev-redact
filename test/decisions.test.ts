import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  DecisionStore,
  defaultDecisionDir,
  loadDecisionConfig,
} from "../src/decisions.js";

const FINGERPRINT_A = "a".repeat(64);
const FINGERPRINT_B = "b".repeat(64);

describe("decision configuration", () => {
  it("uses platform-appropriate cache roots", () => {
    expect(defaultDecisionDir("linux", {}, "/home/test")).toBe(
      "/home/test/.cache/pi-jev-redact",
    );
    expect(
      defaultDecisionDir("linux", { XDG_CACHE_HOME: "/cache" }, "/home/test"),
    ).toBe("/cache/pi-jev-redact");
    expect(defaultDecisionDir("darwin", {}, "/Users/test")).toBe(
      "/Users/test/Library/Caches/pi-jev-redact",
    );
    expect(
      defaultDecisionDir(
        "win32",
        { LOCALAPPDATA: "C:\\Users\\test\\AppData\\Local" },
        "C:\\Users\\test",
      ),
    ).toContain("pi-jev-redact");
  });

  it("lets trusted project settings override the global decisionDir", async () => {
    const root = await mkdtemp(join(tmpdir(), "pi-redact-decisions-config-"));
    const global = join(root, "global.json");
    const project = join(root, "project.json");
    await writeFile(
      global,
      JSON.stringify({ piRedact: { decisionDir: "/global/cache" } }),
    );
    await writeFile(
      project,
      JSON.stringify({ piRedact: { decisionDir: "/project/cache" } }),
    );

    await expect(
      loadDecisionConfig(root, true, { global, project }),
    ).resolves.toMatchObject({ dir: "/project/cache", warnings: [] });
    await expect(
      loadDecisionConfig(root, false, { global, project }),
    ).resolves.toMatchObject({ dir: "/global/cache", warnings: [] });
  });
});

describe("DecisionStore", () => {
  it("persists only fingerprints and decisions across instances", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pi-redact-decisions-"));
    const first = new DecisionStore(dir);
    await first.record([FINGERPRINT_A], "approved", ["email"]);
    await first.record([FINGERPRINT_B], "denied", ["openai-key"]);

    const second = new DecisionStore(dir);
    const decisions = await second.decisionsFor([FINGERPRINT_A, FINGERPRINT_B]);
    expect(decisions.get(FINGERPRINT_A)).toBe("approved");
    expect(decisions.get(FINGERPRINT_B)).toBe("denied");

    const path = join(dir, "decisions.json");
    const contents = await readFile(path, "utf8");
    expect(contents).toContain(FINGERPRINT_A);
    expect(contents).not.toContain("raw-secret-value");
    if (process.platform !== "win32") {
      expect((await stat(path)).mode & 0o777).toBe(0o600);
    }
  });

  it("merges concurrent writes from separate store instances", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pi-redact-decisions-race-"));
    const first = new DecisionStore(dir);
    const second = new DecisionStore(dir);

    await Promise.all([
      first.record([FINGERPRINT_A], "approved", ["email"]),
      second.record([FINGERPRINT_B], "denied", ["openai-key"]),
    ]);

    const verifier = new DecisionStore(dir);
    const decisions = await verifier.decisionsFor([
      FINGERPRINT_A,
      FINGERPRINT_B,
    ]);
    expect(decisions.get(FINGERPRINT_A)).toBe("approved");
    expect(decisions.get(FINGERPRINT_B)).toBe("denied");
  });

  it("fails open and warns once when the cache is invalid", async () => {
    const dir = await mkdtemp(join(tmpdir(), "pi-redact-decisions-invalid-"));
    await writeFile(join(dir, "decisions.json"), "not-json");
    const onError = vi.fn();
    const store = new DecisionStore(dir, onError);

    await expect(store.decisionsFor([FINGERPRINT_A])).resolves.toEqual(
      new Map(),
    );
    await expect(store.decisionsFor([FINGERPRINT_B])).resolves.toEqual(
      new Map(),
    );
    expect(onError).toHaveBeenCalledTimes(1);
  });
});
