import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { loadConfig, type LoadedConfig } from "./config.js";
import { redactPayload } from "./payload.js";

const DEFAULT_CONFIG: LoadedConfig = {
  enabled: true,
  notify: true,
  blocked: true,
  rules: [],
  warnings: ["configuration has not loaded"],
};

export type ConfigLoader = typeof loadConfig;

export default function piRedact(pi: ExtensionAPI): void {
  registerPiRedact(pi);
}

export function registerPiRedact(
  pi: ExtensionAPI,
  configLoader: ConfigLoader = loadConfig,
): void {
  let configPromise = Promise.resolve(DEFAULT_CONFIG);

  pi.on("session_start", async (_event, ctx) => {
    const nextConfig = configLoader(ctx.cwd, ctx.isProjectTrusted()).catch(
      (): LoadedConfig => ({
        ...DEFAULT_CONFIG,
        warnings: [
          "configuration could not be loaded; provider requests are blocked",
        ],
      }),
    );
    configPromise = nextConfig;
    const config = await nextConfig;

    if (!ctx.hasUI) return;
    for (const warning of config.warnings) {
      ctx.ui.notify(`pi-jev-redact: ${warning}`, "warning");
    }
  });

  pi.on("before_provider_request", async (event, ctx) => {
    const config = await configPromise;
    if (!config.enabled) return;
    if (config.blocked) {
      if (config.notify && ctx.hasUI) {
        ctx.ui.notify(
          "pi-jev-redact blocked a provider request because configuration is invalid",
          "error",
        );
      }
      return {};
    }
    if (config.rules.length === 0) return;

    const result = redactPayload(event.payload, config.rules);
    if (result.count === 0) return;

    if (config.notify && ctx.hasUI) {
      const categories = Object.keys(result.categories)
        .sort((left, right) => left.localeCompare(right))
        .join(", ");
      ctx.ui.notify(
        `pi-jev-redact replaced ${result.count} sensitive value${result.count === 1 ? "" : "s"} (${categories})`,
        "warning",
      );
    }

    return result.payload;
  });
}
