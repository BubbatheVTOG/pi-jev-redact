import type {
  ExtensionAPI,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { loadConfig, type LoadedConfig } from "./config.js";
import {
  DEFAULT_LOG_DIR,
  DEFAULT_LOG_MAX_BYTES,
  loadLogConfig,
  logConfigLocations,
  logPathFor,
  SessionLogger,
  type LogConfig,
} from "./logger.js";
import { redactPayload, type PayloadRedactionResult } from "./payload.js";

const DEFAULT_CONFIG: LoadedConfig = {
  enabled: true,
  notify: true,
  blocked: true,
  rules: [],
  warnings: ["configuration has not loaded"],
};

const DEFAULT_LOG_CONFIG: LogConfig = {
  mode: null,
  dir: DEFAULT_LOG_DIR,
  maxBytes: DEFAULT_LOG_MAX_BYTES,
  warnings: [],
};

export type ConfigLoader = typeof loadConfig;
export type LogConfigLoader = typeof loadLogConfig;

export default function piRedact(pi: ExtensionAPI): void {
  registerPiRedact(pi);
}

export function registerPiRedact(
  pi: ExtensionAPI,
  configLoader: ConfigLoader = loadConfig,
  logConfigLoader: LogConfigLoader = loadLogConfig,
): void {
  let configPromise = Promise.resolve(DEFAULT_CONFIG);
  let logConfigPromise = Promise.resolve(DEFAULT_LOG_CONFIG);
  const loggers = new Map<string, SessionLogger>();
  const announcedSessions = new Set<string>();

  pi.on("session_start", async (_event, ctx) => {
    const trusted = ctx.isProjectTrusted();
    const nextConfig = configLoader(ctx.cwd, trusted).catch(
      (): LoadedConfig => ({
        ...DEFAULT_CONFIG,
        warnings: [
          "configuration could not be loaded; provider requests are blocked",
        ],
      }),
    );
    configPromise = nextConfig;
    const nextLogConfig = logConfigLoader(
      ctx.cwd,
      trusted,
      logConfigLocations(ctx.cwd),
    ).catch((): LogConfig => ({
      ...DEFAULT_LOG_CONFIG,
      warnings: [
        "logging configuration could not be loaded; logging is disabled",
      ],
    }));
    logConfigPromise = nextLogConfig;

    const [config, logConfig] = await Promise.all([nextConfig, nextLogConfig]);

    if (!ctx.hasUI) return;
    for (const warning of [...config.warnings, ...logConfig.warnings]) {
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

    const result =
      config.rules.length === 0
        ? { payload: event.payload, count: 0, categories: {} }
        : redactPayload(event.payload, config.rules);

    if (result.count > 0 && config.notify && ctx.hasUI) {
      const categories = Object.keys(result.categories)
        .sort((left, right) => left.localeCompare(right))
        .join(", ");
      ctx.ui.notify(
        `pi-jev-redact replaced ${result.count} sensitive value${result.count === 1 ? "" : "s"} (${categories})`,
        "warning",
      );
    }

    await logProviderRequest(ctx, result);

    return result.count > 0 ? result.payload : undefined;
  });

  async function logProviderRequest(
    ctx: ExtensionContext,
    result: PayloadRedactionResult,
  ): Promise<void> {
    const logConfig = await logConfigPromise;
    if (logConfig.mode === null) return;

    const sessionId = ctx.sessionManager.getSessionId();
    let logger = loggers.get(sessionId);
    if (!logger) {
      logger = new SessionLogger(
        logConfig,
        logPathFor(logConfig, sessionId),
        (message) => {
          if (ctx.hasUI) ctx.ui.notify(message, "warning");
        },
      );
      loggers.set(sessionId, logger);
    }

    await logger.log({
      session: sessionId,
      cwd: ctx.cwd,
      count: result.count,
      categories: result.categories,
      payload: result.payload,
    });

    if (ctx.hasUI && !announcedSessions.has(sessionId)) {
      announcedSessions.add(sessionId);
      ctx.ui.notify(
        `pi-jev-redact is logging provider payloads to ${logConfig.dir}`,
        "info",
      );
    }
  }
}
