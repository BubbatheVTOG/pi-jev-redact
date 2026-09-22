import type {
  ExtensionAPI,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { DEFAULT_THRESHOLD, loadConfig, type LoadedConfig } from "./config.js";
import {
  DecisionStore,
  loadDecisionConfig,
  type DecisionConfig,
} from "./decisions.js";
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
  confirmIntent: true,
  threshold: DEFAULT_THRESHOLD,
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
export type DecisionConfigLoader = typeof loadDecisionConfig;

export default function piRedact(pi: ExtensionAPI): void {
  registerPiRedact(pi);
}

export function registerPiRedact(
  pi: ExtensionAPI,
  configLoader: ConfigLoader = loadConfig,
  logConfigLoader: LogConfigLoader = loadLogConfig,
  decisionConfigLoader: DecisionConfigLoader = loadDecisionConfig,
): void {
  let configPromise = Promise.resolve(DEFAULT_CONFIG);
  let logConfigPromise = Promise.resolve(DEFAULT_LOG_CONFIG);
  let decisionTail: Promise<void> = Promise.resolve();
  const loggers = new Map<string, SessionLogger>();
  const decisionStores = new Map<string, DecisionStore>();
  const reportedDecisionWarnings = new Set<string>();
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

    const result: PayloadRedactionResult =
      config.rules.length === 0
        ? { payload: event.payload, count: 0, categories: {}, fingerprints: [] }
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

    const sendDecision = await resolveSendIntent(ctx, config, result);
    const logPayload = redactPayload(result.payload, config.rules, {
      preserveCredentialHeaders: false,
    }).payload;
    await logProviderRequest(ctx, { ...result, payload: logPayload });
    if (sendDecision === "deny") {
      if (config.notify && ctx.hasUI) {
        ctx.ui.notify(
          "pi-jev-redact censored the provider request at the user's direction",
          "error",
        );
      }
      return {};
    }

    return result.count > 0 ? result.payload : undefined;
  });

  async function resolveSendIntent(
    ctx: ExtensionContext,
    config: LoadedConfig,
    result: PayloadRedactionResult,
  ): Promise<"allow" | "deny"> {
    let outcome: "allow" | "deny" = "allow";
    const work = decisionTail.then(async () => {
      outcome = await resolveSendIntentSerial(ctx, config, result);
    });
    decisionTail = work.catch(() => undefined);
    try {
      await work;
      return outcome;
    } catch {
      if (ctx.hasUI && !reportedDecisionWarnings.has("runtime")) {
        reportedDecisionWarnings.add("runtime");
        ctx.ui.notify(
          "pi-jev-redact could not resolve send intent; the request will proceed with redaction",
          "warning",
        );
      }
      return "allow";
    }
  }

  async function resolveSendIntentSerial(
    ctx: ExtensionContext,
    config: LoadedConfig,
    result: PayloadRedactionResult,
  ): Promise<"allow" | "deny"> {
    if (
      result.count === 0 ||
      !config.confirmIntent ||
      !ctx.hasUI ||
      typeof ctx.ui.confirm !== "function"
    ) {
      return "allow";
    }

    let decisionConfig: DecisionConfig;
    try {
      decisionConfig = await decisionConfigLoader(
        ctx.cwd,
        ctx.isProjectTrusted(),
      );
    } catch {
      if (!reportedDecisionWarnings.has("load")) {
        reportedDecisionWarnings.add("load");
        ctx.ui.notify(
          "pi-jev-redact could not load the decision cache; this request will proceed redacted",
          "warning",
        );
      }
      return "allow";
    }
    for (const warning of decisionConfig.warnings) {
      if (reportedDecisionWarnings.has(warning)) continue;
      reportedDecisionWarnings.add(warning);
      ctx.ui.notify(`pi-jev-redact: ${warning}`, "warning");
    }

    let store = decisionStores.get(decisionConfig.dir);
    if (!store) {
      store = new DecisionStore(decisionConfig.dir, (message) => {
        if (ctx.hasUI) ctx.ui.notify(message, "warning");
      });
      decisionStores.set(decisionConfig.dir, store);
    }
    const known = await store.decisionsFor(result.fingerprints);
    if (
      result.fingerprints.some(
        (fingerprint) => known.get(fingerprint) === "denied",
      )
    ) {
      return "deny";
    }
    const fresh = result.fingerprints.filter(
      (fingerprint) => !known.has(fingerprint),
    );
    if (fresh.length === 0) return "allow";

    const categories = Object.keys(result.categories)
      .sort((left, right) => left.localeCompare(right))
      .join(", ");
    const approved = await ctx.ui.confirm(
      "pi-jev-redact: sensitive data detected",
      `${fresh.length} new sensitive value${fresh.length === 1 ? "" : "s"} (${categories}) would be sent after redaction. Was sending this information intended?`,
    );
    await store.record(
      fresh,
      approved ? "approved" : "denied",
      Object.keys(result.categories),
    );
    return approved ? "allow" : "deny";
  }

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
