import os from "node:os";
import { join, resolve } from "node:path";

/**
 * Reads the bridge configuration from the environment. Everything that points
 * at OpenBot defaults to the locations the OpenBot desktop app uses, so the
 * bridge works without copying any state.
 *
 * `overrides` wins over the environment; tests use it, and so can a future
 * launcher that reads a config file.
 */
export function loadConfig(env = process.env, overrides = {}) {
  const home = env.HOME || os.homedir();
  const openbotConfig = env.OPENBOT_CONFIG_DIR || join(home, ".config", "OpenBot");
  const dataDir = resolve(env.BRIDGE_DATA_DIR || join(process.cwd(), "data"));

  const config = {
    port: Number(env.BRIDGE_PORT || 8790),
    host: env.BRIDGE_HOST || "127.0.0.1",
    publicUrl: (env.BRIDGE_PUBLIC_URL || "").replace(/\/+$/, ""),
    adminSecret: env.BRIDGE_ADMIN_SECRET || "",
    dataDir,
    openbot: {
      dbPath: env.OPENBOT_DB || join(openbotConfig, "openbot.db"),
      automationDir: env.OPENBOT_AUTOMATION_DIR || join(openbotConfig, "automation"),
      configDir: openbotConfig,
    },
    clientAgentIds: JSON.parse(env.BRIDGE_CLIENT_AGENT_IDS || "{}"),
    allowedOrigins: (env.BRIDGE_ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean),
    allowedAgents: (env.BRIDGE_ALLOWED_AGENT_IDS ?? env.BRIDGE_ALLOWED_AGENTS ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    readOnly: !["0", "false"].includes(env.BRIDGE_READ_ONLY),
    extendedTools: env.BRIDGE_EXTENDED_TOOLS === "1",
    events: env.BRIDGE_EVENTS === "1" || env.BRIDGE_EVENTS === "true",
    approvalTtlSeconds: Number(env.BRIDGE_APPROVAL_TTL_SECONDS ?? 120),
    notify: {
      mode: env.BRIDGE_NOTIFY ?? "off",
      webhookUrl: env.BRIDGE_NOTIFY_WEBHOOK_URL ?? "",
      secretFile: env.BRIDGE_NOTIFY_SECRET_FILE ?? "",
      allowLoopbackHttp: env.BRIDGE_NOTIFY_ALLOW_LOOPBACK_HTTP === "1",
      timeoutMs: Number(env.BRIDGE_NOTIFY_TIMEOUT_MS ?? 3000),
    },
    logLevel: env.BRIDGE_LOG_LEVEL || "info",
    sharedDir: env.OPENBOT_SHARED_DIR || join(home, "OpenBot", "Shared"),
    ...overrides,
    openbot: { ...{ dbPath: env.OPENBOT_DB || join(openbotConfig, "openbot.db"), automationDir: env.OPENBOT_AUTOMATION_DIR || join(openbotConfig, "automation"), configDir: openbotConfig }, ...(overrides.openbot ?? {}) },
    limits: {
      requestsPerMinute: Number(env.BRIDGE_RPM || 90),
      approvalsPerGrantPerMinute: Number(env.BRIDGE_APPROVALS_PER_GRANT_PER_MINUTE ?? 8),
      globalApprovalsPerMinute: Number(env.BRIDGE_GLOBAL_APPROVALS_PER_MINUTE ?? 40),
      writesPerMinute: Number(env.BRIDGE_WRITES_PER_MINUTE ?? 12),
      globalWritesPerMinute: Number(env.BRIDGE_GLOBAL_WRITES_PER_MINUTE ?? 60),
      maxMessageChars: Number(env.BRIDGE_MAX_MESSAGE_CHARS || 12000),
      maxToolResultChars: Number(env.BRIDGE_MAX_RESULT_CHARS || 40000),
      artifactBytes: Number(env.BRIDGE_MAX_ARTIFACT_BYTES || 256 * 1024),
      waitSecondsMax: 25,
      ...(overrides.limits ?? {}),
    },
  };

  if (!Array.isArray(config.allowedAgents) || !config.allowedAgents.every(s => typeof s === "string" && s.length > 0)) {
    throw new Error("BRIDGE_ALLOWED_AGENT_IDS must contain agent IDs.");
  }
  if (!config.clientAgentIds || Array.isArray(config.clientAgentIds) || typeof config.clientAgentIds !== "object" ||
      !Object.values(config.clientAgentIds).every(ids => Array.isArray(ids) && ids.every(id => typeof id === "string" && id.length > 0))) {
    throw new Error("BRIDGE_CLIENT_AGENT_IDS must be a JSON object mapping clients to agent ID arrays.");
  }
  if (!Array.isArray(config.allowedOrigins) || !config.allowedOrigins.every(validOrigin)) {
    throw new Error("BRIDGE_ALLOWED_ORIGINS must contain exact HTTPS origins or loopback HTTP origins.");
  }
  if (!Number.isSafeInteger(config.limits.artifactBytes) || config.limits.artifactBytes < 1) {
    throw new Error("BRIDGE_MAX_ARTIFACT_BYTES must be a positive byte count.");
  }
  for (const value of [config.approvalTtlSeconds, config.limits.writesPerMinute, config.limits.globalWritesPerMinute,
    config.limits.approvalsPerGrantPerMinute, config.limits.globalApprovalsPerMinute, config.limits.requestsPerMinute]) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error("Approval lifetime and rate limits must be positive integers.");
  }
  if (config.approvalTtlSeconds > 3600) throw new Error("Approval lifetime exceeds one hour.");
  if (config.events) throw new Error("Events delivery is disabled in this release.");
  if (config.publicUrl && !validOrigin(config.publicUrl)) {
    throw new Error("BRIDGE_PUBLIC_URL must be an HTTPS origin or a loopback HTTP origin.");
  }
  if (!Number.isInteger(config.port) || config.port < 0 || config.port > 65535) throw new Error("BRIDGE_PORT must be a TCP port.");
  if (config.adminSecret.length < 16) {
    throw new Error("BRIDGE_ADMIN_SECRET must be set to at least 16 characters (the OAuth consent passcode).");
  }
  return config;
}

function validOrigin(value) {
  try {
    const url = new URL(value);
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    return url.origin === value && (url.protocol === "https:" || (url.protocol === "http:" && local));
  } catch {
    return false;
  }
}

export function isAgentAllowed(config, agentId) {
  return config.allowedAgents.includes(agentId);
}
