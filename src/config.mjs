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
    allowedAgents: (env.BRIDGE_ALLOWED_AGENTS || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
    readOnly: !["0", "false"].includes(env.BRIDGE_READ_ONLY),
    extendedTools: env.BRIDGE_EXTENDED_TOOLS === "1",
    events: env.BRIDGE_EVENTS === "1" || env.BRIDGE_EVENTS === "true",
    limits: {
      requestsPerMinute: Number(env.BRIDGE_RPM || 90),
      writesPerMinute: Number(env.BRIDGE_WRITES_PER_MINUTE || 12),
      maxMessageChars: Number(env.BRIDGE_MAX_MESSAGE_CHARS || 12000),
      maxToolResultChars: Number(env.BRIDGE_MAX_RESULT_CHARS || 40000),
      artifactBytes: Number(env.BRIDGE_MAX_ARTIFACT_BYTES || 256 * 1024),
      waitSecondsMax: 25,
    },
    logLevel: env.BRIDGE_LOG_LEVEL || "info",
    sharedDir: env.OPENBOT_SHARED_DIR || join(home, "OpenBot", "Shared"),
    ...overrides,
    openbot: { ...{ dbPath: env.OPENBOT_DB || join(openbotConfig, "openbot.db"), automationDir: env.OPENBOT_AUTOMATION_DIR || join(openbotConfig, "automation"), configDir: openbotConfig }, ...(overrides.openbot ?? {}) },
    limits: {
      requestsPerMinute: Number(env.BRIDGE_RPM || 90),
      writesPerMinute: Number(env.BRIDGE_WRITES_PER_MINUTE || 12),
      maxMessageChars: Number(env.BRIDGE_MAX_MESSAGE_CHARS || 12000),
      maxToolResultChars: Number(env.BRIDGE_MAX_RESULT_CHARS || 40000),
      artifactBytes: Number(env.BRIDGE_MAX_ARTIFACT_BYTES || 256 * 1024),
      waitSecondsMax: 25,
      ...(overrides.limits ?? {}),
    },
  };

  if (config.events) throw new Error("Events delivery is disabled in this release.");
  if (config.publicUrl) {
    const url = new URL(config.publicUrl);
    const localHttp = url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.origin !== config.publicUrl || (!localHttp && url.protocol !== "https:")) {
      throw new Error("BRIDGE_PUBLIC_URL must be an HTTPS origin or a loopback HTTP origin.");
    }
  }
  if (!Number.isInteger(config.port) || config.port < 0 || config.port > 65535) throw new Error("BRIDGE_PORT must be a TCP port.");
  if (config.adminSecret.length < 16) {
    throw new Error("BRIDGE_ADMIN_SECRET must be set to at least 16 characters (the OAuth consent passcode).");
  }
  return config;
}

export function publicUrlOf(config, request) {
  if (config.publicUrl) return config.publicUrl;
  return `http://${request.headers.host || `${config.host}:${config.port}`}`;
}

export function isAgentAllowed(config, agentId) {
  return config.allowedAgents.includes(agentId);
}
