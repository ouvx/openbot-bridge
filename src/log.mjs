import { appendFileSync, existsSync, mkdirSync, renameSync, statSync } from "node:fs";
import { join } from "node:path";

const SECRET_PATTERNS = [
  [/\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 ***"],
  [/\b(sk|rk|pk)-[A-Za-z0-9_-]{8,}/g, "$1-***"],
  [/\bwhsec_[A-Za-z0-9+/=]{8,}/g, "whsec_***"],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/g, "jwt-***"],
  [/((?:password|passcode|secret|token|api[_-]?key|authorization)"?\s*[:=]\s*"?)[^\s",}]{4,}/gi, "$1***"],
];

/** Removes credentials from anything the bridge writes to a log or returns to a model. */
export function maskSecrets(value) {
  if (value === null || value === undefined) return value;
  const text = typeof value === "string" ? value : JSON.stringify(value);
  let masked = text;
  for (const [pattern, replacement] of SECRET_PATTERNS) masked = masked.replace(pattern, replacement);
  return typeof value === "string" ? masked : masked;
}

/** Deep copy of a value with every string masked. Used for audit entries. */
export function maskDeep(value, depth = 0) {
  if (depth > 6) return "[deep]";
  if (typeof value === "string") return maskSecrets(value).slice(0, 4000);
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => maskDeep(item, depth + 1));
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = /token|secret|password|authorization|apikey|api_key/i.test(key) ? "***" : maskDeep(item, depth + 1);
    }
    return out;
  }
  return value;
}

export function createLogger({ level = "info", dataDir } = {}) {
  const levels = { error: 0, warn: 1, info: 2, debug: 3 };
  const threshold = levels[level] ?? 2;
  let logFile = null;
  if (dataDir) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    logFile = join(dataDir, "bridge.log");
  }
  const write = (name, message, extra) => {
    if ((levels[name] ?? 2) > threshold) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level: name,
      msg: String(maskSecrets(message)).slice(0, 2000),
      ...(extra ? { extra: maskDeep(extra) } : {}),
    });
    process.stderr.write(`${line}\n`);
    if (!logFile) return;
    try {
      // Rotate at 5 MB so a long-running bridge cannot fill the disk.
      if (existsSync(logFile) && statSync(logFile).size > 5 * 1024 * 1024) renameSync(logFile, `${logFile}.1`);
      appendFileSync(logFile, `${line}\n`, { mode: 0o600 });
    } catch {
      // Logging must never fail a tool call.
    }
  };
  return {
    error: (message, extra) => write("error", message, extra),
    warn: (message, extra) => write("warn", message, extra),
    info: (message, extra) => write("info", message, extra),
    debug: (message, extra) => write("debug", message, extra),
  };
}

export function createAuditLog({ dataDir }) {
  const file = join(dataDir, "audit.jsonl");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  return function audit(entry) {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...maskDeep(entry) });
    try {
      if (existsSync(file) && statSync(file).size > 10 * 1024 * 1024) renameSync(file, `${file}.1`);
      appendFileSync(file, `${line}\n`, { mode: 0o600 });
    } catch {
      // Ignored on purpose: audit failures must not break tool calls.
    }
  };
}

export function truncate(text, max) {
  const value = typeof text === "string" ? text : JSON.stringify(text);
  if (value.length <= max) return value;
  return `${value.slice(0, max)}\n…[truncated ${value.length - max} characters]`;
}
