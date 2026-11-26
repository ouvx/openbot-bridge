#!/usr/bin/env node
/**
 * Read-only environment check for the bridge.
 *
 * Tells you exactly what OpenBot exposes right now: whether the database can be
 * read, whether the Local scripts (automation) API is on, which agents exist,
 * and whether a tunnel is available. It never writes to OpenBot and never
 * prints a token.
 */
import { access, stat } from "node:fs/promises";
import { join } from "node:path";
import { constants } from "node:fs";
import { execFile } from "node:child_process";
import { isAgentAllowed, loadConfig } from "../src/config.mjs";
import { OpenBotDb } from "../src/openbot/db.mjs";
import { AutomationClient } from "../src/openbot/automation.mjs";
import { systemSnapshot } from "../src/openbot/system.mjs";

try {
  process.loadEnvFile(process.env.BRIDGE_ENV_FILE || ".env");
} catch (error) {
  if (error.code !== "ENOENT") throw error;
}
const config = loadConfig();
const result = { ok: false, checks: {} };
const [major, minor] = process.versions.node.split(".").map(Number);
result.checks.node = { version: process.version, ok: major > 22 || (major === 22 && minor >= 5) };
const writesEnabled = config.extendedTools && !config.readOnly;
result.checks.writesEnabled = { enabled: writesEnabled };

const db = new OpenBotDb(config.openbot.dbPath);
let agents = [];
try {
  agents = db.listAgents();
  result.checks.database = { ok: true, allowedAgents: agents.filter(agent => isAgentAllowed(config, agent.id)).length };
} catch {
  result.checks.database = { ok: false, reason: "Could not read the configured agent database." };
}

if (writesEnabled) {
  const automation = new AutomationClient({ dir: config.openbot.automationDir });
  const credentialFiles = ["url", "token"];
  const missing = [];
  for (const name of credentialFiles) {
    try {
      await access(join(config.openbot.automationDir, name), constants.R_OK);
    } catch {
      missing.push(name);
    }
  }

  if (missing.length) {
    result.checks.automation = {
      ok: false,
      missingOrUnreadable: missing,
      reason: "OpenBot automation credentials are unavailable in the configured directory.",
    };
  } else {
    try {
      const list = await automation.listAgents();
      if (!Array.isArray(list)) throw new Error("Unexpected agent list.");
      const available = new Set(list.map((agent) => agent.id));
      const eligible = agents.filter((agent) => available.has(agent.id) && isAgentAllowed(config, agent.id));
      result.checks.automation = {
        ok: eligible.length > 0,
        agentsWithLocalScripts: list.length,
        eligibleTargets: eligible.length,
        ...(eligible.length ? {} : { reason: "No agent is available to both OpenBot automation and this bridge." }),
      };
    } catch {
      result.checks.automation = { ok: false, reason: "Authenticated OpenBot agent discovery failed." };
    }
  }
} else {
  result.checks.automation = { skipped: true, reason: "Write tools are disabled." };
}
db.close();

const tunnels = {};
for (const name of ["ngrok", "cloudflared"]) {
  tunnels[name] = await new Promise((resolve) => {
    execFile("which", [name], (error, stdout) => resolve(Boolean(!error && stdout.trim())));
  });
}
result.checks.tunnel = { available: tunnels, publicUrlSet: Boolean(config.publicUrl) };

const snapshot = await systemSnapshot();
result.checks.system = {
  cpuPercent: snapshot.cpu.percent,
  memoryUsedPercent: snapshot.memory?.usedPercent ?? null,
  diskFreeGb: snapshot.disk.home ? Math.round(snapshot.disk.home.freeBytes / 1e9) : null,
  memoryTotalGb: snapshot.memory ? Math.round(snapshot.memory.totalBytes / 1e9) : null,
  openbotRunning: snapshot.openbotProcess.running,
};

try {
  const info = await stat(config.dataDir);
  await access(config.dataDir, constants.W_OK | constants.X_OK);
  result.checks.dataDir = { ok: info.isDirectory() };
} catch {
  result.checks.dataDir = { ok: false, note: "directory must exist and be writable after first start" };
}

result.ok = Object.values(result.checks).every((check) => check.ok !== false);
console.log(JSON.stringify(result, null, 2));
if (!result.ok) {
  console.error("\nSome checks failed. Fix them before connecting ChatGPT.");
  process.exitCode = 1;
}
