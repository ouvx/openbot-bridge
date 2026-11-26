#!/usr/bin/env node
import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { NOTIFY_EVENTS, NotifyStore } from "../src/notify.mjs";

// Operator CLI for the per-grant notification preferences. It opens the same
// SQLite file the bridge uses and prints grant/client/event values only; it
// never reads or prints the webhook secret.

const USAGE = `Usage:
  node scripts/notify-prefs.mjs list [--dry-run]
  node scripts/notify-prefs.mjs enable --grant <id> --client <id> [--events needs_approval,completed,failed] [--dry-run]
  node scripts/notify-prefs.mjs disable --grant <id> --client <id> [--dry-run]

Options:
  --events   Comma list of needs_approval, completed, failed (default: all three)
  --dry-run  Show what would change; write nothing
  --db       Path to notify.db (default: <BRIDGE_DATA_DIR or ./data>/notify.db)

Enabling needs BRIDGE_NOTIFY=webhook and a valid webhook URL and secret file;
while notifications are off the bridge ignores these rows.`;

const EVENT_NAMES = Object.keys(NOTIFY_EVENTS);
const ALL_EVENTS = EVENT_NAMES.reduce((sum, name) => sum | NOTIFY_EVENTS[name], 0);

function parseArgs(argv) {
  const options = { command: null, dryRun: false, grant: null, client: null, events: null, db: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--grant") options.grant = argv[++index] ?? "";
    else if (arg === "--client") options.client = argv[++index] ?? "";
    else if (arg === "--events") options.events = argv[++index] ?? "";
    else if (arg === "--db") options.db = argv[++index] ?? "";
    else if (arg === "--help" || arg === "-h") return { help: true };
    else if (!options.command && !arg.startsWith("-")) options.command = arg;
    else return { error: `Unknown argument: ${arg}` };
  }
  return options;
}

function parseEvents(value) {
  if (!value) return ALL_EVENTS;
  let mask = 0;
  for (const raw of String(value).split(",")) {
    const name = raw.trim();
    if (!name) continue;
    if (name === "all") { mask = ALL_EVENTS; continue; }
    if (!(name in NOTIFY_EVENTS)) return { error: `Unknown event: ${name} (use ${EVENT_NAMES.join(", ")})` };
    mask |= NOTIFY_EVENTS[name];
  }
  if (!mask) return { error: "At least one event is required." };
  return { mask };
}

function describeEvents(mask) {
  const names = EVENT_NAMES.filter((name) => (mask & NOTIFY_EVENTS[name]) !== 0);
  return names.length ? names.join(",") : "none";
}

// Same resolution as src/config.mjs, without loading the rest of the config:
// this CLI must work before the bridge has an admin passcode.
function dbPath(override) {
  if (override) return override;
  return join(resolve(process.env.BRIDGE_DATA_DIR || join(process.cwd(), "data")), "notify.db");
}

function openStore(file, { create }) {
  if (!create) return new NotifyStore(file);
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  const store = new NotifyStore(file);
  try { chmodSync(file, 0o600); } catch { /* best effort; the data dir is 0700 */ }
  return store;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { console.log(USAGE); return 0; }
  if (options.error) { console.error(options.error); console.error(USAGE); return 2; }
  if (!["list", "enable", "disable"].includes(options.command)) {
    console.error(USAGE);
    return 2;
  }

  const file = dbPath(options.db);
  const mutating = options.command !== "list";
  if (mutating && (!options.grant || !options.client)) {
    console.error("--grant and --client are required.");
    return 2;
  }
  if (options.dryRun && options.command !== "list") {
    if (options.command === "enable") {
      const parsed = parseEvents(options.events);
      if (parsed.error) { console.error(parsed.error); return 2; }
      console.log(`Would enable notifications for grant=${options.grant} client=${options.client} events=${describeEvents(parsed.mask)}.`);
    } else {
      console.log(`Would disable notifications for grant=${options.grant} client=${options.client}.`);
    }
    return 0;
  }

  if (options.command === "list" && !existsSync(file)) {
    console.log(`No notification preferences in ${file} (the file does not exist yet).`);
    return 0;
  }
  if (options.command === "disable" && !existsSync(file)) {
    console.error(`No preference database at ${file}, so nothing is enabled for that grant.`);
    return 1;
  }

  const store = openStore(file, { create: options.command === "enable" && !options.dryRun });

  try {
    if (options.command === "list") {
      const rows = store.listPrefs();
      if (!rows.length) console.log(`No notification preferences in ${file}.`);
      for (const row of rows) {
        console.log(`${row.enabled ? "enabled " : "disabled"}  grant=${row.grantId}  client=${row.clientId}  events=${describeEvents(row.events)}  updated=${row.updatedAt}`);
      }
      return 0;
    }

    if (options.command === "disable") {
      const changed = store.setEnabled(options.grant, options.client, false);
      console.log(changed
        ? `Disabled notifications for grant=${options.grant} client=${options.client}.`
        : `No preference row for grant=${options.grant} client=${options.client}; nothing to disable.`);
      return 0;
    }

    const parsed = parseEvents(options.events);
    if (parsed.error) { console.error(parsed.error); return 2; }
    store.setPref({ grantId: options.grant, clientId: options.client, enabled: true, events: parsed.mask });
    console.log(`Enabled notifications for grant=${options.grant} client=${options.client} events=${describeEvents(parsed.mask)}.`);
    console.log("The bridge still needs BRIDGE_NOTIFY=webhook, a webhook URL and a 0600 secret file to send.");
    return 0;
  } finally {
    store.close();
  }
}

process.exitCode = main();
