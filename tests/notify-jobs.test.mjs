import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { JobStore } from "../src/jobs.mjs";
import { NOTIFY_EVENTS, Notifier, NotifyStore, resolveNotifySettings } from "../src/notify.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

function tempDir() {
  return mkdtempSync(join(tmpdir(), "bridge-jobs-notify-"));
}

const OWNER = { clientId: "client-1", grantId: "grant-1" };

/** A job store with an automation stand-in that never touches OpenBot. */
async function makeJobs(dir, { notify }) {
  const automation = {
    agents: [],
    deliveries: [],
    pendingResult: { prompts: [], approvals: [], browserTakeovers: [] },
    deliveryResult: { status: "running" },
    async sendMessage() { throw new Error("not used in this test"); },
    async delivery() { return this.deliveryResult; },
    async pending() { return this.pendingResult; },
  };
  const jobs = new JobStore({ dataDir: dir, automation, logger: null, db: null, notify });
  await jobs.init();
  return { jobs, automation };
}

test("job transitions notify once per change, after the job file is written", async (t) => {
  const dir = tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const calls = [];
  let onDisk = null;
  const notify = {
    notify(kind, input) {
      // Read the persisted job here: the hook must run after the save.
      onDisk = JSON.parse(readFileSync(join(dir, "jobs", `${input.taskId}.json`), "utf8")).status;
      calls.push({ kind, input, onDisk });
      return Promise.resolve({ attempted: true, delivered: true });
    },
  };
  const { jobs, automation } = await makeJobs(dir, { notify });
  const job = await jobs.create({ agentId: "agent-1", kind: "message", title: "朝の確認", titleFromUser: true, prompt: "secret prompt text", owner: OWNER });
  job.deliveryId = "delivery-1";
  job.status = "queued";

  automation.pendingResult = { prompts: [], approvals: [{ id: "a1" }], browserTakeovers: [] };
  await jobs.refresh(job, { force: true });
  assert.equal(job.status, "needs_person");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].kind, "needs_approval");
  assert.equal(calls[0].onDisk, "needs_person");

  // The same state is not re-announced.
  await jobs.refresh(job, { force: true });
  assert.equal(calls.length, 1);

  automation.pendingResult = { prompts: [], approvals: [], browserTakeovers: [] };
  automation.deliveryResult = { status: "completed", answer: "done" };
  await jobs.refresh(job, { force: true });
  assert.equal(job.status, "completed");
  assert.equal(calls.length, 2);
  assert.equal(calls[1].kind, "completed");
  assert.equal(calls[1].onDisk, "completed");
});

test("a prompt-derived title never reaches the notification", async (t) => {
  const dir = tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const calls = [];
  const notify = { notify(kind, input) { calls.push({ kind, input }); return Promise.resolve({}); } };
  const { jobs, automation } = await makeJobs(dir, { notify });

  const derived = await jobs.create({ agentId: "agent-1", kind: "task", prompt: "PROMPT-TEXT-LEAK", owner: OWNER });
  assert.match(derived.title, /PROMPT-TEXT-LEAK/); // still used for the task list
  derived.deliveryId = "delivery-1";
  derived.status = "queued";
  automation.deliveryResult = { status: "failed", error: "boom" };
  await jobs.refresh(derived, { force: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].kind, "failed");
  assert.equal(calls[0].input.task, null);

  const explicit = await jobs.create({ agentId: "agent-1", kind: "message", title: "私のタイトル", titleFromUser: true, prompt: "body", owner: OWNER });
  explicit.deliveryId = "delivery-2";
  explicit.status = "queued";
  await jobs.refresh(explicit, { force: true });
  assert.equal(calls.length, 2);
  assert.equal(calls[1].input.task, "私のタイトル");
});

test("a failing notifier cannot break the job", async (t) => {
  const dir = tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const notify = { notify() { throw new Error("hook exploded"); } };
  const { jobs, automation } = await makeJobs(dir, { notify });
  const job = await jobs.create({ agentId: "agent-1", kind: "message", prompt: "x", owner: OWNER });
  job.deliveryId = "delivery-1";
  job.status = "queued";
  automation.deliveryResult = { status: "completed" };
  await jobs.refresh(job, { force: true });
  assert.equal(job.status, "completed");
  assert.equal(jobs.get(job.id).status, "completed");
});

test("scripts/notify-prefs.mjs lists, enables and disables rows without secrets", async (t) => {
  const dir = tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const dbFile = join(dir, "notify.db");
  const run = (...args) => execFileSync(process.execPath, [join(root, "scripts", "notify-prefs.mjs"), ...args, "--db", dbFile], { encoding: "utf8" });

  assert.match(run("list"), /No notification preferences/);
  assert.equal(existsSync(dbFile), false, "list must not create the database");

  const dry = run("enable", "--grant", "grant-1", "--client", "client-1", "--events", "completed", "--dry-run");
  assert.match(dry, /Would enable/);
  assert.equal(existsSync(dbFile), false, "dry-run must write nothing");

  const enabled = run("enable", "--grant", "grant-1", "--client", "client-1", "--events", "needs_approval,completed");
  assert.match(enabled, /Enabled notifications for grant=grant-1 client=client-1 events=needs_approval,completed/);
  assert.equal(statSync(dbFile).mode & 0o777, 0o600);
  assert.match(run("list"), /enabled +grant=grant-1 +client=client-1 +events=needs_approval,completed/);

  const disabled = run("disable", "--grant", "grant-1", "--client", "client-1");
  assert.match(disabled, /Disabled notifications/);
  assert.match(run("list"), /disabled +grant=grant-1/);

  const store = NotifyStore.open(dir);
  assert.equal(store.pref("grant-1", "client-1").enabled, false);
  assert.equal(store.listPrefs().length, 1);
  assert.equal(store.listPrefs()[0].events, NOTIFY_EVENTS.needs_approval | NOTIFY_EVENTS.completed);
  store.close();

  // Nothing secret can appear: the script never opens the secret file.
  assert.equal(run("list").includes("secret"), false);
});

test("a revoke hook disables the grant's preferences, and does nothing while off", async (t) => {
  const dir = tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = NotifyStore.open(dir);
  store.setPref({ grantId: "grant-1", clientId: "client-1", enabled: true, events: 7 });
  store.setPref({ grantId: "grant-1", clientId: "client-2", enabled: true, events: 7 });

  const off = new Notifier({ settings: resolveNotifySettings({ mode: "off" }, null), logger: null, store: null });
  off.useDataDir(dir);
  off.disableGrant("grant-1", "client-1");
  assert.equal(store.pref("grant-1", "client-1").enabled, true, "off must not touch the preferences");

  const webhook = { mode: "webhook", url: new URL("https://example.test/hook"), host: "example.test", secret: Buffer.alloc(32), timeoutMs: 1000 };
  const on = new Notifier({ settings: webhook, logger: null, store: null });
  on.useDataDir(dir);
  on.disableGrant("grant-1", "client-1");
  assert.equal(store.pref("grant-1", "client-1").enabled, false);
  assert.equal(store.pref("grant-1", "client-2").enabled, true, "another client of the same grant keeps its row");
  store.close();
});
