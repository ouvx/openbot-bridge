import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { Notifier, NotifyStore, resolveNotifySettings, eventIdFor } from "../src/notify.mjs";

const SECRET = "test-secret-0123456789abcdef";

function tempDir() {
  return mkdtempSync(join(tmpdir(), "bridge-notify-"));
}

function secretFile(dir, mode = 0o600) {
  const file = join(dir, "notify.secret");
  writeFileSync(file, SECRET, { mode });
  chmodSync(file, mode);
  return file;
}

/** Loopback receiver that verifies the HMAC and records requests. */
async function receiver({ tamper = false } = {}) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const ts = req.headers["x-bridge-timestamp"];
      const expected = `sha256=${createHmac("sha256", SECRET).update(`${ts}.${body}`).digest("hex")}`;
      seen.push({ headers: req.headers, body });
      res.statusCode = tamper || req.headers["x-bridge-signature"] !== expected ? 401 : 204;
      res.end();
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return { server, seen, url: `http://127.0.0.1:${port}/hook`, close: () => new Promise((r) => (server.listening ? server.close(() => r()) : r())) };
}

function settingsFor(url, dir) {
  return resolveNotifySettings({
    mode: "webhook",
    webhookUrl: url,
    secretFile: secretFile(dir),
    allowLoopbackHttp: true,
    timeoutMs: 1000,
  });
}

function enabledStore(dir, { grantId = "grant-1", clientId = "client-1", events = 7, includeTask = false } = {}) {
  const store = NotifyStore.open(dir);
  store.setPref({ grantId, clientId, enabled: true, events, includeTask });
  return store;
}

test("off: unset, session, unknown, bad url and bad secret send nothing and create no file", async (t) => {
  const cases = [
    { mode: "" },
    { mode: "session", webhookUrl: "https://example.test/hook" },
    { mode: "on", webhookUrl: "https://example.test/hook" },
    { mode: "webhook", webhookUrl: "", secretFile: "/nonexistent" },
    { mode: "webhook", webhookUrl: "http://example.test/x", allowLoopbackHttp: false },
  ];
  for (const raw of cases) {
    const dir = tempDir();
    let calls = 0;
    const settings = resolveNotifySettings(raw, null);
    assert.equal(settings.mode, "off", JSON.stringify(raw));
    const notifier = new Notifier({ settings, logger: null, store: null, transport: async () => { calls += 1; return { status: 204 }; } });
    notifier.useDataDir(dir);
    const result = await notifier.notify("completed", { taskId: "t1", task: "demo", state: "completed", owner: { clientId: "c", grantId: "g" } });
    assert.equal(result.attempted, false);
    assert.equal(calls, 0);
    assert.equal(existsSync(join(dir, "notify.db")), false, "off must not create the store");
    rmSync(dir, { recursive: true, force: true });
  }
});

test("off: a secret file without 0600 refuses notifications", () => {
  const dir = tempDir();
  const settings = resolveNotifySettings({ mode: "webhook", webhookUrl: "https://example.test/hook", secretFile: secretFile(dir, 0o644) }, null);
  assert.equal(settings.mode, "off");
  rmSync(dir, { recursive: true, force: true });
});

test("prefs: both grant and client must be enabled, and the event bit must be set", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir, { events: 1 }); // needs_approval only
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null });

  const owner = { clientId: "client-1", grantId: "grant-1" };
  assert.equal((await notifier.notify("completed", { taskId: "a", task: "x", state: "completed", owner })).reason, "preference");
  assert.equal(rx.seen.length, 0);
  assert.equal((await notifier.notify("needs_approval", { taskId: "b", task: "y", state: "needs_person", owner })).attempted, true);
  assert.equal(rx.seen.length, 1);
  // another grant is not affected
  assert.equal((await notifier.notify("needs_approval", { taskId: "c", task: "z", state: "needs_person", owner: { clientId: "client-1", grantId: "grant-2" } })).reason, "preference");
  assert.equal((await notifier.notify("needs_approval", { taskId: "d", task: "w", state: "needs_person", owner: { clientId: "client-2", grantId: "grant-1" } })).reason, "preference");
  assert.equal(rx.seen.length, 1);
  store.close();
  await rx.close();
  rmSync(dir, { recursive: true, force: true });
});

test("signature: the receiver accepts a valid HMAC and rejects a tampered body", async (t) => {
  const dir = tempDir();
  const ok = await receiver();
  t.after(() => ok.close());
  const store = enabledStore(dir);
  const notifier = new Notifier({ settings: settingsFor(ok.url, dir), logger: null, store, transport: null });
  const owner = { clientId: "client-1", grantId: "grant-1" };
  const sent = await notifier.notify("completed", { taskId: "t1", task: "demo", state: "completed", owner });
  assert.equal(sent.attempted, true);
  assert.equal(sent.delivered, true);
  assert.equal(sent.status, 204);
  assert.equal(ok.seen.length, 1);
  const first = ok.seen[0];
  assert.match(first.headers["x-bridge-signature"], /^sha256=[0-9a-f]{64}$/);
  assert.equal(first.headers["x-bridge-event"], sent.eventId);
  assert.ok(JSON.parse(first.body).eventId === sent.eventId);
  // A receiver that expects a different HMAC returns 401; the bridge reports the failure.
  await ok.close();
  const bad = await receiver({ tamper: true });
  t.after(() => bad.close());
  const notifier2 = new Notifier({ settings: settingsFor(bad.url, dir), logger: null, store, transport: null });
  const failed = await notifier2.notify("failed", { taskId: "t2", task: "demo2", state: "failed", owner });
  assert.equal(failed.attempted, true);
  assert.equal(failed.delivered, false);
  assert.equal(failed.status, 401);
  store.close();
  await bad.close();
  rmSync(dir, { recursive: true, force: true });
});

test("duplicate event ids are delivered once", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir);
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null });
  const owner = { clientId: "client-1", grantId: "grant-1" };
  const first = await notifier.notify("completed", { taskId: "same", task: "x", state: "completed", owner });
  const second = await notifier.notify("completed", { taskId: "same", task: "x", state: "completed", owner });
  assert.equal(first.attempted, true);
  assert.equal(second.attempted, false);
  assert.equal(second.reason, "duplicate");
  assert.equal(rx.seen.length, 1);
  assert.equal(eventIdFor("grant-1", "same", "completed"), first.eventId);
  store.close();
  await rx.close();
  rmSync(dir, { recursive: true, force: true });
});

test("rate limits suppress extra notifications per grant", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir);
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null, limits: { perGrantPerMinute: 2, globalPerMinute: 10 } });
  const owner = { clientId: "client-1", grantId: "grant-1" };
  const results = [];
  for (const id of ["a", "b", "c"]) results.push(await notifier.notify("completed", { taskId: id, task: id, state: "completed", owner }));
  assert.deepEqual(results.map((r) => r.attempted), [true, true, false]);
  assert.equal(rx.seen.length, 2);
  store.close();
  await rx.close();
  rmSync(dir, { recursive: true, force: true });
});

test("a rate-suppressed event keeps its id and can be sent later", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir);
  let clock = Date.parse("2026-01-01T00:00:00.000Z");
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null, now: () => clock, limits: { perGrantPerMinute: 1, globalPerMinute: 10 } });
  const owner = { clientId: "client-1", grantId: "grant-1" };
  assert.equal((await notifier.notify("completed", { taskId: "a", task: "a", state: "completed", owner })).attempted, true);
  const suppressed = await notifier.notify("completed", { taskId: "b", task: "b", state: "completed", owner });
  assert.equal(suppressed.attempted, false);
  assert.equal(suppressed.reason, "rate");
  clock += 61_000;
  // The same event must not be burned by the earlier suppression.
  const later = await notifier.notify("completed", { taskId: "b", task: "b", state: "completed", owner });
  assert.equal(later.attempted, true);
  assert.equal(later.delivered, true);
  assert.equal(rx.seen.length, 2);
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("the payload carries no task title by default, even when one is given", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir);
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null });
  const owner = { clientId: "client-1", grantId: "grant-1" };
  await notifier.notify("completed", { taskId: "no-title", task: null, state: "completed", owner });
  await notifier.notify("completed", { taskId: "with-title", task: "朝の確認", state: "completed", owner });
  await notifier.notify("failed", { taskId: "secret-title", task: "api_key=abc123 personal note", state: "failed", owner });
  const bodies = rx.seen.map((entry) => JSON.parse(entry.body));
  for (const body of bodies) {
    assert.equal("task" in body, false);
    assert.deepEqual(Object.keys(body).sort(), ["at", "eventId", "kind", "state"]);
  }
  assert.equal(JSON.stringify(bodies).includes("朝の確認"), false);
  assert.equal(JSON.stringify(bodies).includes("api_key"), false);
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("include_task=on adds the user's title, nothing else", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir, { includeTask: true });
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null });
  const owner = { clientId: "client-1", grantId: "grant-1" };
  await notifier.notify("completed", { taskId: "t1", task: "朝の確認", state: "completed", owner });
  await notifier.notify("completed", { taskId: "t2", task: null, state: "completed", owner });
  const bodies = rx.seen.map((entry) => JSON.parse(entry.body));
  assert.equal(bodies[0].task, "朝の確認");
  assert.equal("task" in bodies[1], false, "an empty title is still omitted");
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("include_task keeps the 200-character and 512-byte limits", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir, { includeTask: true });
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null });
  const owner = { clientId: "client-1", grantId: "grant-1" };
  const long = "a".repeat(300);
  assert.equal((await notifier.notify("completed", { taskId: "long", task: long, state: "completed", owner })).attempted, true);
  const body = JSON.parse(rx.seen[0].body);
  assert.equal(body.task.length, 200);
  assert.equal(Buffer.byteLength(rx.seen[0].body) <= 512, true);

  // A multibyte title fits 200 characters but not the 512-byte budget, so it is
  // refused instead of being cut further.
  const fat = "𠮟".repeat(150);
  const result = await notifier.notify("completed", { taskId: "fat", task: fat, state: "completed", owner });
  assert.equal(result.attempted, false);
  assert.equal(result.reason, "payload");
  assert.equal(rx.seen.length, 1);
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("a title never reaches the audit trail or the log", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir, { includeTask: true });
  const logged = [];
  const audited = [];
  const logger = { info: (...a) => logged.push(JSON.stringify(a)), warn: (...a) => logged.push(JSON.stringify(a)), error: (...a) => logged.push(JSON.stringify(a)), debug: (...a) => logged.push(JSON.stringify(a)) };
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger, audit: (entry) => audited.push(JSON.stringify(entry)), store, transport: null });
  await notifier.notify("completed", { taskId: "t1", task: "TITLE-MARKER-42", state: "completed", owner: { clientId: "client-1", grantId: "grant-1" } });
  assert.equal(JSON.stringify(audited).includes("TITLE-MARKER-42"), false);
  assert.equal(JSON.stringify(logged).includes("TITLE-MARKER-42"), false);
  assert.equal(rx.seen[0].body.includes("TITLE-MARKER-42"), true, "the opt-in title does go to the configured receiver");
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("a database from before include_task is migrated with the opt-in off", async (t) => {
  const dir = tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "notify.db");
  const legacy = new DatabaseSync(file);
  legacy.exec(`CREATE TABLE notify_prefs (
    grant_id TEXT NOT NULL, client_id TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    events INTEGER NOT NULL, updated_at TEXT NOT NULL,
    PRIMARY KEY (grant_id, client_id));`);
  legacy.prepare("INSERT INTO notify_prefs VALUES (?,?,?,?,?)").run("grant-1", "client-1", 1, 7, "2026-01-01T00:00:00.000Z");
  legacy.close();

  const store = new NotifyStore(file);
  const prefs = store.pref("grant-1", "client-1");
  assert.equal(prefs.enabled, true);
  assert.equal(prefs.includeTask, false, "an old row must not start sending titles");
  assert.equal(store.listPrefs()[0].includeTask, false);
  assert.equal(store.setIncludeTask("grant-1", "client-1", true), true);
  assert.equal(store.pref("grant-1", "client-1").includeTask, true);
  assert.equal(store.setIncludeTask("grant-9", "client-9", true), false);
  store.close();
});

test("a symlinked secret file is refused", () => {
  const dir = tempDir();
  const real = secretFile(dir);
  const link = join(dir, "link.secret");
  symlinkSync(real, link);
  const settings = resolveNotifySettings({ mode: "webhook", webhookUrl: "https://example.test/hook", secretFile: link }, null);
  assert.equal(settings.mode, "off");
  rmSync(dir, { recursive: true, force: true });
});

test("a revoked grant sends nothing and disables its preference row", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir);
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger: null, store, transport: null, grantActive: () => false });
  const result = await notifier.notify("completed", { taskId: "x", task: "x", state: "completed", owner: { clientId: "client-1", grantId: "grant-1" } });
  assert.equal(result.attempted, false);
  assert.equal(result.reason, "grant");
  assert.equal(rx.seen.length, 0);
  assert.equal(store.pref("grant-1", "client-1").enabled, false);
  store.close();
  await rx.close();
  rmSync(dir, { recursive: true, force: true });
});

test("a private https target is refused before any body is sent", async (t) => {
  const dir = tempDir();
  const store = enabledStore(dir);
  // Default transport resolves and rejects private addresses (callback.mjs rules).
  const notifier = new Notifier({
    settings: resolveNotifySettings({ mode: "webhook", webhookUrl: "https://10.0.0.1/hook", secretFile: secretFile(dir) }, null),
    logger: null,
    store,
    transport: null,
  });
  const result = await notifier.notify("completed", { taskId: "x", task: "x", state: "completed", owner: { clientId: "client-1", grantId: "grant-1" } });
  assert.equal(result.attempted, true);
  assert.equal(result.delivered, false);
  assert.equal(result.reason, "transport");
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

test("the secret never appears in the payload, audit entries or log lines", async (t) => {
  const dir = tempDir();
  const rx = await receiver();
  t.after(() => rx.close());
  const store = enabledStore(dir);
  const logged = [];
  const audited = [];
  const logger = { info: (...a) => logged.push(JSON.stringify(a)), warn: (...a) => logged.push(JSON.stringify(a)), error: (...a) => logged.push(JSON.stringify(a)), debug: (...a) => logged.push(JSON.stringify(a)) };
  const notifier = new Notifier({ settings: settingsFor(rx.url, dir), logger, audit: (entry) => audited.push(JSON.stringify(entry)), store, transport: null });
  await notifier.notify("completed", { taskId: "secret-check", task: "demo", state: "completed", owner: { clientId: "client-1", grantId: "grant-1" } });
  const everything = JSON.stringify({ body: rx.seen.map((r) => r.body), logged, audited });
  assert.equal(everything.includes(SECRET), false);
  assert.equal(everything.includes("x-bridge-signature"), false);
  store.close();
  await rx.close();
  rmSync(dir, { recursive: true, force: true });
});
