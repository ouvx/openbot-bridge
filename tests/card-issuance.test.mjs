import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { setTimeout as sleep } from "node:timers/promises";
import { OperationStore } from "../src/operations.mjs";
import { openApprovalCard } from "../scripts/approve.mjs";

const run = promisify(execFile);
const storeUrl = new URL("../src/operations.mjs", import.meta.url).href;
const digest = text => createHash("sha256").update(text).digest("hex");
const input = { tool: "send_message", args: { message: "sample private note" }, targets: ["agent"],
  auth: { ok: true, grantId: "g", clientId: "c", allowedAgentIds: ["agent"] } };

async function withStore(t, options = {}) {
  const dataDir = await mkdtemp(join(tmpdir(), "bridge-card-"));
  const store = new OperationStore({ dataDir, ...options });
  const cleanups = [];
  t.after(async () => {
    for (const cleanup of cleanups) await cleanup();
    store.close();
    await rm(dataDir, { recursive: true, force: true });
  });
  return { store, dataDir, cleanups };
}

function client(ui) {
  const { origin, hash } = new URL(ui.url);
  const headers = { origin, authorization: "Bearer " + hash.slice(1), "content-type": "application/json" };
  return (path, body = {}) => fetch(origin + path, { method: "POST", headers, body: JSON.stringify(body) });
}

test("one approval issues one card: the second launch is refused and the generation stays", async t => {
  const { store } = await withStore(t);
  const { approvalId } = store.prepare(input);
  const first = store.reserveCard(approvalId);
  assert.equal(first.replaced, false);
  assert.ok(Number.isInteger(first.cardOpenedAt));

  assert.throws(() => store.reserveCard(approvalId), { code: "approval_card_open" });
  const state = store.cardState(approvalId);
  assert.equal(state.cardOpenedAt, first.cardOpenedAt, "a refused launch must not move the generation");
  assert.equal(state.state, "pending");
  // 既存の画面はそのまま有効（単回使用・期限の検査は弱めていない）。
  assert.ok(store.card(approvalId, first.cardOpenedAt).summaryHash);
});

test("concurrent launches issue exactly one card", async t => {
  const dataDir = await mkdtemp(join(tmpdir(), "bridge-card-race-"));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  const store = new OperationStore({ dataDir });
  const { approvalId } = store.prepare(input);
  store.close();

  const script = `
    const { OperationStore } = await import(process.env.STORE_URL);
    const store = new OperationStore({ dataDir: process.env.DATA_DIR });
    try { console.log(JSON.stringify({ ok: true, openedAt: store.reserveCard(process.env.APPROVAL_ID).cardOpenedAt })); }
    catch (error) { console.log(JSON.stringify({ ok: false, code: error.code })); }
    finally { store.close(); }
  `;
  const env = { ...process.env, STORE_URL: storeUrl, DATA_DIR: dataDir, APPROVAL_ID: approvalId };
  const results = await Promise.all([0, 1, 2, 3].map(() =>
    run(process.execPath, ["--input-type=module", "-e", script], { env, timeout: 20000 }).then(({ stdout }) => JSON.parse(stdout.trim()))));
  const winners = results.filter(result => result.ok);
  assert.equal(winners.length, 1, JSON.stringify(results));
  assert.ok(results.filter(result => !result.ok).every(result => result.code === "approval_card_open"));

  const reopened = new OperationStore({ dataDir });
  t.after(() => reopened.close());
  const state = reopened.cardState(approvalId);
  assert.equal(state.cardOpenedAt, winners[0].openedAt);
});

test("--replace invalidates the previous card and only the new one decides", async t => {
  const { store, cleanups } = await withStore(t);
  const { approvalId } = store.prepare(input);
  const first = await openApprovalCard(store, approvalId);
  cleanups.push(async () => { first.stop(); await first.closed; });
  const firstClient = client(first);
  const before = await (await firstClient("/card")).json();

  const second = await openApprovalCard(store, approvalId, { replace: true });
  cleanups.push(async () => { second.stop(); await second.closed; });
  assert.equal(second.replaced, true);
  assert.notEqual(second.openedAt, first.openedAt);

  const stale = await firstClient("/card");
  assert.equal(stale.status, 410);
  assert.equal((await stale.json()).error, "approval_card_stale");
  const staleDecision = await firstClient("/decision", { approved: true, summaryHash: before.summaryHash });
  assert.equal(staleDecision.status, 410);

  const secondClient = client(second);
  assert.equal((await secondClient("/card")).status, 200);
  assert.equal((await secondClient("/decision", { approved: true, summaryHash: before.summaryHash })).status, 200);
  assert.equal(await store.execute({ ...input, approvalId }, async args => args.message), input.args.message);

  // 決定後は画面が閉じ、DB でも再発行できない（単回使用は維持）。
  assert.throws(() => store.card(approvalId), { code: "approval_not_pending" });
  assert.throws(() => store.reserveCard(approvalId, { replace: true }), { code: "approval_not_pending" });
});

test("an expired card answers 410 with a Japanese reason and never executes", async t => {
  const { store, cleanups } = await withStore(t, { ttlSeconds: 1 });
  const { approvalId } = store.prepare(input);
  const card = store.card(approvalId);
  const ui = await openApprovalCard(store, approvalId);
  cleanups.push(async () => { ui.stop(); await ui.closed; });
  const post = client(ui);
  assert.equal((await post("/card")).status, 200);

  await sleep(1300);

  const expired = await post("/card");
  assert.equal(expired.status, 410);
  const body = await expired.json();
  assert.equal(body.error, "approval_expired");
  assert.match(body.message, /期限切れ/);
  assert.match(body.message, /実行されません/);

  const decision = await post("/decision", { approved: true, summaryHash: digest(card.summary) });
  assert.equal(decision.status, 410);
  assert.match((await decision.json()).message, /期限切れ/);

  let executed = false;
  await assert.rejects(store.execute({ ...input, approvalId }, async () => { executed = true; }), { code: "approval_expired" });
  assert.equal(executed, false, "an expired approval must never reach OpenBot");
  // 期限切れは状態にも残る（list と監査で分かる）。
  assert.equal(store.cardState(approvalId).state, "expired");
});

test("the page keeps working after the approval is decided elsewhere and reports it", async t => {
  const { store, cleanups } = await withStore(t);
  const { approvalId } = store.prepare(input);
  const ui = await openApprovalCard(store, approvalId);
  cleanups.push(async () => { ui.stop(); await ui.closed; });
  const post = client(ui);
  const card = await (await post("/card")).json();
  store.decide(approvalId, card.summaryHash, false);
  const late = await post("/decision", { approved: true, summaryHash: card.summaryHash });
  assert.equal(late.status, 409);
  assert.match((await late.json()).message, /決定済み|拒否済み/);
});
