import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { OperationStore, canonicalJSON } from "../src/operations.mjs";

function fixture(t, config = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), "bridge-operation-"));
  let time = 1_800_000_000_000;
  const options = { dataDir, now: () => time, ...config };
  const store = new OperationStore(options);
  const inspect = new DatabaseSync(join(dataDir, "operations.sqlite"));
  t.after(() => {
    inspect.close();
    store.close();
    rmSync(dataDir, { recursive: true, force: true });
  });
  const input = {
    auth: { ok: true, clientId: "client", grantId: "grant", allowedAgentIds: ["alpha", "beta"] },
    tool: "send_message", args: { message: " sample card text ", agent_id: "alpha" }, targets: ["alpha"],
  };
  const approve = (operation = input) => {
    const { approvalId } = store.prepare(operation);
    const card = store.card(approvalId);
    store.decide(approvalId, card.summaryHash, true);
    return { ...operation, approvalId };
  };
  return { store, input, approve, inspect, options, advance: ms => { time += ms; } };
}

test("canonical arguments sort object keys, retain array order and reject collisions", () => {
  assert.equal(canonicalJSON({ z: [2, 1], " e\u0301 ": " e\u0301 ", a: -0 }), '{"a":0,"z":[2,1],"é":"é"}');
  assert.equal(canonicalJSON({ 2: "b", 10: "a" }), '{"10":"a","2":"b"}');
  assert.throws(() => canonicalJSON({ x: 1, " x ": 2 }), { code: "invalid_arguments" });
});

test("pending, missing, declined and expired approvals prevent dispatch", async t => {
  const { store, input, approve, advance } = fixture(t);
  let sent = 0;
  const send = () => ++sent;
  await assert.rejects(store.execute(input, send), { code: "approval_required" });
  const prepared = store.prepare(input);
  await assert.rejects(store.execute({ ...input, approvalId: prepared.approvalId }, send), { code: "approval_not_approved" });
  const card = store.card(prepared.approvalId);
  assert.equal(card.expiresAt - card.issuedAt, 120000);
  store.decide(card.approvalId, card.summaryHash, false);
  await assert.rejects(store.execute({ ...input, approvalId: card.approvalId }, send), { code: "approval_declined" });
  assert.throws(() => store.prepare(input), { code: "approval_declined" });
  const expired = approve({ ...input, args: { ...input.args, message: "other operation" } });
  advance(120000);
  await assert.rejects(store.execute(expired, send), { code: "approval_expired" });
  assert.equal(sent, 0);
});

test("approval rejects changes to arguments, destinations or caller grant", async t => {
  const { store, input, approve } = fixture(t);
  const signed = approve();
  let sent = 0;
  for (const altered of [{ args: { ...input.args, message: "different" } }, { targets: ["beta"] }]) {
    await assert.rejects(store.execute({ ...signed, ...altered }, () => ++sent), { code: "approval_arguments_mismatch" });
  }
  await assert.rejects(store.execute({ ...signed, auth: { ...input.auth, grantId: "other" } }, () => ++sent),
    { code: "approval_principal_mismatch" });
  assert.equal(sent, 0);
});

test("displayed card and execution independently check the summary digest", async t => {
  const { store, input, approve, inspect } = fixture(t);
  const request = store.prepare(input);
  assert.throws(() => store.decide(request.approvalId, "incorrect", true), { code: "approval_card_mismatch" });
  const signed = approve();
  inspect.prepare("UPDATE approvals SET summaryHash='different' WHERE approvalId=?").run(signed.approvalId);
  let sent = 0;
  await assert.rejects(store.execute(signed, () => ++sent), { code: "approval_card_mismatch" });
  assert.equal(sent, 0);
});

test("two connections claiming one approval dispatch exactly once and reject approval replay", async t => {
  const { store, options, approve } = fixture(t);
  const other = new OperationStore(options);
  try {
    const signed = approve();
    let release;
    const gate = new Promise(resolve => { release = resolve; });
    let sent = 0;
    const action = async () => { sent++; await gate; return { ok: true }; };
    const first = store.execute(signed, action);
    try {
      await assert.rejects(other.execute(signed, action), { code: "approval_used" });
    } finally { release(); }
    assert.deepEqual(await first, { ok: true });
    await assert.rejects(other.execute(signed, action), { code: "approval_used" });
    assert.equal(sent, 1);
  } finally { other.close(); }
});

test("idempotent retries after restart return the saved result without dispatch", async t => {
  const { store, input, options, approve } = fixture(t);
  for (const key of [null, "explicit"]) {
    const operation = { ...input, idempotencyKey: key };
    const signed = approve(operation);
    let sent = 0;
    const action = async normalized => {
      assert.equal(normalized.message, input.args.message.trim());
      return { content: [{ text: "receipt" }], count: ++sent };
    };
    const expected = await store.execute(signed, action);
    const reopened = new OperationStore(options);
    try {
      assert.deepEqual(await reopened.execute(operation, action), expected);
      assert.deepEqual(reopened.prepare(operation), { cached: true, result: expected });
    } finally { reopened.close(); }
    assert.equal(sent, 1);
  }
  assert.throws(() => store.prepare({ ...input, idempotencyKey: "explicit", args: { message: "replacement" } }),
    { code: "idempotency_conflict" });
});

test("per-client, per-grant and service budgets refuse excess calls before sending", async t => {
  const { store, input, approve, advance } = fixture(t, { subjectLimit: 1, globalLimit: 2 });
  const send = async () => ({ accepted: true });
  const withCaller = (clientId, grantId, key) => ({
    ...input, auth: { ...input.auth, clientId, grantId }, idempotencyKey: key,
  });
  await store.execute(approve(withCaller("a", "g", "one")), send);
  let excessSends = 0;
  const excess = async () => { excessSends++; return {}; };
  for (const request of [withCaller("a", "h", "two"), withCaller("b", "g", "three")]) {
    await assert.rejects(store.execute(approve(request), excess), { code: "write_rate_limited" });
  }
  await store.execute(approve(withCaller("b", "h", "four")), send);
  const next = approve(withCaller("c", "i", "five"));
  await assert.rejects(store.execute(next, excess), { code: "write_rate_limited" });
  assert.equal(excessSends, 0);
  advance(60000);
  assert.deepEqual(await store.execute(next, send), { accepted: true });
});

test("an ambiguous operation cannot be dispatched again", async t => {
  const { store, input, approve } = fixture(t);
  let sent = 0;
  const uncertain = async () => { sent++; throw new Error("receipt unavailable"); };
  await assert.rejects(store.execute(approve(), uncertain), { code: "operation_outcome_uncertain" });
  await assert.rejects(store.execute(input, uncertain), { code: "operation_in_progress_or_uncertain" });
  assert.equal(sent, 1);
});

test("audit records bind identity and hashes without raw arguments, and an audit error prevents dispatch", async t => {
  const { store, input, approve, inspect } = fixture(t);
  const signed = approve();
  let sent = 0;
  inspect.exec("CREATE TRIGGER deny_audit BEFORE INSERT ON operation_audit BEGIN SELECT RAISE(ABORT, 'unavailable'); END");
  await assert.rejects(store.execute(signed, async () => ++sent), { code: "operation_store_unavailable" });
  assert.equal(sent, 0);
  inspect.exec("DROP TRIGGER deny_audit");
  await store.execute(signed, async () => ++sent);
  const rows = inspect.prepare("SELECT * FROM operation_audit ORDER BY eventId").all();
  assert.deepEqual(rows.map(row => row.outcome), ["issued","approved","execution_claimed","executed"]);
  assert.ok(rows.every(row => row.clientId === input.auth.clientId && row.grantId === input.auth.grantId &&
    row.approvalId === signed.approvalId && row.tool === input.tool && /^[0-9a-f]{64}$/.test(row.argsHash)));
  assert.ok(!JSON.stringify(rows).includes(input.args.message.trim()));
});
