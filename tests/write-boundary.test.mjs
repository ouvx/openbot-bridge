import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OperationStore } from "../src/operations.mjs";
import { registerTools } from "../src/tools.mjs";

async function fixture(t) {
  const dataDir = await mkdtemp(join(tmpdir(), "bridge-write-"));
  const operations = new OperationStore({ dataDir, subjectLimit: 1, globalLimit: 2 });
  t.after(async () => { operations.close(); await rm(dataDir, { recursive: true, force: true }); });
  const agent = { id: "agent-1", name: "Test" };
  const auth = { ok: true, clientId: "client", grantId: "grant", scopes: ["openbot.admin"], allowedAgentIds: [agent.id] };
  const calls = [];
  const db = { listAgents: () => [agent] };
  const tools = new Map();
  registerTools({ registerTool: (name, schema, handler) => tools.set(name, handler) }, {
    config: { extendedTools: true, readOnly: false, allowedAgents: auth.allowedAgentIds, limits: { maxToolResultChars: 4000 } },
    currentAuth: () => auth, db, oauth: { hasScope: (a, s) => a.scopes.includes(s) },
    automation: { newChat: async id => calls.push(id) }, operations, audit() {}, logger: { warn() {} },
  });
  const call = (args = {}) => tools.get("start_new_session")({ agent_id: agent.id, confirm: true, ...args });
  return { operations, call, calls, db, auth, agent };
}

test("a caller confirmation alone never clears a session", async t => {
  const { call, calls } = await fixture(t);
  const result = await call();
  assert.equal(calls.length, 0);
  assert.equal(result.structuredContent.code, "approval_required");
  assert.ok(result.structuredContent.approval_id);
});

test("an unknown approval ID never reaches the OpenBot write adapter", async t => {
  const { call, calls } = await fixture(t);
  const result = await call({ approval_id: "00000000-0000-4000-8000-000000000000" });
  assert.equal(calls.length, 0);
  assert.equal(result.structuredContent.code, "approval_unknown");
});

test("approved MCP tool dispatches once, returns cached result and rejects a rate-limited second operation", async t => {
  const { operations, call, calls } = await fixture(t);
  async function authorize(key) {
    const args = { idempotency_key: key };
    const proposal = await call(args);
    const id = proposal.structuredContent.approval_id;
    operations.decide(id, operations.card(id).summaryHash, true);
    return { ...args, approval_id: id };
  }
  const approved = await authorize("first");
  const [a,b] = await Promise.all([call(approved), call(approved)]);
  assert.deepEqual(calls, ["agent-1"]);
  assert.equal([a,b].filter(v => v.isError).length, 1);
  const success = [a,b].find(v => !v.isError);
  assert.deepEqual(await call({ idempotency_key: "first" }), success);
  const before = calls.length;
  const denial = await call(await authorize("second"));
  assert.equal(denial.structuredContent.code, "write_rate_limited");
  assert.equal(calls.length - before, 0);
});

test("an approved target ID cannot be redirected to an agent with the same name", async t => {
  const { operations, call, calls, db, auth, agent } = await fixture(t);
  const replacement = { id: "agent-2", name: agent.id };
  auth.allowedAgentIds.push(replacement.id);
  const proposal = await call();
  const id = proposal.structuredContent.approval_id;
  operations.decide(id, operations.card(id).summaryHash, true);
  let listed = false;
  db.listAgents = () => {
    if (listed) return [replacement];
    listed = true;
    return [agent, replacement];
  };
  const refused = await call({ approval_id: id });
  assert.equal(refused.isError, true);
  assert.deepEqual(calls, []);
});

test("a valid approval cannot outlive loss of the required scope or target permission", async t => {
  const { operations, call, calls, auth, agent } = await fixture(t);
  const id = (await call()).structuredContent.approval_id;
  operations.decide(id, operations.card(id).summaryHash, true);
  auth.scopes = ["openbot.read"];
  assert.equal((await call({ approval_id: id })).structuredContent.code, "insufficient_scope");
  auth.scopes = ["openbot.admin"];
  auth.allowedAgentIds = [];
  assert.equal((await call({ approval_id: id })).structuredContent.code, "target_denied");
  assert.deepEqual(calls, []);
  auth.allowedAgentIds = [agent.id];
  assert.equal((await call({ approval_id: id })).structuredContent.cleared, true);
});
