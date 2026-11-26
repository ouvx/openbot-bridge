import assert from "node:assert/strict";
import { test } from "node:test";

import { registerTools } from "../src/tools.mjs";

const AUTH = {
  ok: true,
  clientId: "client-1",
  grantId: "grant-1",
  scopes: ["openbot.read", "openbot.write"],
  allowedAgentIds: ["agent-1", "agent-2"],
};

function job(id, { agentId = "agent-1", status = "needs_person", clientId = "client-1", grantId = "grant-1" } = {}) {
  const at = "2026-01-01T00:00:00.000Z";
  return {
    id,
    agentId,
    kind: "message",
    title: `title-${id}`,
    prompt: "PROMPT-TEXT",
    ownerClientId: clientId,
    ownerGrantId: grantId,
    status,
    createdAt: at,
    updatedAt: at,
    deliveryId: null,
    turnId: null,
    answer: null,
    error: null,
  };
}

function build({ jobs, auth = AUTH }) {
  const registered = new Map();
  const server = {
    registerTool(name, meta, handler) { registered.set(name, { meta, handler }); },
    registerResource() {},
  };
  const auditEntries = [];
  registerTools(server, {
    config: { allowedAgents: ["agent-1", "agent-2"], limits: { maxToolResultChars: 8000 }, readOnly: false, extendedTools: true },
    db: null,
    automation: {},
    jobs: {
      get: (id) => jobs.find((entry) => entry.id === id) ?? null,
      list: ({ agentId = null, status = null, limit = 20, accepts = null } = {}) => {
        let found = [...jobs];
        if (accepts) found = found.filter(accepts);
        if (agentId) found = found.filter((entry) => entry.agentId === agentId);
        if (status) found = found.filter((entry) => entry.status === status);
        return found.slice(0, limit);
      },
    },
    oauth: { hasScope: (a, scope) => Boolean(a?.ok && a.scopes.includes(scope)) },
    audit: (entry) => auditEntries.push(entry),
    logger: { warn() {}, info() {}, error() {} },
    currentAuth: () => auth,
  });
  return { registered, auditEntries };
}

const json = (result) => result.structuredContent;

test("get_pending stays inside the grant, the client and the allowed agents", () => {
  const jobs = [
    job("j1"),
    job("j2", { clientId: "client-2" }),
    job("j3", { grantId: "grant-2" }),
    job("j4", { agentId: "agent-9" }),
    job("j5", { status: "running" }),
  ];
  const { registered, auditEntries } = build({ jobs });
  const tool = registered.get("get_pending");
  assert.equal(tool.meta.annotations.readOnlyHint, true);
  assert.equal(tool.meta.annotations.destructiveHint, false);
  assert.equal(tool.meta.inputSchema.limit.safeParse(51).success, false);
  assert.equal(tool.meta.inputSchema.limit.safeParse(1).success, true);

  return tool.handler({}).then((result) => {
    const body = json(result);
    assert.deepEqual(body.pending.map((entry) => entry.task_id), ["j1"]);
    assert.equal(body.count, 1);
    assert.equal(JSON.stringify(body).includes("PROMPT-TEXT"), false);
    assert.equal(auditEntries.at(-1).scope, "openbot.read");
  });
});

test("get_pending honours limit and the default of 10", async () => {
  const jobs = Array.from({ length: 15 }, (_, index) => job(`p${String(index).padStart(2, "0")}`));
  const { registered } = build({ jobs });
  const tool = registered.get("get_pending");
  assert.equal(json(await tool.handler({})).pending.length, 10);
  assert.equal(json(await tool.handler({ limit: 3 })).pending.length, 3);
});

test("get_status separates running from finished tasks and keeps them scoped", async () => {
  const jobs = [
    job("r1", { status: "running" }),
    job("r2", { status: "queued" }),
    job("d1", { status: "completed" }),
    job("d2", { status: "failed" }),
    job("x1", { status: "completed", clientId: "client-2" }),
    job("x2", { status: "running", agentId: "agent-9" }),
    job("n1", { status: "needs_person" }),
  ];
  const { registered } = build({ jobs });
  const tool = registered.get("get_status");
  assert.equal(tool.meta.annotations.readOnlyHint, true);
  const body = json(await tool.handler({}));
  assert.deepEqual(body.running.map((entry) => entry.task_id).sort(), ["r1", "r2"]);
  assert.deepEqual(body.recent.map((entry) => entry.task_id), ["d1", "d2"]);
  assert.equal(body.running_count, 2);
  assert.equal(JSON.stringify(body).includes("PROMPT-TEXT"), false);

  const limited = json(await tool.handler({ limit: 1 }));
  assert.equal(limited.recent.length, 1);
});

test("without the read scope the tools refuse instead of returning data", async () => {
  const jobs = [job("j1")];
  const { registered } = build({ jobs, auth: { ...AUTH, scopes: [] } });
  const result = await registered.get("get_pending").handler({});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /missing the openbot\.read scope/);
});
