import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { registerTools } from "../src/tools.mjs";

const alpha = { id: "alpha", name: "Alpha", title: "", description: "" };
const beta = { id: "beta", name: "Beta", title: "", description: "" };
const principal = { ok: true, clientId: "client-a", grantId: "grant-a", allowedAgentIds: ["alpha"], scopes: ["openbot.read"] };

function fixture({ auth = principal, sharedDir, extraDb = {}, jobs = {} } = {}) {
  const tools = new Map();
  registerTools({ registerTool(name, options, handler) { tools.set(name, handler); } }, {
    currentAuth: () => auth,
    config: { allowedAgents: ["alpha", "beta"], extendedTools: true, sharedDir, limits: { artifactBytes: 4096, maxToolResultChars: 4096 } },
    oauth: { hasScope: (a, scope) => Boolean(a?.ok && a.scopes?.includes(scope)) },
    db: { listAgents: () => [alpha, beta], listThreads: () => [], deliveries: () => [], routines: () => [], ...extraDb },
    jobs: { list: () => [], ...jobs }, audit() {}, logger: { warn() {} },
  });
  return (name, input) => tools.get(name)(input);
}

test("missing write scope denies an agent message", async () => {
  const result = await fixture()("send_message", { agent_id: "alpha", message: "fixture" });
  assert.equal(result.isError, true);
  assert.match(result.structuredContent.error, /scope/);
});

test("OAuth agent grant restricts lists and direct selection", async () => {
  const call = fixture();
  const visible = await call("list_agents", {});
  assert.deepEqual(visible.structuredContent.agents.map(agent => agent.agent_id), ["alpha"]);
  const unavailable = await call("get_agent", { agent_id: "beta" });
  assert.equal(unavailable.isError, true);
});

test("conversation rejects an unowned or unknown thread", async () => {
  const calls = [];
  const call = fixture({ extraDb: {
    thread: id => id === "b-thread" ? { agentId: "beta" } : null,
    messages: () => { calls.push("read"); return []; },
  } });
  for (const session_id of ["b-thread", "unknown"]) {
    assert.equal((await call("get_conversation", { agent_id: "alpha", session_id })).isError, true);
  }
  assert.deepEqual(calls, []);
});

test("job reads deny foreign grants, foreign clients and ownerless legacy records", async () => {
  let polls = 0;
  for (const owner of [{}, { ownerClientId: "client-a", ownerGrantId: "grant-b" }, { ownerClientId: "client-b", ownerGrantId: "grant-a" }]) {
    const job = { id: "a-job", agentId: "alpha", status: "queued", ...owner };
    const call = fixture({ jobs: { get: () => job, refresh: () => { polls++; return job; } } });
    assert.equal((await call("get_task", { task_id: job.id })).isError, true);
  }
  assert.equal(polls, 0);
});

async function artifacts(t) {
  const base = await mkdtemp(join(tmpdir(), "bridge-files-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const dir = join(base, "bridge-artifacts", "alpha");
  await mkdir(dir, { recursive: true });
  return { base, dir, read: path => fixture({ sharedDir: base })("read_artifact", { agent_id: "alpha", path }) };
}

test("artifact read rejects a symlink outside its agent export directory", async t => {
  const { base, dir, read } = await artifacts(t);
  const ordinary = join(base, "other.txt");
  await writeFile(ordinary, "sample");
  await symlink(ordinary, join(dir, "linked.txt"));
  assert.equal((await read("linked.txt")).isError, true);
  assert.equal((await read(ordinary)).isError, true);
  await writeFile(join(dir, "result.txt"), "report");
  assert.equal((await read("result.txt")).structuredContent.text, "report");
});

test("artifact file policy denies dotfiles, credentials, keys, databases and logs", async t => {
  const { dir, read } = await artifacts(t);
  for (const name of [".env", ".hidden.md", "certificate.pem", "debug.log", "vault.key", "credentials.txt", "state.json", "store.sqlite-wal"]) {
    await writeFile(join(dir, name), "fixture");
    assert.equal((await read(name)).isError, true, name);
  }
});

test("task logs reject foreign turns and sessions without an owning agent", async () => {
  let reads = 0;
  const call = fixture({ extraDb: {
    turn: () => ({ threadId: "b-thread" }),
    thread: id => id === "b-thread" ? { agentId: "beta" } : null,
    activities: () => { reads++; return []; },
  } });
  for (const request of [{ turn_id: "b-turn" }, { session_id: "unknown" }]) {
    assert.equal((await call("get_task_logs", request)).isError, true);
  }
  assert.equal(reads, 0);
});

test("request byte override cannot raise the configured artifact limit", async t => {
  const { base, dir } = await artifacts(t);
  await writeFile(join(dir, "large.txt"), Buffer.alloc(5000, 32));
  const result = await fixture({ sharedDir: base })("read_artifact", { agent_id: "alpha", path: "large.txt", max_bytes: 8192 });
  assert.equal(result.isError, true);
});
