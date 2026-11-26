import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { registerTools } from "../src/tools.mjs";
import { isAgentAllowed, loadConfig } from "../src/config.mjs";
import { startBridge } from "../src/index.mjs";

const fixtureSecret = randomBytes(32).toString("hex");

const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

async function freePort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

/** A stand-in for OpenBot's automation API, following the app's real routes. */
async function fakeAutomation(dir) {
  const token = randomBytes(16).toString("base64url");
  const deliveries = new Map();
  const messages = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.headers.authorization !== `Bearer ${token}`) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }
    const send = (status, value) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    if (url.pathname === "/v1/agents" && req.method === "GET") {
      send(200, [
        { id: "agent-1", name: "Example Builder", routines: [] },
        { id: "agent-2", name: "Example Editor", routines: [{ id: "r1", name: "朝の確認", active: true }] },
      ]);
      return;
    }
    const messageMatch = /^\/v1\/agents\/([^/]+)\/messages$/.exec(url.pathname);
    if (messageMatch && req.method === "POST") {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (!body.text || !body.clientMessageId) {
        send(400, { error: "text and clientMessageId are required" });
        return;
      }
      const duplicate = messages.find((item) => item.clientMessageId === body.clientMessageId);
      if (duplicate) {
        send(202, { messageId: duplicate.messageId, deliveries: [duplicate.delivery] });
        return;
      }
      const id = `delivery-${messages.length + 1}`;
      const delivery = { id, recipientAgentId: messageMatch[1], status: "queued" };
      messages.push({ clientMessageId: body.clientMessageId, messageId: `msg-${messages.length + 1}`, delivery });
      deliveries.set(id, { createdAt: Date.now(), agentId: messageMatch[1] });
      send(202, { messageId: `msg-${messages.length}`, deliveries: [delivery] });
      return;
    }
    const deliveryMatch = /^\/v1\/agents\/([^/]+)\/deliveries\/([^/]+)$/.exec(url.pathname);
    if (deliveryMatch) {
      const entry = deliveries.get(deliveryMatch[2]);
      if (!entry) {
        send(404, { error: "not found" });
        return;
      }
      const age = Date.now() - entry.createdAt;
      const status = age > 400 ? "completed" : age > 100 ? "running" : "queued";
      send(200, {
        id: deliveryMatch[2],
        status,
        turnId: status === "queued" ? null : "turn-1",
        error: null,
        answer: status === "completed" ? "できました。3ファイルを直しました。" : null,
      });
      return;
    }
    if (/^\/v1\/agents\/[^/]+\/pending$/.test(url.pathname)) {
      send(200, { prompts: [], approvals: [], browserTakeovers: [] });
      return;
    }
    if (/^\/v1\/agents\/[^/]+\/context\/clear$/.test(url.pathname)) {
      send(200, { ok: true });
      return;
    }
    send(404, { error: "not found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "url"), `http://127.0.0.1:${port}`, { mode: 0o600 });
  await writeFile(join(dir, "token"), token, { mode: 0o600 });
  return { server, port, messages };
}

function fakeDatabase(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE projection_agents (agent_id TEXT PRIMARY KEY, thread_id TEXT, model TEXT, updated_at TEXT, sort_order INTEGER, agent_json TEXT, last_event_sequence INTEGER);
    CREATE TABLE projection_threads (thread_id TEXT PRIMARY KEY, agent_id TEXT, title TEXT, active_turn_id TEXT, created_at TEXT, updated_at TEXT, last_event_sequence INTEGER);
    CREATE TABLE projection_deliveries (delivery_id TEXT PRIMARY KEY, message_id TEXT, recipient_agent_id TEXT, status TEXT, turn_id TEXT, error TEXT, created_at TEXT, delivery_json TEXT, last_event_sequence INTEGER);
    CREATE TABLE projection_turns (turn_id TEXT PRIMARY KEY, thread_id TEXT, provider_session_id TEXT, status TEXT, started_at TEXT, completed_at TEXT, last_event_sequence INTEGER);
    CREATE TABLE projection_thread_messages (thread_id TEXT, message_id TEXT, turn_id TEXT, author TEXT, status TEXT, item_type TEXT, created_at TEXT, ordinal INTEGER, message_json TEXT, last_event_sequence INTEGER, group_start TEXT, group_first INTEGER, group_id TEXT, turn_rank INTEGER, PRIMARY KEY (thread_id, message_id));
    CREATE TABLE projection_thread_activities (activity_id TEXT PRIMARY KEY, thread_id TEXT, turn_id TEXT, activity_type TEXT, payload_json TEXT, created_at TEXT, last_event_sequence INTEGER);
    CREATE TABLE projection_agent_routines (routine_id TEXT PRIMARY KEY, agent_id TEXT, name TEXT, instruction TEXT, active INTEGER, timezone TEXT, created_at TEXT, updated_at TEXT, last_event_sequence INTEGER, limit_policy TEXT, missed_policy TEXT, run_in TEXT);
    CREATE TABLE projection_attachments (attachment_id TEXT PRIMARY KEY, owner_kind TEXT, owner_id TEXT, name TEXT, path TEXT, metadata_json TEXT, created_at TEXT, last_event_sequence INTEGER);
  `);
  const agent = (id, name, provider, model) =>
    JSON.stringify({
      id,
      name,
      title: `${name}の役割`,
      description: `${name}はテスト用のエージェント。`,
      provider,
      model,
      reasoningEffort: "high",
      access: "full",
      computerUse: true,
      threadId: `thread-${id}`,
      workspacePath: "/tmp/does-not-exist",
    });
  db.prepare("INSERT INTO projection_agents VALUES (?,?,?,?,?,?,?)").run("agent-1", "thread-agent-1", "p/m1", "2026-01-01T00:00:00.000Z", 0, agent("agent-1", "Example Builder", "pi", "p/m1"), 1);
  db.prepare("INSERT INTO projection_agents VALUES (?,?,?,?,?,?,?)").run("agent-2", "thread-agent-2", "gemini", "2026-01-01T00:00:00.000Z", 1, agent("agent-2", "Example Editor", "antigravity", "gemini-3.8-flash"), 2);
  db.prepare("INSERT INTO projection_threads VALUES (?,?,?,?,?,?,?)").run("thread-agent-1", "agent-1", "Main", null, "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z", 3);
  db.prepare("INSERT INTO projection_thread_messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)").run(
    "thread-agent-1", "message-1", "turn-0", "user", "completed", null, "2026-01-02T00:00:00.000Z", 0,
    JSON.stringify({ id: "message-1", author: "user", text: "前回の作業を続けて" }), 4, null, null, null, null,
  );
  db.close();
}

test("bridge: OAuth, tools, and task lifecycle against a fake OpenBot", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "openbot-bridge-test-"));
  t.after(async () => rm(root, { recursive: true, force: true }));

  const automationDir = join(root, "automation");
  const automation = await fakeAutomation(automationDir);
  const dbPath = join(root, "openbot.db");
  fakeDatabase(dbPath);
  const port = await freePort();
  const publicUrl = `http://127.0.0.1:${port}`;

  const bridge = await startBridge({
    port,
    host: "127.0.0.1",
    publicUrl,
    allowedOrigins: [publicUrl],
    adminSecret: fixtureSecret,
    dataDir: join(root, "data"),
    openbot: { dbPath, automationDir, configDir: root },
    allowedAgents: ["agent-1", "agent-2"],
    extendedTools: true,
    readOnly: false,
    limits: { requestsPerMinute: 200, writesPerMinute: 1, maxMessageChars: 12000, maxToolResultChars: 40000, artifactBytes: 200000, waitSecondsMax: 25 },
    logLevel: "error",
  });
  t.after(async () => {
    await bridge.stop();
    await new Promise((resolve) => automation.server.close(resolve));
  });

  // --- unauthenticated access is refused with discovery hints -------------
  const unauthorized = await fetch(`${publicUrl}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });
  assert.equal(unauthorized.status, 401);
  assert.match(unauthorized.headers.get("www-authenticate"), /oauth-protected-resource/);

  // --- OAuth 2.1 with PKCE -------------------------------------------------
  const redirectUri = "https://chatgpt.com/connector/oauth/callback";
  const registration = await fetch(`${publicUrl}/oauth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "ChatGPT", redirect_uris: [redirectUri] }),
  }).then((response) => response.json());
  assert.match(registration.client_id, /^client_/);

  const { verifier, challenge } = pkce();
  const authUrl = new URL(`${publicUrl}/oauth/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", registration.client_id);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openbot.read openbot.write openbot.admin");
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", "state-1");
  authUrl.searchParams.set("resource", publicUrl);
  const consent = await fetch(authUrl);
  assert.equal(consent.status, 200);
  assert.match(await consent.text(), /管理者パスコード/);

  const defaultScope = new URLSearchParams(authUrl.searchParams);
  defaultScope.delete("scope");
  assert.deepEqual(bridge.oauth.authorizeRequest(defaultScope).scopes, ["openbot.read"]);
  const wrongPass = await fetch(`${publicUrl}/oauth/authorize/approve`, { method: "POST", body: new URLSearchParams({ ...Object.fromEntries(authUrl.searchParams), passcode: "nope" }) });
  assert.equal(wrongPass.status, 403);

  const approval = await fetch(`${publicUrl}/oauth/authorize/approve`, {
    method: "POST",
    redirect: "manual",
    body: new URLSearchParams({ ...Object.fromEntries(authUrl.searchParams), passcode: fixtureSecret }),
  });
  assert.equal(approval.status, 302);
  const location = new URL(approval.headers.get("location"));
  const code = location.searchParams.get("code");
  assert.ok(code);

  const tokenResponse = await fetch(`${publicUrl}/oauth/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id: registration.client_id,
      redirect_uri: redirectUri,
      resource: publicUrl,
    }),
  });
  assert.equal(tokenResponse.status, 200);
  const tokens = await tokenResponse.json();
  assert.match(tokens.access_token, /^obr_/);
  assert.match(tokens.scope, /openbot\.write/);

  // A replayed code must fail.
  const replay = await fetch(`${publicUrl}/oauth/token`, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: registration.client_id, resource: publicUrl, redirect_uri: redirectUri }),
  });
  assert.equal(replay.status, 400);

  // --- MCP session ---------------------------------------------------------
  const client = new Client({ name: "bridge-test", version: "0.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${publicUrl}/mcp`), {
    requestInit: { headers: { origin: publicUrl, authorization: `Bearer ${tokens.access_token}` } },
  });
  await client.connect(transport);
  t.after(async () => client.close());

  const { tools } = await client.listTools();
  const names = tools.map((tool) => tool.name);
  for (const expected of ["openbot_health", "list_agents", "get_agent", "delegate_task", "get_task", "send_feedback", "get_server_resources"]) {
    assert.ok(names.includes(expected), `missing tool ${expected}`);
  }
  const write = tools.find((tool) => tool.name === "delegate_task");
  assert.equal(write.annotations.readOnlyHint, false);

  const health = await client.callTool({ name: "openbot_health", arguments: {} });
  assert.deepEqual(health.structuredContent.openbot, { databaseAvailable: true });

  const agents = await client.callTool({ name: "list_agents", arguments: {} });
  assert.equal(agents.structuredContent.count, 2);
  assert.equal(agents.structuredContent.agents[0].provider, "pi");

  const args = { agent_id: "Example Builder", task: "README を直す", definition_of_done: "差分と確認結果が返る", idempotency_key: "readme-fix-1" };
  const delegate = (arguments_) => client.callTool({ name: "delegate_task", arguments: arguments_ });
  async function approve(args) {
    const proposal = await delegate(args);
    assert.equal(proposal.structuredContent.code, "approval_required");
    const id = proposal.structuredContent.approval_id;
    bridge.operations.decide(id, bridge.operations.card(id).summaryHash, true);
    return id;
  }
  const approvalId = await approve(args);
  assert.equal(automation.messages.length, 0);
  const altered = await delegate({ ...args, task: "別の依頼", approval_id: approvalId });
  assert.equal(altered.structuredContent.code, "approval_arguments_mismatch");
  assert.equal(automation.messages.length, 0);
  const delegated = await delegate({ ...args, approval_id: approvalId });
  const taskId = delegated.structuredContent.task_id;
  assert.ok(taskId);
  assert.equal(automation.messages.length, 1);
  assert.match(automation.messages[0].clientMessageId, /^job_/);
  const again = await delegate(args);
  assert.deepEqual(again, delegated);
  const other = { ...args, idempotency_key: "second", task: "別の依頼" };
  const secondId = await approve(other);
  const before = automation.messages.length;
  const limited = await delegate({ ...other, approval_id: secondId });
  assert.equal(limited.structuredContent.code, "write_rate_limited");
  assert.equal(automation.messages.length - before, 0);

  const finished = await client.callTool({ name: "get_task", arguments: { task_id: taskId, wait_seconds: 2 } });
  assert.equal(finished.structuredContent.status, "completed");
  assert.match(finished.structuredContent.answer, /直しました/);

  const resources = await client.callTool({ name: "get_server_resources", arguments: {} });
  assert.ok(resources.structuredContent.cpu.cores >= 1);

  const conversation = await client.callTool({ name: "get_conversation", arguments: { agent_id: "agent-1" } });
  assert.equal(conversation.structuredContent.messages[0].text, "前回の作業を続けて");

  const missing = await client.callTool({ name: "get_agent", arguments: { agent_id: "存在しない" } });
  assert.equal(missing.isError, true);
});

test("bridge: read-only mode blocks writes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "openbot-bridge-ro-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const automationDir = join(root, "automation");
  const automation = await fakeAutomation(automationDir);
  const dbPath = join(root, "openbot.db");
  fakeDatabase(dbPath);
  const port = await freePort();
  const publicUrl = `http://127.0.0.1:${port}`;
  const bridge = await startBridge({
    port,
    host: "127.0.0.1",
    publicUrl,
    allowedOrigins: [publicUrl],
    adminSecret: fixtureSecret,
    dataDir: join(root, "data"),
    openbot: { dbPath, automationDir, configDir: root },
    allowedAgents: ["agent-1"],
    extendedTools: true,
    readOnly: true,
    limits: { requestsPerMinute: 200, writesPerMinute: 50, maxMessageChars: 12000, maxToolResultChars: 40000, artifactBytes: 200000, waitSecondsMax: 25 },
    logLevel: "error",
  });
  t.after(async () => {
    await bridge.stop();
    await new Promise((resolve) => automation.server.close(resolve));
  });

  const healthUrl = `${publicUrl}/health`;
  const local = await fetch(healthUrl, { headers: { origin: publicUrl } });
  assert.equal(local.status, 200);
  assert.deepEqual(await local.json(), { ok: true });
  for (const origin of ["null", "https://foreign.example", publicUrl + "/"]) {
    assert.equal((await fetch(healthUrl, { headers: { origin } })).status, 403);
  }
  const tools = new Map();
  registerTools({ registerTool(name, info, fn) { tools.set(name, fn); } }, {
    ...bridge, currentAuth: () => ({ ok: true, clientId: "test", grantId: "fixture", allowedAgentIds: ["agent-1"], scopes: ["openbot.read", "openbot.write"] }), audit: () => {},
  });
  const denied = await tools.get("send_message")({ agent_id: "agent-1", message: "fixture" });
  assert.equal(denied.isError, true);
  assert.match(denied.structuredContent.error, /read-only/);
  assert.equal(automation.messages.length, 0);
  const listed = await tools.get("list_agents")({ include_offline: true });
  assert.deepEqual(listed.structuredContent.agents.map(a => a.agent_id), ["agent-1"]);
  const tokens = await fetch(`${publicUrl}/oauth/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: "invalid",
      code_verifier: "x",
    }),
  });
  assert.equal(tokens.status, 400);
});

test("doctor exits with a failure when automation credentials are missing", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "bridge-doctor-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  fakeDatabase(join(root, "openbot.db"));
  const doctor = fileURLToPath(new URL("../scripts/doctor.mjs", import.meta.url));
  assert.throws(() => execFileSync(process.execPath, [doctor], {
    cwd: root,
    env: {
      PATH: process.env.PATH,
      BRIDGE_ADMIN_SECRET: fixtureSecret,
      BRIDGE_READ_ONLY: "0",
      BRIDGE_EXTENDED_TOOLS: "1",
      BRIDGE_ALLOWED_AGENTS: "agent-1",
      OPENBOT_CONFIG_DIR: root,
      BRIDGE_DATA_DIR: root,
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }), (error) => {
    assert.equal(error.status, 1);
    const result = JSON.parse(error.stdout);
    assert.equal(result.checks.database.ok, true);
    assert.deepEqual(result.checks.automation.missingOrUnreadable, ["url", "token"]);
    assert.equal(result.ok, false);
    return true;
  });
});

test("release defaults expose only health and allowed agents", async () => {
  const env = { BRIDGE_ADMIN_SECRET: fixtureSecret };
  const config = loadConfig(env);
  assert.equal(config.readOnly, true);
  assert.equal(loadConfig({ ...env, BRIDGE_READ_ONLY: "unrecognized" }).readOnly, true);
  assert.equal(isAgentAllowed(config, "agent-1"), false);
  assert.throws(() => loadConfig({ ...env, BRIDGE_EVENTS: "1" }), /disabled/);
  const tools = new Map();
  const audited = [];
  registerTools({ registerTool(name, info, fn) { tools.set(name, fn); } }, {
    config, oauth: { hasScope: () => true }, db: { available: true, listAgents: () => [{ id: "agent-1" }] },
    audit: entry => audited.push(entry), logger: { warn() {} },
  });
  assert.deepEqual([...tools.keys()], ["openbot_health", "list_agents"]);
  assert.deepEqual((await tools.get("list_agents")({ include_offline: true })).structuredContent, { count: 0, agents: [] });
  assert.deepEqual((await tools.get("openbot_health")({})).structuredContent.openbot, { databaseAvailable: true });
  for (const entry of audited) assert.deepEqual(Object.keys(entry).sort(), ["caller", "clientId", "scope", "tool"]);
});

test("doctor succeeds without automation credentials in default read-only mode", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "bridge-ro-doctor-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  fakeDatabase(join(root, "openbot.db"));
  const doctor = fileURLToPath(new URL("../scripts/doctor.mjs", import.meta.url));
  const report = JSON.parse(execFileSync(process.execPath, [doctor], {
    cwd: root, encoding: "utf8",
    env: { PATH: process.env.PATH, BRIDGE_ADMIN_SECRET: fixtureSecret, OPENBOT_CONFIG_DIR: root, BRIDGE_DATA_DIR: root },
    stdio: ["ignore", "pipe", "pipe"],
  }));
  assert.equal(report.ok, true);
  assert.equal(report.checks.writesEnabled.enabled, false);
  assert.equal(report.checks.automation.skipped, true);
});
