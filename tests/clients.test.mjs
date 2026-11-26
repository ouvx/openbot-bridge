import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, readFile, stat, cp, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { auth, refreshAuthorization } from "@modelcontextprotocol/sdk/client/auth.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { startBridge } from "../src/index.mjs";

const run = promisify(execFile);
const project = fileURLToPath(new URL("../", import.meta.url));
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "bridge-client-"));
  const passcode = randomBytes(32).toString("hex");
  t.after(() => rm(root, { recursive: true, force: true }));
  const bridge = await startBridge({
    host: "127.0.0.1", port: 0, dataDir: root, adminSecret: passcode, logLevel: "error",
    openbot: { dbPath: join(root, "absent.db") }, allowedOrigins: ["https://client.example"],
  });
  t.after(() => bridge.stop());
  return { root, passcode, bridge };
}

async function authorizeClient(bridge, passcode) {
  const serverUrl = new URL(bridge.mcpUrl);
  const redirect = "http://127.0.0.1/callback";
  let registration, verifier, authorizationUrl, tokens;
  const provider = {
    redirectUrl: redirect,
    clientMetadata: { redirect_uris: [redirect], token_endpoint_auth_method: "none" },
    clientInformation: () => registration, saveClientInformation: v => { registration = v; },
    codeVerifier: () => verifier, saveCodeVerifier: v => { verifier = v; },
    redirectToAuthorization: url => { authorizationUrl = url; },
    tokens: () => tokens, saveTokens: v => { tokens = v; },
  };
  const options = { serverUrl, scope: "openbot.read" };
  assert.equal(await auth(provider, options), "REDIRECT");
  assert.equal(authorizationUrl.searchParams.get("redirect_uri"), redirect);
  const params = new URLSearchParams(authorizationUrl.searchParams);
  params.set("passcode", passcode);
  const approval = await fetch(bridge.url + "/oauth/authorize/approve", {
    method: "POST", body: params, redirect: "manual",
  });
  assert.equal(approval.status, 302);
  const code = new URL(approval.headers.get("location")).searchParams.get("code");
  assert.equal(await auth(provider, { ...options, authorizationCode: code }), "AUTHORIZED");

  return { provider, registration, tokens, serverUrl };
}

async function connectAndCheck(serverUrl, provider, origin) {
  const client = new Client({ name: "Test MCP client", version: "1.0" });
  try {
    await client.connect(new StreamableHTTPClientTransport(serverUrl, {
      authProvider: provider, requestInit: { headers: origin ? { origin } : {} },
    }));
    assert.deepEqual((await client.listTools()).tools.map(tool => tool.name).sort(), ["list_agents", "openbot_health"]);
    assert.equal((await client.callTool({ name: "openbot_health", arguments: {} })).isError, undefined);
  } finally {
    await client.close();
  }
}

test("SDK discovery and S256 grant allow Streamable HTTP with matching Origin and without Origin", async t => {
  const { bridge, passcode } = await fixture(t);
  const { provider, serverUrl, tokens, registration } = await authorizeClient(bridge, passcode);
  await connectAndCheck(serverUrl, provider, "https://client.example");
  await connectAndCheck(serverUrl, provider);
  const revoked = await fetch(bridge.url + "/oauth/revoke", {
    method: "POST", body: new URLSearchParams({ token: tokens.access_token, client_id: registration.client_id }),
  });
  assert.equal(revoked.status, 200);
  const response = await fetch(serverUrl, { method: "POST", headers: { authorization: "Bearer " + tokens.access_token } });
  assert.equal(response.status, 401);
});

test("standard SDK refresh rotates tokens with no redirect_uri after explicit redirect consent", async t => {
  const { bridge, passcode } = await fixture(t);
  const { provider, serverUrl, registration, tokens } = await authorizeClient(bridge, passcode);
  const metadata = await fetch(bridge.url + "/.well-known/oauth-authorization-server").then(r => r.json());
  const request = { metadata, clientInformation: registration, refreshToken: tokens.refresh_token, resource: bridge.url };
  const rotated = await refreshAuthorization(new URL(bridge.url), request);
  assert.ok(rotated.access_token && rotated.access_token !== tokens.access_token);
  assert.ok(rotated.refresh_token && rotated.refresh_token !== tokens.refresh_token);
  await assert.rejects(refreshAuthorization(new URL(bridge.url), request));
  provider.saveTokens(rotated);
  await connectAndCheck(serverUrl, provider);
});

test("token CLI writes read-only credentials privately and warns on explicit elevation", async t => {
  const { bridge, root, passcode } = await fixture(t);
  const env = { PATH: process.env.PATH, HOME: root, BRIDGE_ADMIN_SECRET: passcode };
  for (const flag of [null, "--admin"]) {
    const output = join(root, flag ? "elevated.json" : "reader.json");
    const args = [join(project, "scripts/token.mjs"), "--output", output, "--port", String(bridge.config.port)];
    if (flag) args.push(flag);
    const { stdout, stderr } = await run(process.execPath, args, { cwd: root, env });
    assert.equal(stdout.trim(), output);
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    const stored = JSON.parse(await readFile(output, "utf8"));
    assert.equal(stored.scope, flag ? "openbot.read openbot.admin" : "openbot.read");
    assert.equal(Boolean(stderr.trim()), Boolean(flag));
    assert.ok(!stderr.includes(stored.access_token) && !stderr.includes(stored.refresh_token) && !stderr.includes(passcode));
    await assert.rejects(run(process.execPath, args, { cwd: root, env }));
  }
});

test("setup shell prints only the private configuration path and preserves an existing passcode", async t => {
  const root = await mkdtemp(join(tmpdir(), "bridge-setup-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "scripts"));
  for (const file of [".env.example", "scripts/setup.mjs", "scripts/setup.sh"]) await cp(join(project, file), join(root, file));
  const script = join(root, "scripts/setup.sh");
  const path = join(root, ".env");
  const result = await run("sh", [script], { cwd: root, env: { PATH: process.env.PATH } });
  assert.equal(result.stdout.trim(), path);
  assert.equal(result.stderr, "");
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  const first = await readFile(path, "utf8");
  await run("sh", [script], { cwd: root, env: { PATH: process.env.PATH } });
  assert.equal(await readFile(path, "utf8") === first, true);
});
