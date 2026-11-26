import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, rm, writeFile, mkdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OAuthServer } from "../src/auth.mjs";

const resource = "https://bridge.example";
const redirectUri = "https://client.example/callback";
const form = (values) => new URLSearchParams(values);

async function fixture(t) {
  const dataDir = await mkdtemp(join(tmpdir(), "bridge-auth-"));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  const passcode = randomBytes(32).toString("base64url");
  const config = { dataDir, publicUrl: resource, adminSecret: passcode, allowedAgentIds: ["agent-a", "agent-b"] };
  const server = new OAuthServer(config);
  await server.init();
  const { client_id: clientId } = await server.register({ redirect_uris: [redirectUri] });
  async function authorization({ includeRedirect = true } = {}) {
    const verifier = randomBytes(40).toString("base64url");
    const query = form({ response_type: "code", client_id: clientId, redirect_uri: redirectUri,
      resource, code_challenge_method: "S256", code_challenge: createHash("sha256").update(verifier).digest("base64url") });
    if (!includeRedirect) query.delete("redirect_uri");
    const callback = await server.approve(server.authorizeRequest(query), passcode);
    const code = new URL(callback).searchParams.get("code");
    const params = form({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri, resource });
    return { params, query, callback };
  }
  async function issue() {
    const { params } = await authorization();
    const tokens = await server.exchange(params);
    const refresh = form({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: clientId, redirect_uri: redirectUri, resource });
    return { tokens, refresh, bearer: "Bearer " + tokens.access_token };
  }
  return { server, config, clientId, authorization, issue };
}

test("OAuth rejects an unregistered redirect and registration containing an invalid redirect URI", async (t) => {
  const { server, authorization } = await fixture(t);
  const { query } = await authorization();
  query.set("redirect_uri", "https://another.example/callback");
  assert.throws(() => server.authorizeRequest(query));
  await assert.rejects(server.register({ redirect_uris: [redirectUri, "https://client.example/callback#fragment"] }));
});

test("OAuth rejects a resource mismatch at consent, issue, refresh and use", async (t) => {
  const { server, authorization, issue } = await fixture(t);
  const other = "https://other.example";
  const { query, params } = await authorization();
  query.set("resource", other);
  assert.throws(() => server.authorizeRequest(query));
  params.set("resource", other);
  await assert.rejects(server.exchange(params));
  params.delete("resource");
  await assert.rejects(server.exchange(params));
  const { bearer, refresh } = await issue();
  refresh.set("resource", other);
  await assert.rejects(server.exchange(refresh));
  assert.equal(server.verify(bearer, other).ok, false);
});

test("OAuth rejects expired access tokens", async (t) => {
  const { server, issue } = await fixture(t);
  const { bearer } = await issue();
  const now = Date.now();
  assert.equal(server.verify(bearer, resource).ok, true);
  t.mock.method(Date, "now", () => now + 3600001);
  assert.equal(server.verify(bearer, resource).ok, false);
});

test("OAuth individually revokes the grant, including rotated tokens, while another grant remains usable", async (t) => {
  const { server, issue, clientId } = await fixture(t);
  const first = await issue();
  const second = await issue();
  const rotated = await server.exchange(first.refresh);
  const grant = server.verify(first.bearer, resource).grantId;
  assert.equal(server.grantAllowsAgent(grant, clientId, "agent-a", "openbot.read"), true);
  assert.equal(server.grantAllowsAgent(grant, clientId, "outside", "openbot.read"), false);
  assert.equal(server.grantAllowsAgent(grant, clientId, "agent-a", "openbot.admin"), false);
  assert.equal(server.verify("Bearer " + rotated.access_token, resource).grantId, server.verify(first.bearer, resource).grantId);
  await server.revoke(form({ client_id: clientId, token: rotated.refresh_token }));
  assert.equal(server.verify(first.bearer, resource).ok, false);
  assert.equal(server.grantAllowsAgent(grant, clientId, "agent-a", "openbot.read"), false);
  assert.equal(server.verify("Bearer " + rotated.access_token, resource).ok, false);
  await assert.rejects(server.exchange(form({ ...Object.fromEntries(first.refresh), refresh_token: rotated.refresh_token })));
  assert.equal(server.verify(second.bearer, resource).ok, true);
});

test("OAuth refresh binds the client, resource and any supplied redirect URI", async (t) => {
  const { server, issue } = await fixture(t);
  const { refresh } = await issue();
  for (const [name, value] of [["client_id", "other-client"], ["redirect_uri", "https://other.example/callback"], ["client_id", null], ["resource", null]]) {
    const params = new URLSearchParams(refresh);
    if (value === null) params.delete(name);
    else params.set(name, value);
    await assert.rejects(server.exchange(params));
  }
  assert.ok((await server.exchange(refresh)).access_token);
});

test("OAuth rejects code replay under concurrent exchange", async (t) => {
  const { server, authorization } = await fixture(t);
  const { params } = await authorization();
  const settled = await Promise.allSettled([server.exchange(params), server.exchange(params)]);
  assert.deepEqual(settled.map(item => item.status).sort(), ["fulfilled", "rejected"]);
});

test("OAuth agent authority contracts on restart and an unlisted client sees no agents", async (t) => {
  const { server, issue, config, clientId } = await fixture(t);
  const { bearer } = await issue();
  assert.deepEqual(server.verify(bearer, resource).allowedAgentIds, ["agent-a", "agent-b"]);
  const restricted = new OAuthServer({ ...config, clientAgentIds: { [clientId]: ["agent-b", "ungranted"] } });
  await restricted.init();
  assert.deepEqual(restricted.verify(bearer, resource).allowedAgentIds, ["agent-b"]);
  const unlisted = new OAuthServer({ ...config, clientAgentIds: { "other-client": ["agent-a"] } });
  await unlisted.init();
  assert.deepEqual(unlisted.verify(bearer, resource).allowedAgentIds, []);
});

test("OAuth refuses a corrupt store and preserves its contents", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "bridge-store-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const store = join(dir, "auth", "state.json");
  await mkdir(join(dir, "auth"));
  await writeFile(store, "{", { mode: 0o600 });
  const server = new OAuthServer({ dataDir: dir, publicUrl: resource, adminSecret: randomBytes(32).toString("hex") });
  await assert.rejects(server.init());
  assert.equal(await readFile(store, "utf8"), "{");
});

test("code exchange requires the original redirect when explicitly requested", async t => {
  const { server, authorization } = await fixture(t);
  const { params } = await authorization();
  params.delete("redirect_uri");
  await assert.rejects(server.exchange(params), { code: "invalid_grant" });
  params.set("redirect_uri", "https://other.example/callback");
  await assert.rejects(server.exchange(params), { code: "invalid_grant" });
  params.set("redirect_uri", redirectUri);
  assert.ok((await server.exchange(params)).access_token);
});

test("authorization with a single registered redirect accepts omission through code exchange", async t => {
  const { server, authorization } = await fixture(t);
  const { params, callback } = await authorization({ includeRedirect: false });
  assert.equal(callback.split("?")[0], redirectUri);
  params.delete("redirect_uri");
  assert.ok((await server.exchange(params)).access_token);
});

test("authorization with multiple registered redirects rejects an omitted redirect", async t => {
  const { server, authorization } = await fixture(t);
  const { query } = await authorization();
  const client = await server.register({ redirect_uris: [redirectUri, "https://another.example/callback"] });
  query.set("client_id", client.client_id);
  query.delete("redirect_uri");
  assert.throws(() => server.authorizeRequest(query), { code: "invalid_request" });
});

test("independent concurrent OAuth refreshes persist both rotations across reload", async t => {
  const { server, config, issue } = await fixture(t);
  const a = await issue();
  const b = await issue();
  a.refresh.delete("redirect_uri");
  b.refresh.delete("redirect_uri");
  const renewed = await Promise.all([server.exchange(a.refresh), server.exchange(b.refresh)]);
  const reopened = new OAuthServer(config);
  await reopened.init();
  for (const [i, grant] of [a, b].entries()) {
    await assert.rejects(reopened.exchange(grant.refresh), { code: "invalid_grant" });
    const replacement = renewed[i];
    assert.equal(reopened.verify("Bearer " + replacement.access_token).ok, true);
    const next = new URLSearchParams(grant.refresh);
    next.set("refresh_token", replacement.refresh_token);
    assert.ok((await reopened.exchange(next)).access_token);
  }
});
