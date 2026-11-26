import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export const SCOPES = ["openbot.read", "openbot.write", "openbot.admin"];

const ACCESS_TTL_MS = 60 * 60 * 1000;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL_MS = 5 * 60 * 1000;
const sha256 = (value) => createHash("sha256").update(value).digest("base64url");
const token = (bytes = 32) => randomBytes(bytes).toString("base64url");
const emptyState = () => ({ clients: {}, codes: {}, access: {}, refresh: {} });
const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);

function one(params, name) {
  const values = params.getAll(name);
  if (values.length !== 1 || !values[0]) throw new OAuthError("invalid_request", `Exactly one ${name} is required.`);
  return values[0];
}

function validRedirect(value) {
  if (typeof value !== "string" || !value || value.length > 2048 || /[\s\\#]/.test(value)) return false;
  try {
    const url = new URL(value);
    if (url.username || url.password || !url.host || url.href !== value) return false;
    return url.protocol === "https:" ||
      (url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname));
  } catch {
    return false;
  }
}

function validStoredClient(id, client) {
  return isObject(client) && client.client_id === id && Array.isArray(client.redirect_uris) && client.redirect_uris.length > 0;
}

function validateStore(state) {
  if (!isObject(state) || !Object.keys(emptyState()).every(key => Object.hasOwn(state, key) && isObject(state[key]))) {
    throw new Error("Invalid OAuth state structure.");
  }
  if (!Object.entries(state.clients).every(([id, client]) => validStoredClient(id, client))) {
    throw new Error("Invalid OAuth client in state.");
  }
  for (const group of ["codes", "access", "refresh"]) {
    if (!Object.values(state[group]).every(row => isObject(row) && Number.isFinite(row.expiresAt) && typeof row.clientId === "string")) {
      throw new Error("Invalid OAuth credential in state.");
    }
  }
}

export class OAuthServer {
  #file;
  #state = emptyState();
  #adminSecret;
  #publicUrl;
  #logger;
  #agents;
  #clientAgents;
  #attempts = new Map();
  #pending = Promise.resolve();

  constructor({ dataDir, adminSecret, publicUrl, logger, allowedAgentIds = [], clientAgentIds = {} }) {
    this.#file = join(dataDir, "auth", "state.json");
    this.#adminSecret = adminSecret;
    this.#publicUrl = publicUrl;
    this.#logger = logger;
    this.#agents = [...new Set(allowedAgentIds)];
    this.#clientAgents = clientAgentIds;
  }

  get issuer() {
    return this.#publicUrl;
  }

  async init() {
    await mkdir(dirname(this.#file), { recursive: true, mode: 0o700 });
    let contents;
    try {
      contents = await readFile(this.#file, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") return;
      throw error;
    }
    const loaded = JSON.parse(contents);
    validateStore(loaded);
    this.#state = loaded;
  }

  // One process owns this store. Publish the new in-memory state only after
  // atomic replacement succeeds, so failed writes cannot consume a code.
  #change(update) {
    const run = this.#pending.then(async () => {
      const draft = structuredClone(this.#state);
      for (const group of ["codes", "access", "refresh"]) {
        for (const [key, row] of Object.entries(draft[group])) {
          if (row.expiresAt <= Date.now()) delete draft[group][key];
        }
      }
      const value = update(draft);
      const tmp = this.#file + "." + token(16) + ".tmp";
      try {
        await writeFile(tmp, JSON.stringify(draft), { mode: 0o600, flag: "wx" });
        await rename(tmp, this.#file);
      } finally {
        await rm(tmp, { force: true });
      }
      this.#state = draft;
      return value;
    });
    this.#pending = run.catch(() => {});
    return run;
  }

  #agentsFor(clientId) {
    const map = this.#clientAgents;
    if (Object.keys(map).length === 0) return this.#agents;
    const assigned = Object.hasOwn(map, clientId) ? map[clientId] : [];
    return this.#agents.filter(id => assigned.includes(id));
  }

  protectedResourceMetadata() {
    return {
      resource: this.#publicUrl,
      authorization_servers: [this.#publicUrl],
      scopes_supported: SCOPES,
      bearer_methods_supported: ["header"],
      resource_documentation: `${this.#publicUrl}/`,
    };
  }

  authorizationServerMetadata() {
    return {
      issuer: this.#publicUrl,
      authorization_endpoint: `${this.#publicUrl}/oauth/authorize`,
      token_endpoint: `${this.#publicUrl}/oauth/token`,
      registration_endpoint: `${this.#publicUrl}/oauth/register`,
      revocation_endpoint: `${this.#publicUrl}/oauth/revoke`,
      revocation_endpoint_auth_methods_supported: ["none"],
      scopes_supported: SCOPES,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      service_documentation: `${this.#publicUrl}/`,
    };
  }

  async register(input) {
    const uris = input?.redirect_uris;
    if (!Array.isArray(uris) || uris.length === 0 || uris.length > 16 || !uris.every(validRedirect)) {
      throw new OAuthError("invalid_client_metadata", "Invalid redirect_uris.");
    }
    const clientId = `client_${token(18)}`;
    const client = {
      client_id: clientId,
      client_name: typeof input.client_name === "string" ? input.client_name.slice(0, 120) : "MCP client",
      redirect_uris: [...uris],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      created_at: new Date().toISOString(),
    };
    await this.#change(state => { state.clients[clientId] = client; });
    this.#logger?.info("Registered an OAuth client", { clientId });
    return { ...client, client_id_issued_at: Math.floor(Date.now() / 1000) };
  }

  client(clientId) {
    return Object.hasOwn(this.#state.clients, clientId) ? this.#state.clients[clientId] : null;
  }

  #resource(query) {
    const resource = one(query, "resource");
    if (resource !== this.#publicUrl) throw new OAuthError("invalid_target", "Resource does not match this bridge.");
    return resource;
  }

  authorizeRequest(query) {
    if (one(query, "response_type") !== "code") throw new OAuthError("unsupported_response_type", "Only code is supported.");
    const clientId = one(query, "client_id");
    const client = this.client(clientId);
    if (!client) throw new OAuthError("invalid_client", "Unknown client.");
    // RFC 6749 §3.1.2.3: omission is unambiguous only for a single registered URI.
    const redirectUriProvided = query.has("redirect_uri");
    const redirectUri = redirectUriProvided ? one(query, "redirect_uri") :
      (client.redirect_uris.length === 1 ? client.redirect_uris[0] : undefined);
    if (!validRedirect(redirectUri) || !client.redirect_uris.includes(redirectUri)) {
      throw new OAuthError("invalid_request", "Invalid redirect_uri.");
    }
    const challenge = one(query, "code_challenge");
    if (one(query, "code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
      throw new OAuthError("invalid_request", "An S256 PKCE challenge is required.");
    }
    const resource = this.#resource(query);
    const scopes = [...new Set((query.has("scope") ? one(query, "scope") : "openbot.read").split(/\s+/).filter(Boolean))];
    if (!scopes.length || !scopes.every(scope => SCOPES.includes(scope))) throw new OAuthError("invalid_scope", "Invalid scope.");
    return { client, clientId, redirectUri, redirectUriProvided, state: query.get("state") ?? "", resource, codeChallenge: challenge, scopes };
  }

  async approve(request, passcode) {
    if (!this.#allowedAttempt(request.clientId)) throw new OAuthError("temporarily_unavailable", "Too many attempts.");
    if (!this.#passcodeMatches(passcode)) throw new OAuthError("access_denied", "Invalid passcode.");
    const code = `code_${token(24)}`;
    await this.#change(state => {
      state.codes[sha256(code)] = {
        clientId: request.clientId, redirectUri: request.redirectUri, redirectUriProvided: request.redirectUriProvided,
        codeChallenge: request.codeChallenge,
        scopes: request.scopes, resource: request.resource, expiresAt: Date.now() + CODE_TTL_MS,
        grantId: token(24), allowedAgentIds: [...this.#agentsFor(request.clientId)],
      };
    });
    const url = new URL(request.redirectUri);
    url.searchParams.set("code", code);
    if (request.state) url.searchParams.set("state", request.state);
    return url.toString();
  }

  #allowedAttempt(clientId) {
    const now = Date.now();
    const entry = this.#attempts.get(clientId) ?? { count: 0, resetAt: now + 60_000 };
    if (now >= entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + 60_000;
    }
    entry.count += 1;
    this.#attempts.set(clientId, entry);
    return entry.count <= 10;
  }

  #passcodeMatches(candidate) {
    if (typeof candidate !== "string") return false;
    const a = Buffer.from(candidate);
    const b = Buffer.from(this.#adminSecret);
    return a.length === b.length && timingSafeEqual(a, b);
  }

  #bound(entry) {
    // Older records lack the consent-time agent set and grant identity.
    return entry && typeof entry.grantId === "string" && entry.grantId.length > 0 &&
      entry.resource === this.#publicUrl && validRedirect(entry.redirectUri) &&
      Array.isArray(entry.allowedAgentIds) && entry.allowedAgentIds.every(id => typeof id === "string") &&
      Array.isArray(entry.scopes) && entry.scopes.every(scope => SCOPES.includes(scope)) &&
      this.client(entry.clientId)?.redirect_uris.includes(entry.redirectUri);
  }

  async exchange(params) {
    const type = one(params, "grant_type");
    if (type !== "authorization_code" && type !== "refresh_token") {
      throw new OAuthError("unsupported_grant_type", "Unsupported grant.");
    }
    const resource = this.#resource(params);
    const clientId = one(params, "client_id");
    const redirectUri = params.has("redirect_uri") ? one(params, "redirect_uri") : null;
    const isCode = type === "authorization_code";
    const key = sha256(one(params, isCode ? "code" : "refresh_token"));
    return this.#change(state => {
      const group = isCode ? state.codes : state.refresh;
      const entry = group[key];
      if (!this.#bound(entry) || entry.resource !== resource || entry.clientId !== clientId) {
        throw new OAuthError("invalid_grant", "Invalid grant or binding.");
      }
      // RFC 6749 §4.1.3 requires the same URI during code exchange when it was
      // sent during authorization. Codes written before the flag existed all
      // required an explicit redirect. §6 does not require a URI on refresh.
      // MCP's resource indicator and the original client binding apply to both.
      if ((redirectUri !== null && redirectUri !== entry.redirectUri) ||
          (isCode && entry.redirectUriProvided !== false && redirectUri === null)) {
        throw new OAuthError("invalid_grant", "Invalid redirect_uri binding.");
      }
      if (isCode) {
        const verifier = one(params, "code_verifier");
        if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || sha256(verifier) !== entry.codeChallenge) {
          throw new OAuthError("invalid_grant", "PKCE verification failed.");
        }
      }
      delete group[key];
      return this.#issue(state, entry);
    });
  }

  #issue(state, entry) {
    const { clientId, redirectUri, grantId, resource, scopes, allowedAgentIds } = entry;
    const binding = { clientId, redirectUri, grantId, resource, scopes, allowedAgentIds };
    const access = `obr_${token()}`;
    const refresh = `obf_${token()}`;
    state.access[sha256(access)] = { ...binding, expiresAt: Date.now() + ACCESS_TTL_MS };
    state.refresh[sha256(refresh)] = { ...binding, expiresAt: Date.now() + REFRESH_TTL_MS };
    return { access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL_MS / 1000, refresh_token: refresh, scope: scopes.join(" ") };
  }

  verify(header, expectedResource = this.#publicUrl) {
    if (typeof header !== "string" || !header.startsWith("Bearer ")) return { ok: false, reason: "missing" };
    const entry = this.#state.access[sha256(header.slice(7).trim())];
    if (!this.#bound(entry) || entry.resource !== expectedResource) return { ok: false, reason: "invalid" };
    if (entry.expiresAt <= Date.now()) return { ok: false, reason: "expired" };
    return {
      ok: true, clientId: entry.clientId, grantId: entry.grantId, scopes: [...entry.scopes],
      allowedAgentIds: this.#agentsFor(entry.clientId).filter(id => entry.allowedAgentIds.includes(id)),
    };
  }

  /** 通知の失効判定: 同じ grant/client の有効な資格情報が 1 つでも残っているか。 */
  grantActive(grantId, clientId) {
    const now = Date.now();
    const alive = entry => this.#bound(entry) && entry.expiresAt > now &&
      entry.grantId === grantId && entry.clientId === clientId &&
      Array.isArray(entry.scopes) && entry.scopes.includes("openbot.read");
    return Object.values(this.#state.access).some(alive) || Object.values(this.#state.refresh).some(alive);
  }

  grantAllowsAgent(grantId, clientId, agentId, scope) {
    if (typeof grantId !== "string" || !this.#agentsFor(clientId).includes(agentId)) return false;
    const permitted = entry => this.#bound(entry) && entry.expiresAt > Date.now() &&
      entry.grantId === grantId && entry.clientId === clientId && entry.scopes.includes(scope) &&
      entry.allowedAgentIds.includes(agentId);
    return Object.values(this.#state.access).some(permitted) || Object.values(this.#state.refresh).some(permitted);
  }

  hasScope(auth, scope) {
    return Boolean(auth?.ok && Array.isArray(auth.scopes) && auth.scopes.includes(scope));
  }

  async revoke(params) {
    const key = sha256(one(params, "token"));
    const clientId = one(params, "client_id");
    const presented = this.#state.access[key] ?? this.#state.refresh[key];
    if (!this.#bound(presented) || presented.clientId !== clientId) return;
    await this.#change(state => {
      const match = state.access[key] ?? state.refresh[key];
      if (!this.#bound(match) || match.clientId !== clientId) return;
      for (const entries of [state.codes, state.access, state.refresh]) {
        for (const [id, entry] of Object.entries(entries)) {
          if (entry.grantId === match.grantId && entry.clientId === clientId) delete entries[id];
        }
      }
    });
  }

  revokeAll() {
    return this.#change(state => {
      state.access = {};
      state.refresh = {};
      state.codes = {};
    });
  }

  stats() {
    return { clients: Object.keys(this.#state.clients).length, activeTokens: Object.keys(this.#state.access).length };
  }
}

export class OAuthError extends Error {
  constructor(code, description) {
    super(description);
    this.code = code;
    this.status = code === "access_denied" ? 403 : 400;
  }
}
