import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile, rename, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

export const SCOPES = ["openbot.read", "openbot.write", "openbot.admin"];

const ACCESS_TTL_MS = 60 * 60 * 1000;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const CODE_TTL_MS = 5 * 60 * 1000;

const sha256 = (value) => createHash("sha256").update(value).digest("base64url");
const token = (bytes = 32) => randomBytes(bytes).toString("base64url");

/**
 * A small OAuth 2.1 authorization server that lives in the bridge process.
 *
 * ChatGPT cannot send API keys, so the MCP spec's OAuth flow is the only
 * supported way to authenticate a custom plugin: protected-resource metadata,
 * authorization-server metadata, dynamic client registration, authorization
 * code + PKCE, and short-lived bearer tokens. The consent page asks for the
 * admin passcode, so only someone with access to this machine can link ChatGPT.
 */
export class OAuthServer {
  #file;
  #state = { clients: {}, codes: {}, access: {}, refresh: {} };
  #adminSecret;
  #publicUrl;
  #logger;
  #attempts = new Map();

  constructor({ dataDir, adminSecret, publicUrl, logger }) {
    this.#file = join(dataDir, "auth", "state.json");
    this.#adminSecret = adminSecret;
    this.#publicUrl = publicUrl;
    this.#logger = logger;
  }

  get issuer() {
    return this.#publicUrl;
  }

  async init() {
    await mkdir(dirname(this.#file), { recursive: true, mode: 0o700 });
    try {
      const loaded = JSON.parse(await readFile(this.#file, "utf8"));
      this.#state = { clients: {}, codes: {}, access: {}, refresh: {}, ...loaded };
    } catch {
      // First start: an empty store is correct.
    }
    this.#sweep();
  }

  async #save() {
    const tmp = `${this.#file}.tmp`;
    await writeFile(tmp, JSON.stringify(this.#state, null, 2), { mode: 0o600 });
    await rename(tmp, this.#file);
  }

  #sweep() {
    const now = Date.now();
    for (const group of ["codes", "access", "refresh"]) {
      for (const [key, value] of Object.entries(this.#state[group])) {
        if ((value.expiresAt ?? 0) < now) delete this.#state[group][key];
      }
    }
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
      scopes_supported: SCOPES,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      service_documentation: `${this.#publicUrl}/`,
    };
  }

  /** Dynamic client registration (public clients only, no client secret). */
  async register(input) {
    const redirectUris = Array.isArray(input?.redirect_uris) ? input.redirect_uris.filter(isHttpsUrlOrLoopback) : [];
    if (redirectUris.length === 0) throw new OAuthError("invalid_client_metadata", "redirect_uris is required");
    const clientId = `client_${token(18)}`;
    const client = {
      client_id: clientId,
      client_name: typeof input.client_name === "string" ? input.client_name.slice(0, 120) : "ChatGPT",
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      created_at: new Date().toISOString(),
    };
    this.#state.clients[clientId] = client;
    await this.#save();
    this.#logger?.info("Registered an OAuth client", { clientId, clientName: client.client_name });
    return {
      ...client,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
  }

  client(clientId) {
    return this.#state.clients[clientId] ?? null;
  }

  /**
   * Validates an authorization request and returns what the consent page needs.
   * Throws OAuthError with a redirect-safe description when the request is wrong.
   */
  authorizeRequest(query) {
    const responseType = query.get("response_type");
    if (responseType !== "code") throw new OAuthError("unsupported_response_type", "Only response_type=code is supported.");
    const clientId = query.get("client_id");
    const client = this.client(clientId ?? "");
    if (!client) throw new OAuthError("invalid_client", "Unknown client_id.");
    const redirectUri = query.get("redirect_uri") ?? client.redirect_uris[0];
    if (!client.redirect_uris.includes(redirectUri)) throw new OAuthError("invalid_request", "redirect_uri is not registered.");
    const challenge = query.get("code_challenge");
    if (!challenge) throw new OAuthError("invalid_request", "PKCE code_challenge is required.");
    if ((query.get("code_challenge_method") ?? "S256") !== "S256") {
      throw new OAuthError("invalid_request", "Only S256 PKCE is supported.");
    }
    const requested = (query.get("scope") ?? "openbot.read").split(/\s+/).filter(Boolean);
    const scopes = requested.filter((scope) => SCOPES.includes(scope));
    if (scopes.length === 0) throw new OAuthError("invalid_scope", "No supported scope was requested.");
    return {
      client,
      clientId,
      redirectUri,
      state: query.get("state") ?? "",
      resource: query.get("resource") ?? this.#publicUrl,
      codeChallenge: challenge,
      scopes,
    };
  }

  /** Step two of consent: the user typed the passcode on this machine. */
  async approve(request, passcode) {
    if (!this.#allowedAttempt(request.clientId)) {
      throw new OAuthError("temporarily_unavailable", "Too many passcode attempts. Wait a minute.");
    }
    if (!this.#passcodeMatches(passcode)) throw new OAuthError("access_denied", "The passcode is wrong.");
    const code = `code_${token(24)}`;
    this.#state.codes[code] = {
      clientId: request.clientId,
      redirectUri: request.redirectUri,
      codeChallenge: request.codeChallenge,
      scopes: request.scopes,
      resource: request.resource,
      expiresAt: Date.now() + CODE_TTL_MS,
    };
    await this.#save();
    const url = new URL(request.redirectUri);
    url.searchParams.set("code", code);
    if (request.state) url.searchParams.set("state", request.state);
    return url.toString();
  }

  #allowedAttempt(clientId) {
    const now = Date.now();
    const entry = this.#attempts.get(clientId) ?? { count: 0, resetAt: now + 60_000 };
    if (now > entry.resetAt) {
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
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  }

  /** Authorization-code or refresh-token exchange. */
  async exchange(params) {
    const grantType = params.get("grant_type");
    if (grantType === "authorization_code") return this.#exchangeCode(params);
    if (grantType === "refresh_token") return this.#exchangeRefresh(params);
    throw new OAuthError("unsupported_grant_type", "Use authorization_code or refresh_token.");
  }

  async #exchangeCode(params) {
    const code = params.get("code") ?? "";
    const entry = this.#state.codes[code];
    if (!entry || entry.expiresAt < Date.now()) throw new OAuthError("invalid_grant", "The code is unknown or expired.");
    const clientId = params.get("client_id") ?? entry.clientId;
    if (clientId !== entry.clientId) throw new OAuthError("invalid_grant", "The code belongs to another client.");
    const verifier = params.get("code_verifier");
    if (!verifier) throw new OAuthError("invalid_request", "code_verifier is required.");
    if (sha256(verifier) !== entry.codeChallenge) throw new OAuthError("invalid_grant", "PKCE verification failed.");
    if (params.get("redirect_uri") && params.get("redirect_uri") !== entry.redirectUri) {
      throw new OAuthError("invalid_grant", "redirect_uri does not match the authorization request.");
    }
    delete this.#state.codes[code];
    return this.#issue(entry.clientId, entry.scopes);
  }

  async #exchangeRefresh(params) {
    const refresh = params.get("refresh_token") ?? "";
    const key = sha256(refresh);
    const entry = this.#state.refresh[key];
    if (!entry || entry.expiresAt < Date.now()) throw new OAuthError("invalid_grant", "The refresh token is unknown or expired.");
    delete this.#state.refresh[key];
    return this.#issue(entry.clientId, entry.scopes);
  }

  async #issue(clientId, scopes) {
    const access = `obr_${token(32)}`;
    const refresh = `obf_${token(32)}`;
    this.#state.access[sha256(access)] = {
      clientId,
      scopes,
      expiresAt: Date.now() + ACCESS_TTL_MS,
      createdAt: new Date().toISOString(),
    };
    this.#state.refresh[sha256(refresh)] = { clientId, scopes, expiresAt: Date.now() + REFRESH_TTL_MS };
    await this.#save();
    return {
      access_token: access,
      token_type: "Bearer",
      expires_in: Math.floor(ACCESS_TTL_MS / 1000),
      refresh_token: refresh,
      scope: scopes.join(" "),
    };
  }

  /** Bearer-token check used by every request to /mcp. */
  verify(header) {
    if (!header || !header.startsWith("Bearer ")) return { ok: false, reason: "missing" };
    const hash = sha256(header.slice(7).trim());
    const entry = this.#state.access[hash];
    if (!entry) return { ok: false, reason: "invalid" };
    if (entry.expiresAt < Date.now()) {
      delete this.#state.access[hash];
      return { ok: false, reason: "expired" };
    }
    return { ok: true, clientId: entry.clientId, scopes: entry.scopes };
  }

  hasScope(auth, scope) {
    return Boolean(auth?.ok && Array.isArray(auth.scopes) && auth.scopes.includes(scope));
  }

  async revokeAll() {
    this.#state.access = {};
    this.#state.refresh = {};
    this.#state.codes = {};
    await this.#save();
  }

  stats() {
    return {
      clients: Object.keys(this.#state.clients).length,
      activeTokens: Object.keys(this.#state.access).length,
    };
  }
}

export class OAuthError extends Error {
  constructor(code, description) {
    super(description);
    this.code = code;
    this.status = code === "access_denied" ? 403 : 400;
  }
}

function isHttpsUrlOrLoopback(value) {
  try {
    const url = new URL(value);
    if (url.protocol === "https:") return true;
    return url.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  } catch {
    return false;
  }
}
