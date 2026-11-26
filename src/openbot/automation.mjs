import { readFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Client for OpenBot's built-in automation ("Local scripts") API.
 *
 * The desktop app binds it to a random loopback port and writes `url`, `token`
 * and `headers` into its automation folder. The API sends a message to one
 * agent, reports the delivery, answers OpenBot's pending questions, and lets a
 * script start a new chat. Writes therefore happen inside OpenBot's own state
 * machine, which is why the bridge never touches the database directly.
 */
export class AutomationClient {
  #dir;
  #cached = null;
  #timeoutMs;

  constructor({ dir, timeoutMs = 15000 }) {
    this.#dir = dir;
    this.#timeoutMs = timeoutMs;
  }

  get dir() {
    return this.#dir;
  }

  /** True when the app has written its automation endpoint (Local scripts is on for at least one agent). */
  async exists() {
    try {
      await this.#connection();
      return true;
    } catch {
      return false;
    }
  }

  async #connection() {
    if (this.#cached) return this.#cached;
    const [url, token] = await Promise.all([
      readFile(join(this.#dir, "url"), "utf8"),
      readFile(join(this.#dir, "token"), "utf8"),
    ]);
    const connection = { url: url.trim().replace(/\/+$/, ""), token: token.trim() };
    if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(connection.url) || !connection.token) {
      throw new Error("OpenBot's automation endpoint is not usable.");
    }
    this.#cached = connection;
    return connection;
  }

  async #fetch(method, path, body, attempt = 0) {
    let connection;
    try {
      connection = await this.#connection();
    } catch {
      throw new AutomationUnavailable(
        "OpenBot's Local scripts API is off. In OpenBot: Settings → the agent → Local scripts, then try again.",
      );
    }
    let response;
    try {
      response = await fetch(`${connection.url}${path}`, {
        method,
        redirect: "error",
        headers: {
          authorization: `Bearer ${connection.token}`,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (error) {
      if (method === "GET" && attempt === 0) {
        this.#cached = null; // The app may have restarted with a new port.
        return this.#fetch(method, path, body, 1);
      }
      throw new AutomationUnavailable(`OpenBot did not answer (${error?.name ?? "network error"}).`);
    }
    const text = await response.text();
    let payload = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = null;
    }
    if (response.ok) return payload;
    if (response.status === 401 && method === "GET" && attempt === 0) {
      this.#cached = null;
      return this.#fetch(method, path, body, 1);
    }
    if (response.status === 401) throw new AutomationUnavailable("OpenBot rejected the automation token.");
    const reason = payload && typeof payload.error === "string" ? payload.error : `HTTP ${response.status}`;
    throw new AutomationRefused(reason, response.status);
  }

  async listAgents() {
    return (await this.#fetch("GET", "/v1/agents")) ?? [];
  }

  /**
   * Queues a message for one agent. `clientMessageId` is the caller's
   * idempotency key: OpenBot ignores a repeat of the same key, so a retried
   * bridge request cannot run the same task twice.
   */
  async sendMessage(agentId, text, clientMessageId) {
    return this.#fetch("POST", `/v1/agents/${encodeURIComponent(agentId)}/messages`, { text, clientMessageId });
  }

  async delivery(agentId, deliveryId) {
    return this.#fetch(
      "GET",
      `/v1/agents/${encodeURIComponent(agentId)}/deliveries/${encodeURIComponent(deliveryId)}`,
    );
  }

  async pending(agentId) {
    return this.#fetch("GET", `/v1/agents/${encodeURIComponent(agentId)}/pending`);
  }

  /** Starts a new chat with the agent; its settings, memory and files stay. */
  async newChat(agentId) {
    return this.#fetch("POST", `/v1/agents/${encodeURIComponent(agentId)}/context/clear`);
  }

  async health() {
    const started = Date.now();
    try {
      const agents = await this.listAgents();
      return { reachable: true, latencyMs: Date.now() - started, agents: agents.length };
    } catch (error) {
      return {
        reachable: false,
        latencyMs: Date.now() - started,
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

export class AutomationUnavailable extends Error {
  constructor(message) {
    super(message);
    this.name = "AutomationUnavailable";
    this.unavailable = true;
  }
}

export class AutomationRefused extends Error {
  constructor(message, status) {
    super(message);
    this.name = "AutomationRefused";
    this.status = status;
  }
}
