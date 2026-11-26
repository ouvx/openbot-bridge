import { createHash, randomBytes, timingSafeEqual, createHmac } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const SECRET_PREFIX = "whsec_";

/**
 * MCP Events support (官方: ChatGPT が購読し、bridge が Webhook で通知する).
 *
 * Implemented defensively: only HTTPS callbacks, no redirects, private
 * addresses refused, Standard Webhooks HMAC signatures, a single-use challenge
 * before the first delivery, and a deterministic subscription id so a repeated
 * subscribe refreshes instead of duplicating.
 */
export class EventBus {
  #file;
  #stateFile;
  #subscriptions = new Map();
  #seen = new Map();
  #logger;
  #jobs;
  #db;
  #timer = null;

  constructor({ dataDir, logger, jobs, db }) {
    this.#file = join(dataDir, "events", "subscriptions.json");
    this.#stateFile = join(dataDir, "events", "delivered.json");
    this.#logger = logger;
    this.#jobs = jobs;
    this.#db = db;
  }

  definitions() {
    return [
      {
        name: "task.status_changed",
        description: "An OpenBot task the bridge started changed status (queued, running, needs_person, completed, failed, cancelled).",
        delivery: ["webhook"],
        inputSchema: {
          type: "object",
          properties: {
            agent_id: { type: "string", description: "Only report tasks for this agent id." },
          },
          additionalProperties: false,
        },
        payloadSchema: {
          type: "object",
          properties: {
            task_id: { type: "string" },
            agent_id: { type: "string" },
            status: { type: "string" },
            title: { type: "string" },
            error: { type: ["string", "null"] },
            updated_at: { type: "string" },
          },
          required: ["task_id", "agent_id", "status"],
          additionalProperties: false,
        },
      },
      {
        name: "task.needs_person",
        description: "An OpenBot agent is waiting for a person: it asked a question or needs an approval inside OpenBot.",
        delivery: ["webhook"],
        inputSchema: {
          type: "object",
          properties: {
            agent_id: { type: "string", description: "Only report this agent id." },
          },
          additionalProperties: false,
        },
        payloadSchema: {
          type: "object",
          properties: {
            task_id: { type: "string" },
            agent_id: { type: "string" },
            title: { type: "string" },
            agent_name: { type: "string" },
            updated_at: { type: "string" },
          },
          required: ["task_id", "agent_id"],
          additionalProperties: false,
        },
      },
    ];
  }

  async init() {
    await mkdir(dirname(this.#file), { recursive: true, mode: 0o700 });
    try {
      const loaded = JSON.parse(await readFile(this.#file, "utf8"));
      for (const sub of loaded) if (sub.expiresAt > Date.now()) this.#subscriptions.set(sub.id, sub);
    } catch {
      // none
    }
    try {
      const seen = JSON.parse(await readFile(this.#stateFile, "utf8"));
      for (const [key, value] of Object.entries(seen)) this.#seen.set(key, value);
    } catch {
      // none
    }
  }

  async #save() {
    const tmp = `${this.#file}.tmp`;
    await writeFile(tmp, JSON.stringify([...this.#subscriptions.values()], null, 2), { mode: 0o600 });
    await rename(tmp, this.#file);
  }

  async #saveSeen() {
    const entries = [...this.#seen.entries()].slice(-5000);
    this.#seen = new Map(entries);
    const tmp = `${this.#stateFile}.tmp`;
    await writeFile(tmp, JSON.stringify(Object.fromEntries(entries)), { mode: 0o600 });
    await rename(tmp, this.#stateFile);
  }

  /** events/subscribe */
  async subscribe({ name, arguments: args = {}, delivery = {}, cursor = null }, principal) {
    const definition = this.definitions().find((event) => event.name === name);
    if (!definition) throw new EventError("unknown_event", `The bridge does not offer an event named ${name}.`);
    if (delivery.mode !== "webhook") throw new EventError("unsupported_delivery", "Only webhook delivery is supported.");
    const url = String(delivery.url ?? "");
    const secret = String(delivery.secret ?? "");
    if (!url.startsWith("https://")) throw new EventError("invalid_callback", "The callback URL must be HTTPS.");
    if (!secret.startsWith(SECRET_PREFIX)) throw new EventError("invalid_secret", "The signing secret must start with whsec_.");
    const key = Buffer.from(secret.slice(SECRET_PREFIX.length), "base64");
    if (key.length < 24 || key.length > 64) throw new EventError("invalid_secret", "The signing secret must decode to 24–64 bytes.");
    await assertPublicHttps(url);
    const agentId = typeof args.agent_id === "string" ? args.agent_id : null;
    const id = `sub_${createHash("sha256")
      .update(`${principal}|${url}|${name}|${canonicalJson(args)}`)
      .digest("base64url")
      .slice(0, 24)}`;
    const existing = this.#subscriptions.get(id);
    const subscription = {
      id,
      principal,
      name,
      agentId,
      url,
      secret,
      verified: existing?.verified ? existing.verifiedAt > Date.now() - 24 * 60 * 60 * 1000 : false,
      verifiedAt: existing?.verifiedAt ?? 0,
      createdAt: existing?.createdAt ?? new Date().toISOString(),
      expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      cursor,
    };
    if (!subscription.verified) {
      const challenge = randomBytes(32).toString("base64url");
      const verificationId = `msg_verification_${randomBytes(8).toString("hex")}`;
      const accepted = await this.#post(subscription, verificationId, { type: "verification", challenge });
      if (!accepted.ok) throw new EventError("challenge_failed", `The callback did not verify (${accepted.reason}).`);
      subscription.verified = true;
      subscription.verifiedAt = Date.now();
    }
    this.#subscriptions.set(id, subscription);
    await this.#save();
    this.#logger.info("Event subscription stored", { id, name, agentId });
    return {
      id,
      refreshBefore: new Date(subscription.expiresAt).toISOString(),
      cursor: null,
      truncated: false,
    };
  }

  async unsubscribe(id, principal) {
    const subscription = this.#subscriptions.get(id);
    if (!subscription || (principal && subscription.principal !== principal)) return { removed: false };
    this.#subscriptions.delete(id);
    await this.#save();
    return { removed: true };
  }

  get count() {
    return this.#subscriptions.size;
  }

  start(intervalMs = 8000) {
    if (this.#timer) return;
    this.#timer = setInterval(() => {
      this.#poll().catch((error) => this.#logger.warn("Event poll failed", { error: error instanceof Error ? error.message : String(error) }));
    }, intervalMs);
    this.#timer.unref?.();
  }

  stop() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  async #poll() {
    if (this.#subscriptions.size === 0) return;
    const now = Date.now();
    for (const [id, sub] of [...this.#subscriptions]) {
      if (sub.expiresAt < now) {
        this.#subscriptions.delete(id);
        await this.#save();
        continue;
      }
    }
    const jobs = this.#jobs.list({ limit: 50 });
    let changed = false;
    for (const job of jobs) {
      const previous = this.#seen.get(job.id);
      if (previous === job.status) continue;
      this.#seen.set(job.id, job.status);
      changed = true;
      for (const sub of this.#subscriptions.values()) {
        if (sub.agentId && sub.agentId !== job.agentId) continue;
        if (sub.name === "task.status_changed") {
          await this.#deliver(sub, {
            eventId: `evt_${randomBytes(12).toString("hex")}`,
            name: "task.status_changed",
            timestamp: new Date().toISOString(),
            data: {
              task_id: job.id,
              agent_id: job.agentId,
              status: job.status,
              title: job.title,
              error: job.error ?? null,
              updated_at: job.updatedAt,
            },
          });
        }
        if (sub.name === "task.needs_person" && job.status === "needs_person") {
          await this.#deliver(sub, {
            eventId: `evt_${randomBytes(12).toString("hex")}`,
            name: "task.needs_person",
            timestamp: new Date().toISOString(),
            data: {
              task_id: job.id,
              agent_id: job.agentId,
              title: job.title,
              agent_name: this.#db.agent(job.agentId)?.name ?? job.agentId,
              updated_at: job.updatedAt,
            },
          });
        }
      }
    }
    if (changed) await this.#saveSeen();
  }

  async #deliver(subscription, event) {
    const body = JSON.stringify(event);
    if (Buffer.byteLength(body, "utf8") > 256 * 1024) {
      this.#logger.warn("Event payload too large", { eventId: event.eventId });
      return;
    }
    for (let attempt = 0; attempt < 3; attempt++) {
      const result = await this.#post(subscription, event.eventId, event, body);
      if (result.ok) return;
      await new Promise((resolve) => setTimeout(resolve, 1000 * (attempt + 1)));
    }
    this.#logger.warn("Event delivery failed", { id: subscription.id, eventId: event.eventId });
  }

  async #post(subscription, webhookId, payload, body = JSON.stringify(payload)) {
    await assertPublicHttps(subscription.url).catch(() => {});
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = sign(subscription.secret, webhookId, timestamp, body);
    try {
      const response = await fetch(subscription.url, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
        headers: {
          "content-type": "application/json",
          "webhook-id": webhookId,
          "webhook-timestamp": timestamp,
          "webhook-signature": signature,
          "X-MCP-Subscription-Id": subscription.id,
        },
        body,
      });
      if (!response.ok) return { ok: false, reason: `HTTP ${response.status}` };
      if (payload.type === "verification") {
        const answer = await response.json().catch(() => null);
        return { ok: Boolean(answer && answer.challenge === payload.challenge), reason: "challenge did not match" };
      }
      return { ok: true };
    } catch (error) {
      return { ok: false, reason: error instanceof Error ? error.message : "network error" };
    }
  }
}

function sign(secret, webhookId, timestamp, body) {
  const key = Buffer.from(secret.replace(SECRET_PREFIX, ""), "base64");
  const mac = createHmac("sha256", key).update(`${webhookId}.${timestamp}.${body}`).digest("base64");
  return `v1,${mac}`;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

/** Refuses callbacks that point at a private address or use a non-HTTPS scheme. */
export async function assertPublicHttps(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") throw new EventError("invalid_callback", "The callback URL must be HTTPS.");
  if (parsed.username || parsed.password) throw new EventError("invalid_callback", "The callback URL must not contain credentials.");
  const host = parsed.hostname;
  const addresses = isIP(host) ? [{ address: host }] : await lookup(host, { all: true });
  for (const { address } of addresses) {
    if (isPrivateAddress(address)) throw new EventError("invalid_callback", "The callback URL must not point at a private address.");
  }
  return true;
}

export function isPrivateAddress(address) {
  const privateRanges = [
    /^10\./,
    /^127\./,
    /^169\.254\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^0\./,
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
    /^::1$/,
    /^f[cd][0-9a-f]{2}:/i,
    /^fe80:/i,
  ];
  return privateRanges.some((pattern) => pattern.test(address));
}

export class EventError extends Error {
  constructor(reason, message) {
    super(message);
    this.code = -32015;
    this.reason = reason;
  }
}

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}
