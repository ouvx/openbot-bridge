import { createHash, createHmac, randomUUID } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { isPrivateAddress, postPinned, resolveCallback } from "./callback.mjs";

/** kinds → ビット（notify_prefs.events と対応） */
export const NOTIFY_EVENTS = Object.freeze({ needs_approval: 1, completed: 2, failed: 4 });

const EVENT_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_PAYLOAD_BYTES = 512;

/**
 * 通知の設定を解決する。壊れた設定は「通知だけ止める」(fail-closed)。
 * 戻り値の mode が "off" のときは、Notifier は最初の行で return する。
 */
export function resolveNotifySettings(raw = {}, logger = null) {
  const off = (reason) => {
    if (reason) logger?.warn(`Notifications are off: ${reason}`);
    return { mode: "off" };
  };
  const mode = String(raw.mode ?? "off").trim().toLowerCase();
  if (mode === "" || mode === "off") return { mode: "off" };
  if (mode === "session") return off("'session' is reserved and not implemented; using off");
  if (mode !== "webhook") return off(`unknown BRIDGE_NOTIFY value; using off`);

  let url;
  try {
    url = new URL(String(raw.webhookUrl ?? ""));
  } catch {
    return off("BRIDGE_NOTIFY_WEBHOOK_URL is missing or invalid");
  }
  if (url.username || url.password || url.hash) return off("the webhook URL must not carry credentials or a fragment");
  const loopback = ["127.0.0.1", "[::1]", "::1"].includes(url.hostname);
  if (url.protocol === "http:") {
    if (!(loopback && raw.allowLoopbackHttp === true)) return off("the webhook URL must be HTTPS");
  } else if (url.protocol !== "https:") {
    return off("the webhook URL must be HTTPS");
  }

  let secret;
  try {
    const file = String(raw.secretFile ?? "");
    if (!file) return off("BRIDGE_NOTIFY_SECRET_FILE is not set");
    const stat = statSync(file);
    if ((stat.mode & 0o777) !== 0o600) return off("the secret file must have mode 0600");
    secret = readFileSync(file);
    if (secret.length < 16) return off("the secret file is too short");
  } catch {
    return off("the secret file is missing or unreadable");
  }

  return {
    mode: "webhook",
    url,
    host: url.host,
    secret,
    allowLoopbackHttp: raw.allowLoopbackHttp === true,
    timeoutMs: Math.max(500, Math.min(10000, Number(raw.timeoutMs ?? 3000) || 3000)),
  };
}

export class NotifyStore {
  #db;

  constructor(file) {
    this.#db = new DatabaseSync(file);
    this.#db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS notify_prefs (
        grant_id TEXT NOT NULL,
        client_id TEXT NOT NULL,
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
        events INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (grant_id, client_id)
      );
      CREATE TABLE IF NOT EXISTS notify_events (
        event_id TEXT PRIMARY KEY,
        at INTEGER NOT NULL
      );
    `);
  }

  static open(dataDir) {
    return new NotifyStore(join(dataDir, "notify.db"));
  }

  setPref({ grantId, clientId, enabled, events }) {
    this.#db.prepare(
      `INSERT INTO notify_prefs (grant_id, client_id, enabled, events, updated_at) VALUES (?,?,?,?,?)
       ON CONFLICT(grant_id, client_id) DO UPDATE SET enabled=excluded.enabled, events=excluded.events, updated_at=excluded.updated_at`,
    ).run(grantId, clientId, enabled ? 1 : 0, events, new Date().toISOString());
  }

  pref(grantId, clientId) {
    const row = this.#db.prepare("SELECT enabled, events FROM notify_prefs WHERE grant_id = ? AND client_id = ?").get(grantId, clientId);
    return row ? { enabled: row.enabled === 1, events: Number(row.events) } : null;
  }

  disableGrant(grantId) {
    this.#db.prepare("UPDATE notify_prefs SET enabled = 0, updated_at = ? WHERE grant_id = ?").run(new Date().toISOString(), grantId);
  }

  /** 同じ eventId を 1 回だけ通す。既に見ていれば false。 */
  claimEvent(eventId, now = Date.now()) {
    this.#db.prepare("DELETE FROM notify_events WHERE at < ?").run(now - EVENT_TTL_MS);
    try {
      this.#db.prepare("INSERT INTO notify_events (event_id, at) VALUES (?,?)").run(eventId, now);
      return true;
    } catch {
      return false;
    }
  }

  close() {
    this.#db.close();
  }
}

/** 決定的な eventId（同じタスク・同じ種別なら 1 回だけ送る） */
export function eventIdFor(grantId, taskId, kind) {
  const hex = createHash("sha256").update(`${grantId}:${taskId}:${kind}`).digest("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function sign(secret, timestamp, body) {
  return `sha256=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

/** ループバックの http 受信器（テスト用。許可フラグがあるときだけ使う） */
function postLoopback(url, headers, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      protocol: "http:",
      hostname: "127.0.0.1",
      port: url.port || 80,
      method: "POST",
      path: url.pathname + url.search,
      headers: { ...headers, host: url.host, "content-length": Buffer.byteLength(body) },
      signal: AbortSignal.timeout(timeoutMs),
    }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

/**
 * 通知の単一ゲート。無効時は先頭で即 return し、DB・ファイル・ソケットに触れない。
 * 送信は fire-and-forget（キューなし）。失敗しても呼び出し元へ投げない。
 */
export class Notifier {
  #settings;
  #store;
  #logger;
  #audit;
  #grantActive;
  #transport;
  #now;
  #limits;
  #sent = new Map();
  #dataDir = null;
  #suppressed = 0;
  #global = [];

  constructor({
    settings,
    logger,
    audit = null,
    grantActive = () => true,
    store = null,
    transport = null,
    now = () => Date.now(),
    limits = {},
  }) {
    this.#settings = settings;
    this.#logger = logger;
    this.#audit = audit;
    this.#grantActive = grantActive;
    this.#store = store;
    this.#now = now;
    this.#limits = {
      perGrantPerMinute: limits.perGrantPerMinute ?? 20,
      globalPerMinute: limits.globalPerMinute ?? 100,
    };
    this.#transport = transport ?? (async ({ url, headers, body, timeoutMs, allowLoopbackHttp }) => {
      if (url.protocol === "http:") {
        if (!(allowLoopbackHttp && ["127.0.0.1", "[::1]"].includes(url.hostname))) throw new Error("plain HTTP is not allowed");
        return postLoopback(url, headers, body, timeoutMs);
      }
      const approved = await resolveCallback(url);
      return postPinned(url, approved, headers, body, undefined, undefined, timeoutMs);
    });
  }

  get enabled() {
    return this.#settings.mode === "webhook";
  }

  #storeOrOpen() {
    if (!this.#store) this.#store = NotifyStore.open(this.#dataDir);
    return this.#store;
  }

  /** dataDir は store を遅延生成するときだけ使う */
  useDataDir(dir) {
    this.#dataDir = dir;
    return this;
  }

  /**
   * @param {"needs_approval"|"completed"|"failed"} kind
   * @param {{taskId: string, task: string, state: string, owner: {clientId: string, grantId: string}}} input
   */
  async notify(kind, input) {
    if (!this.enabled) return { sent: false, reason: "off" };

    const { owner } = input;
    const bit = NOTIFY_EVENTS[kind];
    if (!bit || !owner?.grantId || !owner?.clientId) return { sent: false, reason: "no-owner" };

    let store;
    try {
      store = this.#storeOrOpen();
    } catch (error) {
      this.#logger?.warn("Notification skipped: preference store unavailable", { error: String(error?.message ?? error) });
      return { sent: false, reason: "store" };
    }

    if (!this.#grantActive(owner.grantId, owner.clientId)) {
      try { store.disableGrant(owner.grantId); } catch { /* ignore */ }
      return { sent: false, reason: "grant" };
    }

    const pref = store.pref(owner.grantId, owner.clientId);
    if (!pref?.enabled || (pref.events & bit) === 0) return { sent: false, reason: "preference" };

    const eventId = eventIdFor(owner.grantId, input.taskId ?? input.task, kind);
    if (!store.claimEvent(eventId, this.#now())) return { sent: false, reason: "duplicate" };

    const now = this.#now();
    if (!this.#underRate(owner.grantId, now)) {
      this.#suppressed += 1;
      this.#logger?.info("Notification suppressed by rate limit", { kind, grantId: owner.grantId, eventId, suppressedTotal: this.#suppressed });
      return { sent: false, reason: "rate" };
    }

    const body = JSON.stringify({
      eventId,
      kind,
      task: String(input.task ?? "").slice(0, 200),
      state: String(input.state ?? "").slice(0, 40),
      at: new Date(now).toISOString(),
    });
    if (Buffer.byteLength(body) > MAX_PAYLOAD_BYTES) {
      this.#logger?.warn("Notification skipped: payload too large", { kind, eventId });
      return { sent: false, reason: "payload" };
    }

    const timestamp = String(Math.floor(now / 1000));
    const headers = {
      "content-type": "application/json",
      "x-bridge-signature": sign(this.#settings.secret, timestamp, body),
      "x-bridge-timestamp": timestamp,
      "x-bridge-event": eventId,
    };

    try {
      const res = await this.#transport({
        url: this.#settings.url,
        headers,
        body,
        timeoutMs: this.#settings.timeoutMs,
        allowLoopbackHttp: this.#settings.allowLoopbackHttp,
      });
      this.#audit?.({ event: "notify", kind, eventId, host: this.#settings.host, status: res?.status ?? null, ok: res?.status >= 200 && res?.status < 300 });
      return { sent: true, eventId, status: res?.status ?? null };
    } catch (error) {
      this.#logger?.warn("Notification delivery failed", {
        kind,
        eventId,
        host: this.#settings.host,
        error: String(error?.message ?? error).slice(0, 200),
      });
      this.#audit?.({ event: "notify", kind, eventId, host: this.#settings.host, ok: false });
      return { sent: false, reason: "transport" };
    }
  }

  #underRate(grantId, now) {
    const window = 60_000;
    const recent = (this.#sent.get(grantId) ?? []).filter((t) => now - t < window);
    this.#global = this.#global.filter((t) => now - t < window);
    if (recent.length >= this.#limits.perGrantPerMinute) { this.#sent.set(grantId, recent); return false; }
    if (this.#global.length >= this.#limits.globalPerMinute) { this.#sent.set(grantId, recent); return false; }
    recent.push(now);
    this.#global.push(now);
    this.#sent.set(grantId, recent);
    return true;
  }
}

export function createNotifier({ config, logger, audit, oauth, store = null, transport = null, now, limits }) {
  const settings = config.notifyResolved ?? resolveNotifySettings(config.notify ?? {}, logger);
  const notifier = new Notifier({
    settings,
    logger,
    audit,
    store,
    transport,
    now,
    limits,
    grantActive: (grantId, clientId) => (typeof oauth?.grantActive === "function" ? oauth.grantActive(grantId, clientId) : true),
  });
  return notifier.useDataDir(config.dataDir);
}
