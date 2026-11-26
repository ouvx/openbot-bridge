import { createHash, randomUUID } from "node:crypto";
import { closeSync, lstatSync, mkdirSync, openSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const hash = text => createHash("sha256").update(text, "utf8").digest("hex");
export class OperationError extends Error {
  constructor(code, options) { super(code, options); this.code = code; }
}
const deny = code => { throw new OperationError(code); };
function storeErrorCode(error) {
  if (error instanceof OperationError) return error.code;
  // The low byte of SQLite's extended result code is the primary result code (5 = BUSY).
  if (error?.code === "ERR_SQLITE_ERROR" && (error.errcode & 255) === 5) return "operation_store_busy";
  return "operation_store_unavailable";
}

const approvalIdPattern = /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/i;

// Canonical JSON: trim + NFC strings (including keys), sort keys by UTF-16 code
// units, retain array order, use JSON's finite-number spelling, reject collisions.
export function canonicalJSON(value) {
  if (typeof value === "string") return JSON.stringify(value.trim().normalize("NFC"));
  if (typeof value === "number" && !Number.isFinite(value)) deny("invalid_arguments");
  if (value === null || ["boolean", "number"].includes(typeof value)) return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  if (!value || typeof value !== "object" || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) deny("invalid_arguments");
  const fields = new Map();
  for (const [key, item] of Object.entries(value)) {
    const name = key.trim().normalize("NFC");
    if (fields.has(name)) deny("invalid_arguments");
    fields.set(name, item);
  }
  return "{" + [...fields.keys()].sort().map(k => JSON.stringify(k) + ":" + canonicalJSON(fields.get(k))).join(",") + "}";
}

function describe({ tool, args, targets, auth, idempotencyKey }) {
  if (!auth?.ok || !auth.grantId || !auth.clientId) deny("unauthenticated");
  if (!Array.isArray(targets) || !targets.length || !targets.every(id =>
    typeof id === "string" && id.length && id === id.trim().normalize("NFC") && auth.allowedAgentIds?.includes(id))) deny("target_denied");
  if (typeof tool !== "string" || !/^[a-z][a-z0-9_]*$/.test(tool)) deny("invalid_tool");
  const normalized = canonicalJSON(args);
  const sorted = [...new Set(targets)].sort();
  const argsHash = hash(canonicalJSON([tool, JSON.parse(normalized)]));
  // Display every effective argument. Escape invisible formatting characters
  // in the human-facing JSON in addition to JSON's built-in control escapes.
  const summary = canonicalJSON({ tool, targets: sorted, args: JSON.parse(normalized) }).replace(
    /[\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g,
    ch => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
  if (idempotencyKey != null && (typeof idempotencyKey !== "string" || !idempotencyKey.trim())) deny("invalid_idempotency_key");
  const key = idempotencyKey == null ? ["derived", tool, argsHash] : ["caller", idempotencyKey.trim().normalize("NFC")];
  return { grantId: auth.grantId, clientId: auth.clientId, tool, argsHash, targets: JSON.stringify(sorted),
    normalized, summary, summaryHash: hash(summary), opKey: hash(JSON.stringify([auth.grantId, auth.clientId, key])) };
}

export class OperationStore {
  #db;
  #now;
  #ttl;
  #subjectLimit;
  #globalLimit;

  #issuanceGrantLimit;
  #issuanceGlobalLimit;

  constructor({ dataDir, ttlSeconds = 120, subjectLimit = 12, globalLimit = 60,
    issuanceGrantLimit = 8, issuanceGlobalLimit = 40, now = Date.now }) {
    if (![ttlSeconds, subjectLimit, globalLimit, issuanceGrantLimit, issuanceGlobalLimit].every(n => Number.isSafeInteger(n) && n > 0)) deny("invalid_operation_limits");
    this.#now = now;
    this.#ttl = ttlSeconds * 1000;
    this.#subjectLimit = subjectLimit;
    this.#globalLimit = globalLimit;
    this.#issuanceGrantLimit = issuanceGrantLimit;
    this.#issuanceGlobalLimit = issuanceGlobalLimit;
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    const dir = lstatSync(dataDir);
    const uid = process.getuid?.();
    if (!dir.isDirectory() || (dir.mode & 0o022) || (uid !== undefined && dir.uid !== uid)) deny("unsafe_operation_store");
    const path = join(dataDir, "operations.sqlite");
    try { closeSync(openSync(path, "wx", 0o600)); }
    catch (e) { if (e.code !== "EEXIST") throw e; }
    const info = lstatSync(path);
    if (!info.isFile() || info.nlink !== 1 || (info.mode & 0o077) || (uid !== undefined && info.uid !== uid)) deny("unsafe_operation_store");
    this.#db = new DatabaseSync(path);
    try {
      this.#db.exec(`
        PRAGMA busy_timeout=2000;
        PRAGMA synchronous=FULL;
        PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS approvals (
          approvalId TEXT PRIMARY KEY, auditId TEXT NOT NULL, grantId TEXT NOT NULL, clientId TEXT NOT NULL,
          tool TEXT NOT NULL, argsHash TEXT NOT NULL, targets TEXT NOT NULL, summaryHash TEXT NOT NULL,
          summary TEXT, opKey TEXT NOT NULL, issuedAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL,
          state TEXT NOT NULL, usedAt INTEGER, result TEXT
        );
        CREATE INDEX IF NOT EXISTS op_key ON approvals(opKey);
        CREATE INDEX IF NOT EXISTS op_issued ON approvals(issuedAt,grantId);
        CREATE INDEX IF NOT EXISTS op_used ON approvals(usedAt);
        CREATE TABLE IF NOT EXISTS operation_audit (
          eventId INTEGER PRIMARY KEY, auditId TEXT, approvalId TEXT, grantId TEXT, clientId TEXT,
          tool TEXT, argsHash TEXT, issuedAt INTEGER, usedAt INTEGER, at INTEGER NOT NULL, outcome TEXT NOT NULL
        );
      `);
      // カード発行は DB を正とする。既存ファイルにも列を足す（値は NULL = 未発行）。
      const columns = this.#db.prepare("PRAGMA table_info(approvals)").all().map(column => column.name);
      if (!columns.includes("cardOpenedAt")) this.#db.exec("ALTER TABLE approvals ADD COLUMN cardOpenedAt INTEGER");
    } catch (error) { this.#db.close(); throw error; }
  }

  close() { this.#db.close(); }

  #transaction(action) {
    this.#db.exec("BEGIN IMMEDIATE");
    try {
      const result = action();
      this.#db.exec("COMMIT");
      return result;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  #audit(row, outcome) {
    this.#db.prepare(`INSERT INTO operation_audit
      (auditId,approvalId,grantId,clientId,tool,argsHash,issuedAt,usedAt,at,outcome)
      VALUES(?,?,?,?,?,?,?,?,?,?)`).run(row?.auditId ?? null, approvalIdPattern.test(row?.approvalId) ? row.approvalId : null, row?.grantId ?? null,
      row?.clientId ?? null, row?.tool ?? null, row?.argsHash ?? null, row?.issuedAt ?? null, row?.usedAt ?? null,
      this.#now(), outcome);
  }

  #row(id) {
    return this.#db.prepare("SELECT * FROM approvals WHERE approvalId=?").get(id ?? "");
  }

  recordDenial(input, code) {
    try {
      let row = this.#row(input.approvalId);
      if (!row && !input.approvalId) {
        try { row = this.#latest(describe(input)); }
        catch (error) { if (!(error instanceof OperationError)) throw error; }
      }
      const { auth, tool } = input;
      let argsHash = null;
      let outcome = code;
      if (tool && input.args) {
        try { argsHash = hash(canonicalJSON([tool, input.args])); }
        catch { outcome = code + ":args_hash_unavailable"; }
      }
      this.#audit({ ...row, approvalId: input.approvalId ?? row?.approvalId, grantId: auth?.grantId, clientId: auth?.clientId, tool, argsHash }, outcome);
    } catch (error) { deny(storeErrorCode(error)); }
  }

  #guard(input, action) {
    try { return this.#transaction(action); }
    catch (err) {
      const code = storeErrorCode(err);
      this.recordDenial(input, code);
      deny(code);
    }
  }

  #check(row, desc, byKey = false) {
    if (row.grantId !== desc.grantId || row.clientId !== desc.clientId) deny("approval_principal_mismatch");
    if (row.tool !== desc.tool || row.argsHash !== desc.argsHash || row.targets !== desc.targets) {
      deny(byKey ? "idempotency_conflict" : "approval_arguments_mismatch");
    }
    if (row.opKey !== desc.opKey) deny("approval_key_mismatch");
    if (row.summaryHash !== desc.summaryHash) deny("approval_card_mismatch");
  }

  #latest(desc) {
    return this.#db.prepare("SELECT * FROM approvals WHERE opKey=? ORDER BY rowid DESC LIMIT 1").get(desc.opKey);
  }

  #prepared(row) {
    return { approvalId: row.approvalId, summary: row.summary, summaryHash: row.summaryHash, expiresAt: row.expiresAt, state: row.state };
  }

  #cache(row) {
    if (row.result == null || row.state !== "completed") deny("operation_in_progress_or_uncertain");
    const result = JSON.parse(row.result);
    this.#audit(row, "cached_result");
    return { cached: true, result };
  }

  prepare(input) {
    return this.#guard(input, () => {
      const desc = describe(input);
      const now = this.#now();
      const old = this.#latest(desc);
      if (old) {
        this.#check(old, desc, true);
        if (old.usedAt !== null) return this.#cache(old);
        if (old.state === "declined") deny("approval_declined");
        if (["pending", "approved"].includes(old.state) && old.expiresAt > now) return this.#prepared({ ...old, summary: desc.summary });
      }
      // Count every issued card, even one already consumed or declined. Idempotent
      // lookups above never spend a new slot. BEGIN IMMEDIATE serializes this with INSERT.
      const issued = this.#db.prepare(`SELECT count(*) AS total,
        count(CASE WHEN grantId=? THEN 1 END) AS personal
        FROM approvals WHERE issuedAt>?`).get(desc.grantId, now - 60000);
      if (issued.personal >= this.#issuanceGrantLimit || issued.total >= this.#issuanceGlobalLimit) {
        deny("approval_issue_rate_limited");
      }
      this.#db.prepare("UPDATE approvals SET state='expired',summary=NULL WHERE state IN ('pending','approved') AND expiresAt<=?").run(now);
      const pending = this.#db.prepare(`SELECT count(*) AS total, count(CASE WHEN grantId=? THEN 1 END) AS personal
        FROM approvals WHERE state IN ('pending','approved')`).get(desc.grantId);
      if (pending.total >= 256 || pending.personal >= 32) deny("too_many_pending");
      const row = { ...desc, approvalId: randomUUID(), auditId: randomUUID(), issuedAt: now, expiresAt: now + this.#ttl, state: "pending" };
      this.#db.prepare(`INSERT INTO approvals
        (approvalId,auditId,grantId,clientId,tool,argsHash,targets,summaryHash,summary,opKey,issuedAt,expiresAt,state)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'pending')`).run(row.approvalId,row.auditId,row.grantId,row.clientId,row.tool,
          row.argsHash,row.targets,row.summaryHash,row.summary,row.opKey,row.issuedAt,row.expiresAt);
      this.#audit(row, "issued");
      return this.#prepared(row);
    });
  }

  card(approvalId, openedAt = undefined) {
    const row = this.#row(approvalId);
    if (!row) deny("approval_unknown");
    if (row.expiresAt <= this.#now()) deny("approval_expired");
    if (row.state !== "pending") deny("approval_not_pending");
    // 呼び出し元が発行世代を渡した場合だけ照合する（--replace で古い画面を無効化）。
    if (openedAt !== undefined && (row.cardOpenedAt ?? null) !== openedAt) deny("approval_card_stale");
    if (hash(row.summary) !== row.summaryHash) deny("approval_card_mismatch");
    return { ...this.#prepared(row), tool: row.tool, targets: JSON.parse(row.targets), grantId: row.grantId, clientId: row.clientId,
      argsHash: row.argsHash, auditId: row.auditId, issuedAt: row.issuedAt };
  }

  /**
   * カード発行の予約。DB の条件付き UPDATE で、同時に起動しても1枚しか勝たない。
   * replace=true のときだけ既存の画面を失効させて新しい世代を発行する。
   */
  reserveCard(approvalId, { replace = false } = {}) {
    return this.#transaction(() => {
      const now = this.#now();
      // 期限切れは状態にも反映する（監査と list で期限切れと分かるように）。
      this.sweepExpired(now);
      const row = this.#row(approvalId);
      if (!row) deny("approval_unknown");
      if (row.expiresAt <= now) deny("approval_expired");
      if (row.state !== "pending") deny(row.state === "declined" ? "approval_declined" : "approval_not_pending");
      if (hash(row.summary) !== row.summaryHash) deny("approval_card_mismatch");
      if (row.cardOpenedAt === null || row.cardOpenedAt === undefined) {
        const reserved = this.#db.prepare(`UPDATE approvals SET cardOpenedAt=?
          WHERE approvalId=? AND cardOpenedAt IS NULL AND state='pending' AND expiresAt>?`).run(now, approvalId, now);
        if (reserved.changes !== 1) deny("approval_card_open");
        this.#audit(row, "card_opened");
        return { approvalId, expiresAt: row.expiresAt, cardOpenedAt: now, replaced: false };
      }
      if (!replace) deny("approval_card_open");
      // 直前の世代と一致するときだけ差し替える（同時 --replace でも1枚だけ勝つ）。
      const replaced = this.#db.prepare("UPDATE approvals SET cardOpenedAt=? WHERE approvalId=? AND cardOpenedAt IS ?")
        .run(now, approvalId, row.cardOpenedAt);
      if (replaced.changes !== 1) deny("approval_card_open");
      this.#audit(row, "card_replaced");
      return { approvalId, expiresAt: row.expiresAt, cardOpenedAt: now, replaced: true, previousOpenedAt: row.cardOpenedAt };
    });
  }

  /** 期限切れを状態に反映する（pending のまま残さない）。 */
  sweepExpired(now = this.#now()) {
    return this.#db.prepare("UPDATE approvals SET state='expired',summary=NULL WHERE state IN ('pending','approved') AND expiresAt<=?").run(now).changes;
  }

  /** CLI の案内用。例外を投げずに発行状態だけを返す。 */
  cardState(approvalId) {
    this.sweepExpired();
    const row = this.#row(approvalId);
    if (!row) return null;
    return { approvalId: row.approvalId, state: row.state, expiresAt: row.expiresAt, cardOpenedAt: row.cardOpenedAt ?? null };
  }

  decide(approvalId, summaryHash, approved, openedAt = undefined) {
    try {
      return this.#transaction(() => {
        const card = this.card(approvalId, openedAt);
        if (card.summaryHash !== summaryHash) deny("approval_card_mismatch");
        if (typeof approved !== "boolean") deny("invalid_decision");
        const state = approved ? "approved" : "declined";
        this.#db.prepare("UPDATE approvals SET state=?,summary=NULL WHERE approvalId=?").run(state, approvalId);
        this.#audit(card, state);
        return { approvalId, state };
      });
    } catch (err) {
      const code = storeErrorCode(err);
      try { this.#audit(this.#row(approvalId) ?? { approvalId }, code); } catch (error) { deny(storeErrorCode(error)); }
      deny(code);
    }
  }

  #claim(input) {
    const desc = describe(input);
    if (!input.approvalId) {
      const prior = this.#latest(desc);
      if (!prior) deny("approval_required");
      this.#check(prior, desc, true);
      if (prior.usedAt === null) deny("approval_required");
      return this.#cache(prior);
    }
    const row = this.#row(input.approvalId);
    if (!row) deny("approval_unknown");
    this.#check(row, desc);
    if (row.usedAt !== null) deny("approval_used");
    const now = this.#now();
    if (row.expiresAt <= now) deny("approval_expired");
    if (row.state !== "approved") deny(row.state === "declined" ? "approval_declined" : "approval_not_approved");
    const counts = this.#db.prepare(`SELECT count(*) AS total,
      count(CASE WHEN clientId=? AND tool=? THEN 1 END) AS perClient,
      count(CASE WHEN grantId=? AND tool=? THEN 1 END) AS perGrant
      FROM approvals WHERE usedAt>?`).get(desc.clientId, desc.tool, desc.grantId, desc.tool, now-60000);
    if (counts.total >= this.#globalLimit || Math.max(counts.perClient, counts.perGrant) >= this.#subjectLimit) deny("write_rate_limited");
    const claimed = this.#db.prepare(`UPDATE approvals SET state='executing',usedAt=?,summary=NULL
      WHERE approvalId=? AND state='approved' AND expiresAt>? AND usedAt IS NULL`).run(now, row.approvalId, now);
    if (claimed.changes !== 1) deny("approval_used");
    this.#audit({ ...row, usedAt: now }, "execution_claimed");
    return { approvalId: row.approvalId, args: JSON.parse(desc.normalized) };
  }

  // Once the external action has run, reporting a generic storage error could
  // induce another submission. Keep the phase-specific code even if audit is down.
  #saveAfterDispatch(input, failureCode, save) {
    try {
      return this.#transaction(save);
    } catch (error) {
      try { this.recordDenial(input, failureCode); }
      catch (auditError) { throw new OperationError(failureCode, { cause: auditError }); }
      throw new OperationError(failureCode, { cause: error });
    }
  }

  async execute(input, action) {
    const claim = this.#guard(input, () => this.#claim(input));
    if (claim.cached) return claim.result;
    let result;
    try {
      result = await action(claim.args);
    } catch {
      this.#saveAfterDispatch(input, "operation_outcome_uncertain", () => {
        this.#db.prepare("UPDATE approvals SET state='uncertain' WHERE approvalId=?").run(claim.approvalId);
        this.#audit(this.#row(claim.approvalId), "execution_uncertain");
      });
      deny("operation_outcome_uncertain");
    }
    return this.#saveAfterDispatch(input, "operation_result_unrecorded", () => {
      const encoded = JSON.stringify(result);
      const saved = this.#db.prepare("UPDATE approvals SET state='completed',result=? WHERE approvalId=? AND state='executing'").run(encoded, claim.approvalId);
      if (saved.changes !== 1) deny("operation_result_unrecorded");
      this.#audit(this.#row(claim.approvalId), result?.isError ? "executed_error" : "executed");
      return JSON.parse(encoded);
    });
  }
}
