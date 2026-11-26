import { mkdir, readdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

const ENDED = new Set(["completed", "failed", "interrupted", "cancelled"]);

/**
 * Async job layer.
 *
 * ChatGPT tool calls must answer quickly, while an agent turn can run for
 * minutes. Every message the bridge sends becomes a job: the tool returns at
 * once with an id, and later calls poll the job. Jobs are persisted as one
 * small JSON file each, so a bridge restart neither loses nor re-runs work.
 */
export class JobStore {
  #dir;
  #jobs = new Map();
  #automation;
  #logger;
  #db;
  #max = 2000;

  constructor({ dataDir, automation, logger, db }) {
    this.#dir = join(dataDir, "jobs");
    this.#automation = automation;
    this.#logger = logger;
    this.#db = db;
  }

  async init() {
    await mkdir(this.#dir, { recursive: true, mode: 0o700 });
    let files = [];
    try {
      files = (await readdir(this.#dir)).filter((name) => name.endsWith(".json"));
    } catch {
      files = [];
    }
    const loaded = [];
    for (const name of files) {
      try {
        const job = JSON.parse(await readFile(join(this.#dir, name), "utf8"));
        if (job?.id) loaded.push(job);
      } catch {
        // A half-written file is ignored; the next poll recreates nothing.
      }
    }
    loaded.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
    for (const job of loaded.slice(-this.#max)) this.#jobs.set(job.id, job);
    return this.#jobs.size;
  }

  get size() {
    return this.#jobs.size;
  }

  findByIdempotencyKey(key, owner) {
    if (!key) return null;
    for (const job of this.#jobs.values()) if (job.idempotencyKey === key && belongsToGrant(job, owner)) return job;
    return null;
  }

  get(id) {
    return this.#jobs.get(id) ?? null;
  }

  list({ agentId = null, status = null, limit = 20, accepts = null } = {}) {
    let jobs = [...this.#jobs.values()];
    if (accepts) jobs = jobs.filter(accepts);
    if (agentId) jobs = jobs.filter((job) => job.agentId === agentId);
    if (status) jobs = jobs.filter((job) => job.status === status);
    return jobs.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, limit);
  }

  async create({ agentId, kind, title, prompt, idempotencyKey = null, owner }) {
    if (!owner?.clientId || !owner.grantId) throw new Error("Authenticated grant required.");
    const now = new Date().toISOString();
    const job = {
      id: `job_${randomUUID()}`,
      kind,
      ownerClientId: owner.clientId,
      ownerGrantId: owner.grantId,
      agentId,
      title: title || prompt.slice(0, 80),
      prompt,
      idempotencyKey,
      status: "created",
      deliveryId: null,
      messageId: null,
      turnId: null,
      answer: null,
      error: null,
      attempts: 0,
      createdAt: now,
      updatedAt: now,
      lastPollAt: null,
      events: [{ at: now, status: "created", detail: "Bridge queued the job." }],
    };
    await this.save(job);
    return job;
  }

  async save(job) {
    job.updatedAt = new Date().toISOString();
    this.#jobs.set(job.id, job);
    const file = join(this.#dir, `${job.id}.json`);
    const tmp = `${file}.tmp`;
    await writeFile(tmp, JSON.stringify(job, null, 2), { mode: 0o600 });
    await rename(tmp, file);
    // Keep the in-memory map bounded; old files stay on disk.
    if (this.#jobs.size > this.#max) {
      const oldest = [...this.#jobs.values()].sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)))[0];
      if (oldest) this.#jobs.delete(oldest.id);
    }
    return job;
  }

  note(job, status, detail) {
    job.events = [...(job.events ?? []), { at: new Date().toISOString(), status, detail: String(detail).slice(0, 500) }].slice(-100);
  }

  /**
   * Sends the job's prompt to OpenBot. A repeat call for an already sent job
   * returns the stored state, so a retried HTTP request is harmless.
   */
  async dispatch(job) {
    if (job.deliveryId) return job;
    const receipt = await this.#automation.sendMessage(job.agentId, job.prompt, job.id);
    const delivery = Array.isArray(receipt?.deliveries)
      ? receipt.deliveries.find((item) => item.recipientAgentId === job.agentId) ?? null
      : null;
    if (!delivery?.id) throw new Error("OpenBot returned no delivery for the requested agent.");
    job.messageId = receipt?.messageId ?? null;
    job.deliveryId = delivery?.id ?? null;
    job.status = delivery?.status === "running" ? "running" : "queued";
    job.attempts += 1;
    this.note(job, job.status, "OpenBot accepted the message.");
    return this.save(job);
  }

  /** Polls OpenBot once (at most every second) and folds the result into the job. */
  async refresh(job, { force = false } = {}) {
    if (!job.deliveryId) return job;
    if (!force && job.lastPollAt && Date.now() - Date.parse(job.lastPollAt) < 1000) return job;
    job.lastPollAt = new Date().toISOString();
    try {
      const delivery = await this.#automation.delivery(job.agentId, job.deliveryId);
      if (delivery) {
        job.turnId = delivery.turnId ?? job.turnId;
        job.error = delivery.error ?? null;
        if (delivery.answer) job.answer = delivery.answer;
        if (delivery.status !== job.status) {
          this.note(job, delivery.status, `OpenBot reports the delivery as ${delivery.status}.`);
          job.status = delivery.status;
        }
        if (!ENDED.has(job.status) && delivery.status === "running") {
          const pending = await this.#automation.pending(job.agentId).catch(() => null);
          const waiting = pending ? pending.prompts.length + pending.approvals.length + pending.browserTakeovers.length : 0;
          if (waiting > 0 && job.status !== "needs_person") {
            job.status = "needs_person";
            this.note(job, "needs_person", "The agent asked a question or needs approval inside OpenBot.");
          } else if (waiting === 0 && job.status === "needs_person") {
            job.status = "running";
            this.note(job, "running", "OpenBot has no pending question any more.");
          }
        }
      }
    } catch (error) {
      this.note(job, job.status, `Poll failed: ${error instanceof Error ? error.message : String(error)}`);
      this.#logger?.warn("Job poll failed", { job: job.id, error: error instanceof Error ? error.message : String(error) });
    }
    if (job.turnId && !job.answer && this.#db) {
      try {
        const turn = this.#db.turn(job.turnId);
        if (turn && this.#db.thread(turn.threadId)?.agentId === job.agentId && turn.status === "completed" && !ENDED.has(job.status)) {
          job.status = "completed";
          this.note(job, "completed", "OpenBot finished the turn.");
        }
      } catch {
        // The database is optional for progress; the automation API is authoritative.
      }
    }
    return this.save(job);
  }

  /** Waits up to `seconds` for the job to end. Kept short to fit MCP timeouts. */
  async waitFor(job, seconds) {
    const deadline = Date.now() + Math.max(0, seconds) * 1000;
    let current = await this.refresh(job, { force: true });
    while (!ENDED.has(current.status) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(2000, Math.max(200, deadline - Date.now()))));
      current = await this.refresh(current, { force: true });
    }
    return current;
  }

  async cancel(job, reason = "Cancelled from ChatGPT.") {
    if (ENDED.has(job.status)) return job;
    job.status = "cancelled";
    this.note(job, "cancelled", reason);
    return this.save(job);
  }
}

export function isEnded(status) {
  return ENDED.has(status);
}

export function belongsToGrant(job, owner) {
  return Boolean(owner?.clientId && owner?.grantId &&
    job?.ownerClientId === owner.clientId && job?.ownerGrantId === owner.grantId);
}
