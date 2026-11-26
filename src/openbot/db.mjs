import { DatabaseSync } from "node:sqlite";
import { existsSync } from "node:fs";

/**
 * Read-only view of OpenBot's projection database. The bridge never writes
 * here: every change goes through OpenBot's own automation API, so the app's
 * state machine stays the only writer.
 */
export class OpenBotDb {
  #db = null;
  #path;

  constructor(path) {
    this.#path = path;
  }

  get path() {
    return this.#path;
  }

  get available() {
    return existsSync(this.#path);
  }

  #open() {
    if (this.#db) return this.#db;
    if (!this.available) throw new Error(`OpenBot database not found at ${this.#path}`);
    this.#db = new DatabaseSync(this.#path, { readOnly: true });
    this.#db.exec("PRAGMA busy_timeout = 3000");
    return this.#db;
  }

  close() {
    try {
      this.#db?.close();
    } catch {
      // ignore
    }
    this.#db = null;
  }

  #all(sql, params = []) {
    return this.#open().prepare(sql).all(...params);
  }

  #get(sql, params = []) {
    return this.#open().prepare(sql).get(...params);
  }

  listAgents() {
    const rows = this.#all(
      `SELECT agent_id, thread_id, model, updated_at, sort_order, agent_json
         FROM projection_agents ORDER BY sort_order`,
    );
    return rows.map((row) => {
      const agent = safeJson(row.agent_json) || {};
      return {
        id: row.agent_id,
        name: agent.name ?? row.agent_id,
        title: agent.title ?? "",
        description: agent.description ?? "",
        provider: agent.provider ?? null,
        model: agent.model ?? row.model ?? null,
        reasoningEffort: agent.reasoningEffort ?? null,
        access: agent.access ?? null,
        computerUse: agent.computerUse ?? null,
        workspacePath: agent.workspacePath ?? null,
        threadId: agent.threadId ?? row.thread_id ?? null,
        updatedAt: row.updated_at ?? agent.updatedAt ?? null,
        sortOrder: row.sort_order,
      };
    });
  }

  agent(agentId) {
    return this.listAgents().find((agent) => agent.id === agentId) ?? null;
  }

  listThreads(agentId = null) {
    const rows = agentId
      ? this.#all(
          `SELECT thread_id, agent_id, title, active_turn_id, created_at, updated_at
             FROM projection_threads WHERE agent_id = ? ORDER BY updated_at DESC`,
          [agentId],
        )
      : this.#all(
          `SELECT thread_id, agent_id, title, active_turn_id, created_at, updated_at
             FROM projection_threads ORDER BY updated_at DESC LIMIT 100`,
        );
    return rows.map(normalizeThread);
  }

  thread(threadId) {
    const row = this.#get(
      `SELECT thread_id, agent_id, title, active_turn_id, created_at, updated_at
         FROM projection_threads WHERE thread_id = ?`,
      [threadId],
    );
    return row ? normalizeThread(row) : null;
  }

  /** Messages of one thread, oldest first. `beforeOrdinal` pages backwards. */
  messages(threadId, { limit = 40, beforeOrdinal = null } = {}) {
    const rows = beforeOrdinal === null
      ? this.#all(
          `SELECT message_id, turn_id, author, status, item_type, created_at, ordinal, message_json
             FROM projection_thread_messages WHERE thread_id = ?
             ORDER BY ordinal DESC LIMIT ?`,
          [threadId, limit],
        )
      : this.#all(
          `SELECT message_id, turn_id, author, status, item_type, created_at, ordinal, message_json
             FROM projection_thread_messages WHERE thread_id = ? AND ordinal < ?
             ORDER BY ordinal DESC LIMIT ?`,
          [threadId, beforeOrdinal, limit],
        );
    return rows
      .map((row) => {
        const message = safeJson(row.message_json) || {};
        return {
          messageId: row.message_id,
          turnId: row.turn_id ?? null,
          author: row.author,
          status: row.status,
          ordinal: row.ordinal,
          createdAt: row.created_at,
          text: typeof message.text === "string" ? message.text : null,
          attachments: Array.isArray(message.attachments) ? message.attachments.length : 0,
        };
      })
      .reverse();
  }

  /** Tool calls, plan updates and other turn activities: the agent's execution log. */
  activities({ turnId = null, threadId = null, since = null, limit = 100 } = {}) {
    const filters = [];
    const params = [];
    if (turnId) {
      filters.push("turn_id = ?");
      params.push(turnId);
    }
    if (threadId) {
      filters.push("thread_id = ?");
      params.push(threadId);
    }
    if (since) {
      filters.push("created_at >= ?");
      params.push(since);
    }
    if (filters.length === 0) return [];
    params.push(limit);
    const rows = this.#all(
      `SELECT activity_id, thread_id, turn_id, activity_type, payload_json, created_at
         FROM projection_thread_activities WHERE ${filters.join(" AND ")}
         ORDER BY created_at DESC LIMIT ?`,
      params,
    );
    return rows.map((row) => ({
      activityId: row.activity_id,
      threadId: row.thread_id,
      turnId: row.turn_id ?? null,
      type: row.activity_type,
      createdAt: row.created_at,
      payload: safeJson(row.payload_json),
    }));
  }

  delivery(deliveryId) {
    const row = this.#get(
      `SELECT delivery_id, message_id, recipient_agent_id, status, turn_id, error, created_at
         FROM projection_deliveries WHERE delivery_id = ?`,
      [deliveryId],
    );
    return row ? normalizeDelivery(row) : null;
  }

  deliveries(agentId, limit = 20) {
    const rows = this.#all(
      `SELECT delivery_id, message_id, recipient_agent_id, status, turn_id, error, created_at
         FROM projection_deliveries WHERE recipient_agent_id = ?
         ORDER BY created_at DESC LIMIT ?`,
      [agentId, limit],
    );
    return rows.map(normalizeDelivery);
  }

  turn(turnId) {
    const row = this.#get(
      `SELECT turn_id, thread_id, status, started_at, completed_at FROM projection_turns WHERE turn_id = ?`,
      [turnId],
    );
    return row
      ? {
          turnId: row.turn_id,
          threadId: row.thread_id,
          status: row.status,
          startedAt: row.started_at,
          completedAt: row.completed_at ?? null,
        }
      : null;
  }

  routines(agentId) {
    return this.#all(
      `SELECT routine_id, name, active, timezone, updated_at FROM projection_agent_routines
        WHERE agent_id = ? ORDER BY name`,
      [agentId],
    ).map((row) => ({
      id: row.routine_id,
      name: row.name,
      active: row.active === 1,
      timezone: row.timezone,
      updatedAt: row.updated_at,
    }));
  }

  /** Files an agent produced or that were attached to its messages. */
  attachments({ agentId = null, limit = 30 } = {}) {
    const rows = agentId
      ? this.#all(
          `SELECT attachment_id, owner_kind, owner_id, name, path, metadata_json, created_at
             FROM projection_attachments
            WHERE owner_id = ? OR path LIKE ? ORDER BY created_at DESC LIMIT ?`,
          [agentId, `%/${agentId}/%`, limit],
        )
      : this.#all(
          `SELECT attachment_id, owner_kind, owner_id, name, path, metadata_json, created_at
             FROM projection_attachments ORDER BY created_at DESC LIMIT ?`,
          [limit],
        );
    return rows.map((row) => {
      const meta = safeJson(row.metadata_json) || {};
      return {
        id: row.attachment_id,
        name: row.name,
        path: row.path,
        kind: meta.kind ?? row.owner_kind,
        mimeType: meta.mimeType ?? null,
        size: typeof meta.size === "number" ? meta.size : null,
        createdAt: row.created_at,
      };
    });
  }

  /** Simple text search inside one agent's thread messages. */
  searchMessages(agentId, query, limit = 20) {
    const rows = this.#all(
      `SELECT m.thread_id, m.message_id, m.author, m.created_at, m.message_json
         FROM projection_thread_messages m
         JOIN projection_threads t ON t.thread_id = m.thread_id
        WHERE t.agent_id = ? AND m.message_json LIKE ?
        ORDER BY m.created_at DESC LIMIT ?`,
      [agentId, `%${query}%`, limit],
    );
    return rows.map((row) => {
      const message = safeJson(row.message_json) || {};
      return {
        threadId: row.thread_id,
        messageId: row.message_id,
        author: row.author,
        createdAt: row.created_at,
        text: typeof message.text === "string" ? message.text.slice(0, 600) : null,
      };
    });
  }
}

function normalizeThread(row) {
  return {
    threadId: row.thread_id,
    agentId: row.agent_id,
    title: row.title,
    activeTurnId: row.active_turn_id ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function normalizeDelivery(row) {
  return {
    deliveryId: row.delivery_id,
    messageId: row.message_id,
    agentId: row.recipient_agent_id,
    status: row.status,
    turnId: row.turn_id ?? null,
    error: row.error ?? null,
    createdAt: row.created_at,
  };
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
