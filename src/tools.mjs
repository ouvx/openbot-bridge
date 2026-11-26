import { z } from "zod";
import { readArtifact, listArtifacts } from "./artifacts.mjs";
import { systemSnapshot } from "./openbot/system.mjs";
import { isAgentAllowed } from "./config.mjs";
import { OperationError, canonicalJSON } from "./operations.mjs";
import { isEnded, belongsToGrant } from "./jobs.mjs";
import { maskSecrets, truncate } from "./log.mjs";

const MAX_TEXT = 8000;
const ENDED_STATUSES = new Set(["completed", "failed", "interrupted", "cancelled"]);

/**
 * Registers every bridge tool on the MCP server.
 *
 * Agent reads are scoped to the authenticated grant and local allowlist.
 * Files must be present in a dedicated agent export directory.
 */
export function registerTools(server, ctx) {
  const { config, db, automation, jobs, oauth, audit, logger } = ctx;

  const text = (value) => ({ type: "text", text: truncate(value, config.limits.maxToolResultChars) });
  const reply = (structured, summary) => ({
    structuredContent: structured,
    content: [text(summary ?? JSON.stringify(structured, null, 2))],
  });
  const fail = (message, structured = {}) => ({
    isError: true,
    structuredContent: { error: message, ...structured },
    content: [text(message)],
  });

  const withScope = (scope, name, handler) => async (args, extra) => {
    const auth = ctx.currentAuth?.();
    if (scope !== "openbot.read") return guardedWrite(scope, name, args, handler, extra, auth);
    if (!oauth.hasScope(auth, scope)) {
      return fail(`This connection is missing the ${scope} scope. Reconnect the plugin in ChatGPT to grant it.`);
    }
    audit({
      tool: name,
      scope,
      clientId: auth?.clientId ?? null,
      caller: extra?.sessionId ?? null,
    });
    try {
      return await handler(args, extra);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.warn("Tool failed", { tool: name, error: message });
      return fail(message);
    }
  };

  const agentAllowed = id => {
    const auth = ctx.currentAuth?.();
    return Boolean(auth?.ok && auth.clientId && auth.grantId && Array.isArray(auth.allowedAgentIds) &&
      auth.allowedAgentIds.includes(id) && isAgentAllowed(config, id));
  };
  const ownsJob = job => job && agentAllowed(job.agentId) && belongsToGrant(job, ctx.currentAuth());
  const ownedJob = id => {
    const job = jobs.get(id);
    if (!ownsJob(job)) throw new Error("Task unavailable.");
    return job;
  };

  const resolveAgent = (reference) => {
    const agents = db.listAgents().filter(agent => agentAllowed(agent.id));
    if (!reference) throw new Error(`agent_id is required. Known agents: ${agents.map((a) => `${a.name} (${a.id})`).join(", ")}`);
    const byId = agents.find((agent) => agent.id === reference);
    if (byId) return byId;
    const wanted = reference.trim().toLowerCase();
    const named = agents.filter((agent) => agent.name.trim().toLowerCase() === wanted);
    if (named.length === 1) return named[0];
    if (named.length > 1) throw new Error(`"${reference}" matches ${named.length} agents. Pass the agent id instead.`);
    const partial = agents.filter((agent) => agent.name.toLowerCase().includes(wanted));
    if (partial.length === 1) return partial[0];
    throw new Error(`No agent matches "${reference}". Known agents: ${agents.map((a) => a.name).join(", ")}`);
  };

  const requireAllowed = (agent) => {
    if (!agentAllowed(agent.id)) throw new Error(`The bridge is not allowed to drive ${agent.name}.`);
    return agent;
  };

  const agentStatus = (agent) => {
    const threads = db.listThreads(agent.id);
    const active = threads.find((thread) => thread.activeTurnId);
    const recent = db.deliveries(agent.id, 10);
    const queued = recent.filter((delivery) => delivery.status === "queued").length;
    const running = recent.filter((delivery) => delivery.status === "running").length;
    return {
      status: active || running > 0 ? "working" : queued > 0 ? "queued" : "ready",
      activeTurnId: active?.activeTurnId ?? null,
      queuedDeliveries: queued,
      runningDeliveries: running,
      lastDeliveryAt: recent[0]?.createdAt ?? null,
      sessionCount: threads.length,
    };
  };

  const jobsForAgent = (agentId) => jobs.list({ agentId, limit: 5, accepts: ownsJob });

  // ---------------------------------------------------------------- reads ---

  server.registerTool(
    "openbot_health",
    {
      title: "OpenBot connection health",
      description:
        "Show the bridge mode and local database availability.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "openbot_health", async () => {
      return reply({
        bridge: { readOnly: config.readOnly, extendedTools: config.extendedTools },
        openbot: { databaseAvailable: db.available },
      });
    }),
  );

  server.registerTool(
    "list_agents",
    {
      title: "List OpenBot agents",
      description:
        "List only explicitly allowed agents, with its runtime/provider, model, reasoning effort, permission level and live status. Agents are discovered from OpenBot itself, so new agents appear without a bridge update. Use this before naming an agent in another tool.",
      inputSchema: {
        include_offline: z.boolean().optional().describe("Compatibility option. The configured allowlist always applies."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "list_agents", async () => {
      const visible = db.listAgents().filter(agent => agentAllowed(agent.id)).map((agent) => {
        const status = agentStatus(agent);
        return {
          agent_id: agent.id,
          name: agent.name,
          title: agent.title,
          provider: agent.provider,
          model: agent.model,
          reasoning_effort: agent.reasoningEffort,
          access: agent.access,
          computer_use: agent.computerUse,
          status: status.status,
          allowed: true,
          running_tasks: jobsForAgent(agent.id).filter((job) => !isEnded(job.status)).length,
          last_activity_at: status.lastDeliveryAt,
        };
      });
      const structured = { count: visible.length, agents: visible };
      const summary = visible
        .map((agent) => `${agent.name} (${agent.agent_id}) — ${agent.provider}/${agent.model}, ${agent.status}`)
        .join("\n");
      return reply(structured, summary || "No agents are visible to the bridge.");
    }),
  );

  if (!config.extendedTools) return;

  server.registerTool(
    "get_agent",
    {
      title: "Get one agent",
      description:
        "Read one agent's role description, runtime, model, permission level, routines, current session and recent activity. Use it to explain what an agent can do or to pick the right agent for a task.",
      inputSchema: {
        agent_id: z.string().describe("Agent id (or an exact agent name)."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_agent", async ({ agent_id }) => {
      const agent = resolveAgent(agent_id);
      const status = agentStatus(agent);
      const threads = db.listThreads(agent.id).slice(0, 5);
      const structured = {
        agent: {
          agent_id: agent.id,
          name: agent.name,
          title: agent.title,
          description: truncate(agent.description, MAX_TEXT),
          provider: agent.provider,
          model: agent.model,
          reasoning_effort: agent.reasoningEffort,
          access: agent.access,
          computer_use: agent.computerUse,
          allowed_by_bridge: agentAllowed(agent.id),
          updated_at: agent.updatedAt,
        },
        status,
        routines: db.routines(agent.id),
        sessions: threads.map((thread) => ({
          session_id: thread.threadId,
          title: thread.title,
          active: Boolean(thread.activeTurnId),
          updated_at: thread.updatedAt,
        })),
        open_tasks: jobsForAgent(agent.id).map(jobSummary),
      };
      return reply(structured, `${agent.name}: ${agent.provider}/${agent.model}, ${status.status}. ${agent.title}`);
    }),
  );

  server.registerTool(
    "list_sessions",
    {
      title: "List OpenBot sessions",
      description:
        "List an agent's chat sessions (threads) newest first, including which one is active. Continue an existing session by chatting with the same agent; OpenBot always continues its current thread.",
      inputSchema: {
        agent_id: z.string().describe("Agent id or exact name."),
        limit: z.number().int().min(1).max(50).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "list_sessions", async ({ agent_id, limit }) => {
      const agent = resolveAgent(agent_id);
      const threads = db.listThreads(agent.id).slice(0, limit ?? 10);
      return reply(
        {
          agent_id: agent.id,
          current_session_id: threads.some(thread => thread.threadId === agent.threadId) ? agent.threadId : null,
          sessions: threads.map((thread) => ({
            session_id: thread.threadId,
            title: thread.title,
            active_turn_id: thread.activeTurnId,
            created_at: thread.createdAt,
            updated_at: thread.updatedAt,
          })),
        },
        threads.map((thread) => `${thread.threadId} — ${thread.title} (${thread.updatedAt})`).join("\n") || "No sessions yet.",
      );
    }),
  );

  server.registerTool(
    "get_conversation",
    {
      title: "Read a conversation",
      description:
        "Read recent messages of one OpenBot session. Pass session_id, or only agent_id to read the agent's current session. Use it to pick up context before delegating work or to quote an agent's last answer.",
      inputSchema: {
        agent_id: z.string().describe("Agent id or exact name."),
        session_id: z.string().optional().describe("Session (thread) id; defaults to the agent's current session."),
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_conversation", async ({ agent_id, session_id, limit }) => {
      const agent = resolveAgent(agent_id);
      const threadId = session_id ?? agent.threadId ?? db.listThreads(agent.id)[0]?.threadId;
      if (!threadId) return fail(`${agent.name} has no session yet.`);
      if (db.thread(threadId)?.agentId !== agent.id) return fail("Session unavailable for this agent.");
      const messages = db.messages(threadId, { agentId: agent.id, limit: limit ?? 30 });
      return reply(
        {
          agent_id: agent.id,
          session_id: threadId,
          messages: messages.map((message) => ({
            message_id: message.messageId,
            author: message.author,
            created_at: message.createdAt,
            text: truncate(message.text ?? "", MAX_TEXT),
          })),
        },
        messages
          .map((message) => `[${message.createdAt}] ${message.author === "user" ? "ユーザー" : agent.name}: ${truncate(message.text ?? "", 400)}`)
          .join("\n\n") || "This session has no messages yet.",
      );
    }),
  );

  server.registerTool(
    "list_tasks",
    {
      title: "List tasks",
      description:
        "List the asynchronous tasks this bridge started (newest first) and OpenBot's recent deliveries for an agent. Use it to see what is running, what finished and what needs a person inside OpenBot.",
      inputSchema: {
        agent_id: z.string().optional().describe("Filter by agent id or exact name."),
        status: z
          .enum(["queued", "running", "needs_person", "completed", "failed", "cancelled"])
          .optional()
          .describe("Filter by status."),
        limit: z.number().int().min(1).max(50).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "list_tasks", async ({ agent_id, status, limit }) => {
      const agent = agent_id ? resolveAgent(agent_id) : null;
      const tasks = jobs.list({ agentId: agent?.id ?? null, status, limit: limit ?? 20, accepts: ownsJob });
      const refreshed = await Promise.all(tasks.slice(0, 10).map((job) => jobs.refresh(job).catch(() => job)));
      const structured = {
        agent_id: agent?.id ?? null,
        tasks: refreshed.map((job) => ({ ...jobSummary(job), agent_id: job.agentId })),
        recent_deliveries: agent ? db.deliveries(agent.id, limit ?? 10).filter(d => tasks.some(j => j.deliveryId === d.deliveryId)) : [],
      };
      return reply(
        structured,
        structured.tasks.map((task) => `${task.task_id} — ${task.status} — ${task.title}`).join("\n") || "No tasks yet.",
      );
    }),
  );

  server.registerTool(
    "get_task",
    {
      title: "Get task status and result",
      description:
        "Read one task: status, OpenBot delivery state, the agent's final answer when it finished, error text, and whether OpenBot is waiting for a person. Set wait_seconds (1–25) to poll briefly so short tasks finish inside the call.",
      inputSchema: {
        task_id: z.string().describe("Task id returned by send_message or delegate_task."),
        wait_seconds: z.number().min(0).max(25).optional(),
        include_answer: z.boolean().optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_task", async ({ task_id, wait_seconds, include_answer }) => {
      let job = ownedJob(task_id);
      job = wait_seconds ? await jobs.waitFor(job, wait_seconds) : await jobs.refresh(job, { force: true });
      const agent = db.agent(job.agentId);
      const threadId = job.turnId && db.turn(job.turnId)?.threadId;
      const logs = threadId && db.thread(threadId)?.agentId === job.agentId
        ? db.activities({ agentId: job.agentId, turnId: job.turnId, threadId, limit: 30 }).reverse() : [];
      const structured = {
        ...jobSummary(job),
        agent_name: agent?.name ?? null,
        delivery_id: job.deliveryId,
        turn_id: job.turnId,
        error: job.error,
        ended: isEnded(job.status),
        answer: include_answer === false ? undefined : truncate(job.answer ?? "", MAX_TEXT),
        needs_person: job.status === "needs_person",
        steps: logs.map((entry) => ({ at: entry.createdAt, type: entry.type })),
      };
      const headline = `${job.title} — ${job.status}${job.error ? ` (${job.error})` : ""}`;
      const body = job.answer ? `\n\n${truncate(job.answer, MAX_TEXT)}` : "";
      const hint =
        job.status === "needs_person"
          ? "\n\nOpenBot is waiting for a person: a question or approval is pending inside the OpenBot app."
          : "";
      return reply(structured, `${headline}${body}${hint}`);
    }),
  );

  server.registerTool(
    "get_task_logs",
    {
      title: "Get task logs",
      description:
        "Read the execution log of a task: tool calls, plan updates and other turn activities OpenBot recorded, oldest last. Use it to see what an agent actually did or where it stalled.",
      inputSchema: {
        task_id: z.string().optional(),
        turn_id: z.string().optional(),
        session_id: z.string().optional(),
        limit: z.number().int().min(1).max(200).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_task_logs", async ({ task_id, turn_id, session_id, limit }) => {
      let turnId = turn_id ?? null;
      let threadId = session_id ?? null;
      if (task_id) {
        const job = ownedJob(task_id);
        if (!job.turnId || (turnId && turnId !== job.turnId)) return fail("Turn unavailable.");
        turnId = job.turnId;
        const ownerThread = db.turn(turnId)?.threadId;
        if (!ownerThread || db.thread(ownerThread)?.agentId !== job.agentId) return fail("Turn unavailable.");
      }
      if (!turnId && !threadId) return fail("Give task_id, turn_id or session_id.");
      if (turnId) {
        const turnThread = db.turn(turnId)?.threadId;
        if (!turnThread || (threadId && threadId !== turnThread)) return fail("Turn unavailable.");
        threadId = turnThread;
      }
      const agentId = db.thread(threadId)?.agentId;
      if (!agentAllowed(agentId)) return fail("Session unavailable.");
      const activities = db.activities({ agentId, turnId, threadId, limit: limit ?? 80 }).reverse();
      return reply(
        { turn_id: turnId, session_id: threadId, count: activities.length, activities },
        activities.map((entry) => `[${entry.createdAt}] ${entry.type} ${truncate(JSON.stringify(entry.payload ?? {}), 300)}`).join("\n") ||
          "No activity recorded yet.",
      );
    }),
  );

  server.registerTool(
    "list_artifacts",
    {
      title: "List artifacts",
      description:
        "List eligible text files in each permitted agent's export directory. Other workspace and attachment files are private.",
      inputSchema: {
        agent_id: z.string().optional(),
        include_workspace: z.boolean().optional(),
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "list_artifacts", async ({ agent_id, limit }) => {
      const agent = agent_id ? resolveAgent(agent_id) : null;
      const sources = agent ? [agent] : db.listAgents().filter(item => agentAllowed(item.id));
      const attachments = [];
      const count = limit ?? 30;
      for (const item of sources) {
        if (attachments.length >= count) break;
        attachments.push(...await listArtifacts(config.sharedDir, item.id, count - attachments.length, config.limits.artifactBytes));
      }
      return reply({ agent_id: agent?.id ?? null, attachments, workspace_files: [] });
    }),
  );

  server.registerTool(
    "read_artifact",
    {
      title: "Read an artifact",
      description:
        "Read an exported text artifact belonging to an agent permitted by this grant.",
      inputSchema: {
        agent_id: z.string().describe("Agent that owns the workspace."),
        path: z.string().describe("Path inside the agent export directory."),
        max_bytes: z.number().int().min(1024).max(524288).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "read_artifact", async ({ agent_id, path, max_bytes }) => {
      const agent = resolveAgent(agent_id);
      const limit = Math.min(max_bytes ?? config.limits.artifactBytes, config.limits.artifactBytes);
      const file = await readArtifact(config.sharedDir, agent.id, path, limit);
      const body = truncate(maskSecrets(file.text), config.limits.maxToolResultChars);
      return reply({ ...file, text: body }, body);
    }),
  );

  server.registerTool(
    "get_git_diff",
    {
      title: "Get a workspace git diff",
      description:
        "Workspace Git access is disabled. An agent can export a reviewed patch for read_artifact.",
      inputSchema: {
        agent_id: z.string().describe("Agent whose workspace is inspected."),
        mode: z.enum(["status", "diff", "stat"]).optional(),
        max_bytes: z.number().int().min(1024).max(524288).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_git_diff", async ({ agent_id }) => {
      resolveAgent(agent_id);
      return fail("Workspace diffs are private. Read a published diff from the agent export directory.");
    }),
  );

  server.registerTool(
    "get_server_resources",
    {
      title: "Get server resources",
      description:
        "Read this computer's CPU load, memory, disk space, uptime, and whether the OpenBot app is running. Use it when the user asks about server health or when work seems slow.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_server_resources", async () => {
      const snapshot = await systemSnapshot();
      const gb = (bytes) => Math.round((bytes / 1e9) * 10) / 10;
      const summary = [
        `CPU ${snapshot.cpu.percent ?? "?"}% (${snapshot.cpu.cores} cores, load ${snapshot.cpu.loadAvg.join(" / ")})`,
        snapshot.memory ? `RAM ${snapshot.memory.usedPercent}% used (${gb(snapshot.memory.usedBytes)} / ${gb(snapshot.memory.totalBytes)} GB)` : "RAM unknown",
        snapshot.disk.home ? `Disk ${gb(snapshot.disk.home.freeBytes)} GB free of ${gb(snapshot.disk.home.totalBytes)} GB` : "Disk unknown",
        `Uptime ${Math.floor(snapshot.uptimeSeconds / 3600)} h`,
        `OpenBot app: ${snapshot.openbotProcess.running ? `running (pid ${snapshot.openbotProcess.pid})` : "not running"}`,
      ].join("\n");
      return reply(snapshot, summary);
    }),
  );

  server.registerTool(
    "search_conversations",
    {
      title: "Search an agent's conversations",
      description:
        "Search the stored messages of one agent for a word or phrase and return the matching messages with their session ids. Use it to recall earlier work or a decision without reading whole sessions.",
      inputSchema: {
        agent_id: z.string().describe("Agent id or exact name."),
        query: z.string().min(2).describe("Word or phrase to search for."),
        limit: z.number().int().min(1).max(50).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "search_conversations", async ({ agent_id, query, limit }) => {
      const agent = resolveAgent(agent_id);
      const matches = db.searchMessages(agent.id, query, limit ?? 20);
      return reply(
        { agent_id: agent.id, query, matches: matches.map((match) => ({ ...match, text: truncate(match.text ?? "", 800) })) },
        matches.map((match) => `[${match.createdAt}] ${match.threadId}\n${truncate(match.text ?? "", 400)}`).join("\n\n") || "No matches.",
      );
    }),
  );

  // --------------------------------------------------------------- writes ---

  const approvalFields = {
    approval_id: z.string().uuid().optional().describe("Single-use ID after the operator approves the local card. Omit to request a card or retrieve a completed result."),
    idempotency_key: z.string().trim().min(1).max(120).optional().describe("Stable key for the same operation. Change it only for an intentionally new action."),
  };

  // The same entry point guards all write/admin tools, including direct SDK calls.
  async function guardedWrite(scope, tool, raw, handler, extra, auth) {
    const { approval_id: approvalId, idempotency_key: idempotencyKey, ...args } = raw;
    const input = { auth, tool, args, targets: [], approvalId, idempotencyKey };
    const refuse = (code, message) => {
      ctx.operations?.recordDenial(input, code);
      if (!ctx.operations) audit({ event: code, tool, clientId: auth?.clientId, grantId: auth?.grantId });
      return fail(message, { code });
    };
    try {
      if (!oauth.hasScope(auth, scope)) return refuse("insufficient_scope", "The required scope is missing.");
      if (config.readOnly) return refuse("read_only", "The bridge runs in read-only mode.");
      if (!ctx.operations) return refuse("operation_store_unavailable", "The approval store is unavailable.");
      const effective = JSON.parse(canonicalJSON(args));
      try {
        if (Object.hasOwn(effective, "agent_id")) {
          // Bind a name to an immutable ID before preparing or looking up a result.
          effective.agent_id = resolveAgent(effective.agent_id).id;
          input.targets = [effective.agent_id];
        } else {
          input.targets = [ownedJob(effective.task_id).agentId];
        }
      } catch {
        return refuse("target_denied", "The target is unavailable for this grant.");
      }
      input.args = effective;
      if (["message", "task", "feedback"].some(key => Object.hasOwn(effective, key) && !effective[key])) {
        return refuse("invalid_arguments", "An empty instruction cannot be approved.");
      }
      if (!approvalId) {
        const prepared = ctx.operations.prepare(input);
        if (prepared.cached) return prepared.result;
        return fail("Local human approval required. Review the card before repeating this call.", {
          code: "approval_required", approval_id: prepared.approvalId, expires_at: new Date(prepared.expiresAt).toISOString(),
        });
      }
      return await ctx.operations.execute(input, normalized => handler(normalized, extra));
    } catch (error) {
      const code = error instanceof OperationError ? error.code : "operation_store_unavailable";
      logger.warn("Write refused or outcome unconfirmed", { tool, code, grantId: auth?.grantId });
      return fail(code, { code });
    }
  }

  // An approved ID must never be interpreted as a name during dispatch.
  const exactWriteAgent = id => {
    const agent = db.listAgents().find(candidate => candidate.id === id);
    if (!agent || !agentAllowed(id)) throw new Error("Approved target unavailable.");
    return agent;
  };

  const dispatch = async ({ agentId, kind, title, prompt }) => {
    const job = await jobs.create({ agentId, kind, title, prompt, owner: ctx.currentAuth() });
    try {
      return await jobs.dispatch(job);
    } catch (error) {
      job.status = "failed";
      job.error = error instanceof Error ? error.message : String(error);
      jobs.note(job, "failed", job.error);
      await jobs.save(job);
      throw error;
    }
  };

  server.registerTool(
    "send_message",
    {
      title: "Message an OpenBot agent",
      description:
        "Send a message to one OpenBot agent in its current session and return a task id at once. The agent works with its own runtime, model and tools; poll with get_task. Keep follow-ups to the same agent so its context continues.",
      inputSchema: {
        ...approvalFields,
        agent_id: z.string().describe("Agent id or exact name from list_agents."),
        message: z.string().min(1).describe("The text to send."),
        title: z.string().max(120).optional().describe("Short label for the task list."),
        wait_seconds: z.number().min(0).max(25).optional().describe("Poll briefly so quick replies can finish in this call."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.write", "send_message", async ({ agent_id, message, title, wait_seconds }) => {
      const agent = exactWriteAgent(agent_id);
      if (message.length > config.limits.maxMessageChars) return fail(`The message is longer than ${config.limits.maxMessageChars} characters.`);
      const job = await dispatch({
        agentId: agent.id,
        kind: "message",
        title,
        prompt: message,
      });
      const current = wait_seconds ? await jobs.waitFor(job, wait_seconds) : job;
      return reply(
        { ...jobSummary(current), agent_name: agent.name, answer: current.answer ? truncate(current.answer, MAX_TEXT) : undefined },
        `Sent to ${agent.name}. Task ${current.id} is ${current.status}.${current.answer ? `\n\n${truncate(current.answer, MAX_TEXT)}` : ""}`,
      );
    }),
  );

  server.registerTool(
    "delegate_task",
    {
      title: "Delegate a task to an agent",
      description:
        "Delegate a complete task to one agent. The bridge frames the request with the goal, context, constraints and the definition of done, then returns a task id immediately. Use send_message instead for short conversation, and send_feedback to correct a finished task.",
      inputSchema: {
        ...approvalFields,
        agent_id: z.string().describe("Agent id or exact name."),
        task: z.string().min(1).describe("What the agent must do."),
        context: z.string().optional().describe("Background the agent cannot see, such as the current ChatGPT discussion."),
        constraints: z.string().optional().describe("Limits: files to avoid, no network, no push, and so on."),
        definition_of_done: z.string().optional().describe("How the result will be judged."),
        title: z.string().max(120).optional(),
        wait_seconds: z.number().min(0).max(25).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.write", "delegate_task", async ({ agent_id, task, context, constraints, definition_of_done, title, wait_seconds }) => {
      const agent = exactWriteAgent(agent_id);
      const prompt = [
        "【ChatGPTからの依頼】",
        `目的: ${task}`,
        context ? `\n背景・文脈:\n${context}` : "",
        constraints ? `\n制約:\n${constraints}` : "",
        definition_of_done ? `\n完了条件:\n${definition_of_done}` : "",
        "\n進め方: まず短い作業計画を出し、そのまま実行してください。確認や判断が必要になったら、止まらずにOpenBot側で質問してください。終わったら、変更したファイル・確認したこと・未確認のことを短くまとめて返してください。",
      ]
        .filter(Boolean)
        .join("\n");
      if (prompt.length > config.limits.maxMessageChars) return fail(`The framed task is longer than ${config.limits.maxMessageChars} characters.`);
      const job = await dispatch({
        agentId: agent.id,
        kind: "task",
        title: title ?? task.slice(0, 80),
        prompt,
      });
      const current = wait_seconds ? await jobs.waitFor(job, wait_seconds) : job;
      return reply(
        { ...jobSummary(current), agent_name: agent.name, answer: current.answer ? truncate(current.answer, MAX_TEXT) : undefined },
        `Delegated to ${agent.name}: task ${current.id} is ${current.status}.`,
      );
    }),
  );

  server.registerTool(
    "send_feedback",
    {
      title: "Send a correction to a finished task",
      description:
        "Send review notes about a task back to the agent that did it. The agent keeps its session, so it can revise the same work. Pass task_id; the feedback is sent as a new task that references the original.",
      inputSchema: {
        ...approvalFields,
        task_id: z.string().describe("The task being corrected."),
        feedback: z.string().min(1).describe("What is wrong and what to change."),
        wait_seconds: z.number().min(0).max(25).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.write", "send_feedback", async ({ task_id, feedback, wait_seconds }) => {
      const original = ownedJob(task_id);
      const agent = requireAllowed(db.agent(original.agentId) ?? { id: original.agentId, name: original.agentId });
      const prompt = [
        `【前の作業への修正指示】対象: ${original.title} (${original.id})`,
        "",
        "修正点:",
        feedback,
        "",
        "前回の続きとして、同じセッションの文脈で直してください。直したこと・確認したこと・未確認のことを短く返してください。",
      ].join("\n");
      const job = await dispatch({ agentId: agent.id, kind: "feedback", title: `修正: ${original.title}`, prompt });
      const current = wait_seconds ? await jobs.waitFor(job, wait_seconds) : job;
      return reply(
        { ...jobSummary(current), agent_name: agent.name ?? null, original_task_id: original.id },
        `Feedback sent to ${agent.name ?? agent.id}: task ${current.id} is ${current.status}.`,
      );
    }),
  );

  server.registerTool(
    "cancel_task",
    {
      title: "Cancel a task",
      description:
        "Stop tracking a task and mark it cancelled. OpenBot cannot interrupt a turn that is already running from the automation API, so tell the user the agent may still finish its current step inside OpenBot.",
      inputSchema: {
        ...approvalFields,
        task_id: z.string(),
        reason: z.string().max(300).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    withScope("openbot.write", "cancel_task", async ({ task_id, reason }) => {
      const job = ownedJob(task_id);
      requireAllowed({ id: job.agentId, name: "this target" });
      const updated = await jobs.cancel(job, reason ?? "Cancelled from ChatGPT.");
      return reply(
        { ...jobSummary(updated), note: "OpenBot is not interrupted by this call; its current turn may still finish." },
        `Task ${task_id} is now ${updated.status}. The agent's running turn inside OpenBot is not interrupted.`,
      );
    }),
  );

  server.registerTool(
    "start_new_session",
    {
      title: "Start a new session with an agent",
      description:
        "Start a fresh chat with one agent so old context is not carried into a new request. The agent's instructions, model and files stay unchanged. This changes OpenBot state, so confirm with the user first.",
      inputSchema: {
        ...approvalFields,
        agent_id: z.string().describe("Agent id or exact name."),
        confirm: z.literal(true).describe("Must be true: this clears the agent's current conversation context."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    withScope("openbot.admin", "start_new_session", async ({ agent_id }) => {
      const agent = exactWriteAgent(agent_id);
      await automation.newChat(agent.id);
      return reply(
        { agent_id: agent.id, agent_name: agent.name, cleared: true },
        `${agent.name}: a new session has started. Its previous conversation is no longer in context.`,
      );
    }),
  );

  server.registerTool(
    "openbot_dashboard",
    {
      title: "Open the OpenBot dashboard",
      description:
        "Show the OpenBot dashboard inside ChatGPT: connection status, agents with runtime and model, sessions, tasks, resources and recent logs. Use it when the user wants an overview rather than a single answer.",
      inputSchema: {
        agent_id: z.string().optional().describe("Focus one agent."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      _meta: { ui: { resourceUri: ctx.dashboardUri } },
    },
    withScope("openbot.read", "openbot_dashboard", async ({ agent_id }) => {
      const focus = agent_id ? resolveAgent(agent_id) : null;
      const agents = db.listAgents().filter(agent => agentAllowed(agent.id)).map((agent) => ({
        agent_id: agent.id,
        name: agent.name,
        provider: agent.provider,
        model: agent.model,
        status: agentStatus(agent).status,
        focus: focus?.id === agent.id,
      }));
      const tasks = jobs.list({ agentId: focus?.id ?? null, limit: 8, accepts: ownsJob }).map(jobSummary);
      const snapshot = await systemSnapshot();
      const payload = {
        updated_at: new Date().toISOString(),
        connection: { automation: (await automation.health()).reachable, database: db.available, read_only: config.readOnly },
        agents,
        tasks,
        resources: {
          cpu_percent: snapshot.cpu.percent,
          memory_percent: snapshot.memory?.usedPercent ?? null,
          disk_free_gb: snapshot.disk.home ? Math.round(snapshot.disk.home.freeBytes / 1e9) : null,
          uptime_hours: Math.floor(snapshot.uptimeSeconds / 3600),
        },
      };
      return {
        structuredContent: payload,
        content: [
          text(`${agents.length} agents, ${tasks.length} recent tasks, OpenBot ${payload.connection.automation ? "connected" : "unreachable"}.`),
          { type: "resource", resource: { uri: ctx.dashboardUri, mimeType: "text/html;profile=mcp-app", text: ctx.renderDashboard(payload) } },
        ],
      };
    }),
  );

  return { resolveAgent, agentStatus };
}

function jobSummary(job) {
  return {
    task_id: job.id,
    title: job.title,
    kind: job.kind,
    status: job.status,
    created_at: job.createdAt,
    updated_at: job.updatedAt,
    delivery_id: job.deliveryId,
    turn_id: job.turnId,
    error: job.error,
    ended: ENDED_STATUSES.has(job.status),
    needs_person: job.status === "needs_person",
  };
}
