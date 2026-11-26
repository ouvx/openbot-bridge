import { z } from "zod";
import { execFile } from "node:child_process";
import { readFile, readdir, realpath, stat } from "node:fs/promises";
import { basename, resolve, sep } from "node:path";
import { systemSnapshot } from "./openbot/system.mjs";
import { isAgentAllowed } from "./config.mjs";
import { isEnded } from "./jobs.mjs";
import { maskSecrets, truncate } from "./log.mjs";

const MAX_TEXT = 8000;
const ENDED_STATUSES = new Set(["completed", "failed", "interrupted", "cancelled"]);

/**
 * Registers every bridge tool on the MCP server.
 *
 * Reads come from OpenBot's projection database (read-only) and system files;
 * writes go through OpenBot's automation API. Nothing here runs a shell with
 * model-provided text: `git` is only ever called with fixed arguments inside an
 * agent's own workspace.
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
    const auth = extra?.authInfo ?? ctx.currentAuth?.();
    if (!oauth.hasScope(auth, scope)) {
      return fail(`This connection is missing the ${scope} scope. Reconnect the plugin in ChatGPT to grant it.`);
    }
    if (scope !== "openbot.read" && config.readOnly) {
      return fail("The bridge runs in read-only mode (BRIDGE_READ_ONLY=1).");
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

  const resolveAgent = (reference) => {
    const agents = db.listAgents().filter(agent => isAgentAllowed(config, agent.id));
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
    if (!isAgentAllowed(config, agent.id)) throw new Error(`The bridge is not allowed to drive ${agent.name}.`);
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

  const jobsForAgent = (agentId) => jobs.list({ agentId, limit: 5 });

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
      const visible = db.listAgents().filter(agent => isAgentAllowed(config, agent.id)).map((agent) => {
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
        "Read one agent's role description, runtime, model, permission level, local skills, routines, current session and recent activity. Use it to explain what an agent can do or to pick the right agent for a task.",
      inputSchema: {
        agent_id: z.string().describe("Agent id (or an exact agent name)."),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_agent", async ({ agent_id }) => {
      const agent = resolveAgent(agent_id);
      const status = agentStatus(agent);
      const threads = db.listThreads(agent.id).slice(0, 5);
      const skills = await listSkills(agent.workspacePath).catch(() => []);
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
          workspace_path: agent.workspacePath,
          local_skills: skills,
          allowed_by_bridge: isAgentAllowed(config, agent.id),
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
          current_session_id: agent.threadId,
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
      const messages = db.messages(threadId, { limit: limit ?? 30 });
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
      let tasks = jobs.list({ agentId: agent?.id ?? null, limit: limit ?? 20 }).filter(job => isAgentAllowed(config, job.agentId));
      if (status) tasks = tasks.filter((job) => job.status === status);
      const refreshed = await Promise.all(tasks.slice(0, 10).map((job) => jobs.refresh(job).catch(() => job)));
      const structured = {
        agent_id: agent?.id ?? null,
        tasks: refreshed.map((job) => ({ ...jobSummary(job), agent_id: job.agentId })),
        recent_deliveries: agent ? db.deliveries(agent.id, limit ?? 10) : [],
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
      let job = jobs.get(task_id);
      if (!job || !isAgentAllowed(config, job.agentId)) return fail("Task unavailable.");
      job = wait_seconds ? await jobs.waitFor(job, wait_seconds) : await jobs.refresh(job, { force: true });
      const agent = db.agent(job.agentId);
      const logs = job.turnId ? db.activities({ turnId: job.turnId, limit: 30 }).reverse() : [];
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
        const job = jobs.get(task_id);
        if (!job || !isAgentAllowed(config, job.agentId)) return fail("Task unavailable.");
        turnId = turnId ?? job.turnId;
        threadId = threadId ?? db.agent(job.agentId)?.threadId ?? null;
      }
      if (!turnId && !threadId) return fail("Give task_id, turn_id or session_id.");
      if (turnId) {
        const turnThread = db.turn(turnId)?.threadId;
        if (!turnThread || (threadId && threadId !== turnThread)) return fail("Turn unavailable.");
        threadId = turnThread;
      }
      if (!isAgentAllowed(config, db.thread(threadId)?.agentId)) return fail("Session unavailable.");
      const activities = db.activities({ turnId, threadId, limit: limit ?? 80 }).reverse();
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
        "List files an agent produced (OpenBot attachments) and, optionally, files in the agent's workspace. Use it to find reports, diffs, images or generated documents before fetching one with read_artifact.",
      inputSchema: {
        agent_id: z.string().optional(),
        include_workspace: z.boolean().optional(),
        limit: z.number().int().min(1).max(100).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "list_artifacts", async ({ agent_id, include_workspace, limit }) => {
      const agent = agent_id ? resolveAgent(agent_id) : null;
      const sources = agent ? [agent] : db.listAgents().filter(item => isAgentAllowed(config, item.id));
      const attachments = sources.flatMap(item => db.attachments({ agentId: item.id, limit: limit ?? 30 })).slice(0, limit ?? 30);
      const workspace = agent && include_workspace ? await listWorkspace(agent.workspacePath, 40).catch(() => []) : [];
      return reply(
        { agent_id: agent?.id ?? null, attachments, workspace_files: workspace },
        [...attachments.map((item) => `${item.name} — ${item.size ?? "?"} bytes — ${item.path}`), ...workspace.map((item) => `workspace: ${item}`)].join("\n") ||
          "No artifacts found.",
      );
    }),
  );

  server.registerTool(
    "read_artifact",
    {
      title: "Read an artifact",
      description:
        "Read the text of one artifact: either an attachment path from list_artifacts or a file inside an agent's workspace. Binary files and files above the size limit are refused. Only paths that resolve inside an allowed folder are readable.",
      inputSchema: {
        agent_id: z.string().describe("Agent that owns the workspace."),
        path: z.string().describe("Absolute or workspace-relative path."),
        max_bytes: z.number().int().min(1024).max(524288).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "read_artifact", async ({ agent_id, path, max_bytes }) => {
      const agent = resolveAgent(agent_id);
      const roots = [agent.workspacePath, config.sharedDir].filter(Boolean);
      const absolute = path.startsWith("/") ? path : resolve(agent.workspacePath ?? "/", path);
      const real = await realpath(absolute).catch(() => null);
      if (!real) return fail(`File not found: ${path}`);
      const allowed = roots.some((root) => real === root || real.startsWith(root + sep));
      if (!allowed) return fail("That path is outside the agent's workspace and the shared folder.");
      const info = await stat(real);
      if (!info.isFile()) return fail("That path is not a regular file.");
      const limitBytes = max_bytes ?? config.limits.artifactBytes;
      if (info.size > limitBytes) return fail(`The file is ${info.size} bytes; the limit is ${limitBytes}.`);
      if (!isTextFile(real)) return fail("Only text files can be read through the bridge.");
      const body = await readFile(real, "utf8");
      return reply(
        { path: real, name: basename(real), size: info.size, text: truncate(maskSecrets(body), config.limits.maxToolResultChars) },
        truncate(maskSecrets(body), MAX_TEXT),
      );
    }),
  );

  server.registerTool(
    "get_git_diff",
    {
      title: "Get a workspace git diff",
      description:
        "Run a read-only git status/diff inside an agent's workspace so you can review the code it changed. No other command can be run; arguments are fixed by the bridge.",
      inputSchema: {
        agent_id: z.string().describe("Agent whose workspace is inspected."),
        mode: z.enum(["status", "diff", "stat"]).optional(),
        max_bytes: z.number().int().min(1024).max(524288).optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.read", "get_git_diff", async ({ agent_id, mode, max_bytes }) => {
      const agent = resolveAgent(agent_id);
      if (!agent.workspacePath) return fail(`${agent.name} has no workspace folder.`);
      const args = mode === "status" ? ["-C", agent.workspacePath, "status", "--short", "--branch"] : mode === "stat" ? ["-C", agent.workspacePath, "diff", "--stat"] : ["-C", agent.workspacePath, "diff", "--no-color"];
      const output = await runGit(args, max_bytes ?? config.limits.artifactBytes);
      return reply({ agent_id: agent.id, workspace: agent.workspacePath, mode: mode ?? "diff", diff: output }, output || "No changes.");
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

  const dispatch = async ({ agentId, kind, title, prompt, idempotencyKey }) => {
    if (idempotencyKey) {
      const existing = jobs.findByIdempotencyKey(idempotencyKey);
      if (existing && existing.agentId !== agentId) throw new Error("That idempotency key cannot be reused for a different target.");
      if (existing) return existing;
    }
    const job = await jobs.create({ agentId, kind, title, prompt, idempotencyKey });
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
        agent_id: z.string().describe("Agent id or exact name from list_agents."),
        message: z.string().min(1).describe("The text to send."),
        title: z.string().max(120).optional().describe("Short label for the task list."),
        idempotency_key: z.string().max(120).optional().describe("Reuse to avoid sending the same message twice."),
        wait_seconds: z.number().min(0).max(25).optional().describe("Poll briefly so quick replies can finish in this call."),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.write", "send_message", async ({ agent_id, message, title, idempotency_key, wait_seconds }) => {
      const agent = requireAllowed(resolveAgent(agent_id));
      if (message.length > config.limits.maxMessageChars) return fail(`The message is longer than ${config.limits.maxMessageChars} characters.`);
      const job = await dispatch({
        agentId: agent.id,
        kind: "message",
        title,
        prompt: message,
        idempotencyKey: idempotency_key ?? null,
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
        agent_id: z.string().describe("Agent id or exact name."),
        task: z.string().min(1).describe("What the agent must do."),
        context: z.string().optional().describe("Background the agent cannot see, such as the current ChatGPT discussion."),
        constraints: z.string().optional().describe("Limits: files to avoid, no network, no push, and so on."),
        definition_of_done: z.string().optional().describe("How the result will be judged."),
        title: z.string().max(120).optional(),
        idempotency_key: z.string().max(120).optional(),
        wait_seconds: z.number().min(0).max(25).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.write", "delegate_task", async ({ agent_id, task, context, constraints, definition_of_done, title, idempotency_key, wait_seconds }) => {
      const agent = requireAllowed(resolveAgent(agent_id));
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
        idempotencyKey: idempotency_key ?? null,
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
        task_id: z.string().describe("The task being corrected."),
        feedback: z.string().min(1).describe("What is wrong and what to change."),
        wait_seconds: z.number().min(0).max(25).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    },
    withScope("openbot.write", "send_feedback", async ({ task_id, feedback, wait_seconds }) => {
      const original = jobs.get(task_id);
      if (!original) return fail(`No task ${task_id}.`);
      const agent = requireAllowed(db.agent(original.agentId) ?? { id: original.agentId, name: original.agentId });
      const prompt = [
        `【前の作業への修正指示】対象: ${original.title} (${original.id})`,
        "",
        "修正点:",
        feedback,
        "",
        "前回の続きとして、同じセッションの文脈で直してください。直したこと・確認したこと・未確認のことを短く返してください。",
      ].join("\n");
      const job = await dispatch({ agentId: agent.id, kind: "feedback", title: `修正: ${original.title}`, prompt, idempotencyKey: null });
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
        task_id: z.string(),
        reason: z.string().max(300).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    withScope("openbot.write", "cancel_task", async ({ task_id, reason }) => {
      const job = jobs.get(task_id);
      if (!job) return fail(`No task ${task_id}.`);
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
        agent_id: z.string().describe("Agent id or exact name."),
        confirm: z.literal(true).describe("Must be true: this clears the agent's current conversation context."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    withScope("openbot.admin", "start_new_session", async ({ agent_id }) => {
      const agent = requireAllowed(resolveAgent(agent_id));
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
      const agents = db.listAgents().filter(agent => isAgentAllowed(config, agent.id)).map((agent) => ({
        agent_id: agent.id,
        name: agent.name,
        provider: agent.provider,
        model: agent.model,
        status: agentStatus(agent).status,
        focus: focus?.id === agent.id,
      }));
      const tasks = jobs.list({ agentId: focus?.id ?? null, limit: 8 }).filter(job => isAgentAllowed(config, job.agentId)).map(jobSummary);
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

async function listSkills(workspacePath) {
  if (!workspacePath) return [];
  const roots = [`${workspacePath}/.agents/skills`, `${workspacePath}/.claude/skills`];
  const found = new Set();
  for (const root of roots) {
    try {
      for (const entry of await readdir(root)) found.add(entry);
    } catch {
      // No skills folder.
    }
  }
  return [...found].slice(0, 40);
}

async function listWorkspace(workspacePath, limit) {
  if (!workspacePath) return [];
  const entries = await readdir(workspacePath);
  return entries.filter((entry) => !entry.startsWith(".")).slice(0, limit);
}

function isTextFile(path) {
  const textExtensions = new Set([
    "md", "txt", "json", "yaml", "yml", "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "rb", "go", "rs", "java", "kt",
    "c", "h", "cpp", "hpp", "cs", "php", "sh", "bash", "zsh", "sql", "html", "css", "scss", "svg", "xml", "toml",
    "ini", "cfg", "conf", "log", "csv", "tsv", "diff", "patch", "env", "lock", "gitignore", "dockerfile", "makefile",
  ]);
  const name = basename(path).toLowerCase();
  if (name === "dockerfile" || name === "makefile") return true;
  const extension = name.includes(".") ? name.split(".").pop() : "";
  return textExtensions.has(extension);
}

function runGit(args, maxBytes) {
  return new Promise((resolvePromise, reject) => {
    execFile("git", args, { timeout: 15000, maxBuffer: maxBytes, encoding: "utf8" }, (error, stdout) => {
      if (error && !stdout) {
        reject(new Error(`git could not read that workspace: ${error.message}`));
        return;
      }
      resolvePromise(truncate(maskSecrets(stdout), maxBytes));
    });
  });
}
