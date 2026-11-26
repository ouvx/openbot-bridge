import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { on, once } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { OperationStore } from "../src/operations.mjs";

const script = fileURLToPath(new URL("./fixtures/claim-worker.mjs", import.meta.url));

function launchWorker(dataDir, signal) {
  const child = spawn(process.execPath, [script, dataDir], { stdio: ["ignore", "ignore", "inherit", "ipc"] });
  const closed = once(child, "close");
  const messages = on(child, "message", { signal, close: ["close"] });
  async function receive() {
    const { done, value } = await messages.next();
    assert.equal(done, false, "worker exited before reporting its result");
    return value[0];
  }
  return { child, closed, receive };
}

test("four independent processes claim one approval and dispatch exactly once", { timeout: 20000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "bridge-process-claim-"));
  const workers = [];
  let store, lock;
  try {
    store = new OperationStore({ dataDir: dir });
    const input = {
      auth: { ok: true, clientId: "client", grantId: "grant", allowedAgentIds: ["alpha"] },
      tool: "send_message", args: { message: "sample", agent_id: "alpha" }, targets: ["alpha"],
    };
    const { approvalId } = store.prepare(input);
    store.decide(approvalId, store.card(approvalId).summaryHash, true);
    const signal = AbortSignal.timeout(12000);
    for (let i = 0; i < 4; i++) workers.push(launchWorker(dir, signal));
    const receiveAll = () => Promise.all(workers.map(worker => worker.receive()));
    assert.deepEqual(await receiveAll(), Array(4).fill("ready"));

    // Hold the writer slot until every independent connection is entering
    // execute. This avoids depending on process startup timing or sleeps.
    lock = new DatabaseSync(join(dir, "operations.sqlite"));
    lock.exec("BEGIN IMMEDIATE");
    for (const { child } of workers) child.send({ ...input, approvalId });
    assert.deepEqual(await receiveAll(), Array(4).fill("entering"));
    lock.exec("ROLLBACK");

    assert.deepEqual((await receiveAll()).sort(), ["approval_used", "approval_used", "approval_used", "succeeded"]);
    for (const worker of workers) assert.deepEqual(await worker.closed, [0, null]);
    const dispatches = readFileSync(join(dir, "dispatches"), "utf8").trimEnd().split("\n");
    assert.equal(dispatches.length, 1);
    assert.ok(workers.some(({ child }) => String(child.pid) === dispatches[0]));
  } finally {
    lock?.close();
    for (const { child } of workers) {
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
    await Promise.allSettled(workers.map(worker => worker.closed));
    store?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
