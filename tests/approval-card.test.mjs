import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { OperationStore } from "../src/operations.mjs";
import { openApprovalCard } from "../scripts/approve.mjs";

test("private human card binds the visible content and refuses foreign origin, missing capability and modified display", async t => {
  const dataDir = await mkdtemp(join(tmpdir(), "bridge-human-"));
  const store = new OperationStore({ dataDir });
  const input = { tool: "send_message", args: { message: "sample private note" }, targets: ["agent"],
    auth: { ok: true, grantId: "g", clientId: "c", allowedAgentIds: ["agent"] } };
  const { approvalId } = store.prepare(input);
  const ui = await openApprovalCard(store, approvalId);
  t.after(async () => { ui.stop(); await ui.closed; store.close(); await rm(dataDir, { recursive: true, force: true }); });
  const { origin, hash } = new URL(ui.url);
  const headers = { origin, authorization: "Bearer " + hash.slice(1), "content-type": "application/json" };
  const post = (path, body, overrides = {}) => fetch(origin + path, {
    method: "POST", headers: { ...headers, ...overrides }, body: JSON.stringify(body),
  });
  const page = await fetch(origin);
  assert.equal(page.status, 200);
  assert.ok(!(await page.text()).includes(input.args.message));
  assert.equal((await post("/card", {}, { origin: "https://other.example" })).status, 403);
  assert.equal((await post("/card", {}, { authorization: "" })).status, 403);
  const card = await (await post("/card", {})).json();
  assert.deepEqual(JSON.parse(card.summary), { args: input.args, targets: input.targets, tool: input.tool });
  assert.equal((await post("/decision", { approved: true, summaryHash: "different" })).status, 409);
  const digest = createHash("sha256").update(card.summary).digest("hex");
  assert.equal((await post("/decision", { approved: true, summaryHash: digest })).status, 200);
  const result = await store.execute({ ...input, approvalId }, async args => args.message);
  assert.equal(result, input.args.message);
});
