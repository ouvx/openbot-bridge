import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startBridge } from "../src/index.mjs";

test("Origin mismatch or an empty origin allowlist is refused", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "bridge-origin-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bridge = await startBridge({
    port: 0, logLevel: "error", allowedOrigins: [], dataDir: root, host: "127.0.0.1",
    adminSecret: randomBytes(32).toString("hex"), openbot: { dbPath: join(root, "fixture.db") },
  });
  t.after(() => bridge.stop());
  for (const origin of [bridge.url, "https://unlisted.example"]) {
    const res = await fetch(bridge.url + "/health", { headers: { origin } });
    assert.equal(res.status, 403);
  }
  const res = await fetch(bridge.url + "/health");
  assert.deepEqual(await res.json(), { ok: true });
});
