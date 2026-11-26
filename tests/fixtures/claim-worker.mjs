import { appendFileSync } from "node:fs";
import { join } from "node:path";
import { OperationStore } from "../../src/operations.mjs";

const dataDir = process.argv[2];
const store = new OperationStore({ dataDir });

process.once("message", async signed => {
  process.send("entering");
  try {
    await store.execute(signed, () => {
      appendFileSync(join(dataDir, "dispatches"), process.pid + "\n");
      return { ok: true };
    });
    process.send("succeeded");
  } catch (error) {
    process.send(error.code ?? error.name);
  } finally {
    store.close();
    process.disconnect();
  }
});
process.send("ready");
