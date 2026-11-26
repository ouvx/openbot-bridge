import { randomBytes } from "node:crypto";
import { mkdir, lstat, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);
const template = await readFile(new URL(".env.example", root), "utf8");
const config = template.replace(/^BRIDGE_ADMIN_SECRET=$/m,
  () => "BRIDGE_ADMIN_SECRET=" + randomBytes(32).toString("base64url"));
try {
  await writeFile(new URL(".env", root), config, { flag: "wx", mode: 0o600 });
} catch (error) {
  if (error.code !== "EEXIST") throw error;
  const file = await lstat(new URL(".env", root));
  if (!file.isFile() || (file.mode & 0o777) !== 0o600) {
    throw new Error("Existing .env must be a private regular file with mode 0600.");
  }
}
await mkdir(new URL("data/", root), { recursive: true, mode: 0o700 });
console.log(fileURLToPath(new URL(".env", root)));
