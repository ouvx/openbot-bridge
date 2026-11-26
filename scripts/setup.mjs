import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const template = await readFile(new URL(".env.example", root), "utf8");
const config = template.replace(/^BRIDGE_ADMIN_SECRET=$/m,
  () => "BRIDGE_ADMIN_SECRET=" + randomBytes(32).toString("base64url"));
try {
  await writeFile(new URL(".env", root), config, { flag: "wx", mode: 0o600 });
  console.log("Created private .env. Read the consent passcode locally when connecting.");
} catch (error) {
  if (error.code !== "EEXIST") throw error;
  console.log("Using existing .env.");
}
await mkdir(new URL("data/", root), { recursive: true, mode: 0o700 });
