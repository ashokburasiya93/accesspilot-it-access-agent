#!/usr/bin/env node
// AccessPilot MCP server over stdio. Add it to any MCP client (Claude Desktop, Claude Code, Cursor...).
// The signed-in user comes from ACCESSPILOT_USER, set by whoever launches the server (in production: SSO/OAuth).
// Tool arguments can never change who the caller is.
require("../lib/env").loadEnv();
const readline = require("readline");
const { handle } = require("../lib/mcp");
const { person } = require("../lib/data");

const actor = process.env.ACCESSPILOT_USER || "priya.sharma";
if (!person(actor)) { process.stderr.write(`ACCESSPILOT_USER "${actor}" is not in data/directory.json\n`); process.exit(1); }
process.stderr.write(`AccessPilot MCP server (stdio) for ${actor}\n`);

const rl = readline.createInterface({ input: process.stdin });
let chain = Promise.resolve();
rl.on("line", (line) => {
  if (!line.trim()) return;
  chain = chain.then(async () => {
    let msg; try { msg = JSON.parse(line); } catch { return write({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); }
    const batch = Array.isArray(msg) ? msg : [msg];
    const out = (await Promise.all(batch.map((m) => handle(m, actor, { channel: "mcp-stdio" })))).filter(Boolean);
    if (out.length) write(Array.isArray(msg) ? out : out[0]);
  });
});
rl.on("close", () => chain.then(() => process.exit(0)));
function write(o) { process.stdout.write(JSON.stringify(o) + "\n"); }
