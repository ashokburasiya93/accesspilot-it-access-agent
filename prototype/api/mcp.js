// MCP over HTTP (stateless JSON responses). Same handler and guardrails as the stdio server.
require("../lib/env").loadEnv();
const { handle } = require("../lib/mcp");
const { actorFrom } = require("./_identity");
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "POST JSON-RPC 2.0 messages here (MCP streamable HTTP, JSON responses)." });
  const actor = actorFrom(req);
  const body = req.body;
  const one = async (m) => {
    if (m && m.method === "tools/call" && !actor) return { jsonrpc: "2.0", id: m.id, error: { code: -32001, message: "No signed-in user. Send X-AccessPilot-User (demo) or a verified identity." } };
    return handle(m, actor, { channel: req.headers["x-accesspilot-channel"] === "web" ? "web-demo" : "mcp-http" });
  };
  const out = Array.isArray(body) ? (await Promise.all(body.map(one))).filter(Boolean) : await one(body);
  if (out == null || (Array.isArray(out) && !out.length)) return res.status(202).end();
  res.status(200).json(out);
};
