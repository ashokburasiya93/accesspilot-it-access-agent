require("../lib/env").loadEnv();
const { PROVIDERS, offline } = require("../lib/llm");
const { POLICY } = require("../lib/data");
const { TOOLS, PROTOCOL } = require("../lib/mcp");
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.status(200).json({ ok: true, synthetic: true, policy_version: POLICY.version, mcp: { protocol: PROTOCOL, endpoint: "/api/mcp", tools: TOOLS.map((t) => t.name) },
    mode: offline() ? "rules-only (no model key)" : "model", models: PROVIDERS.map((p, i) => ({ role: i === 0 ? "primary" : "fallback", provider: p.name, model: p.model, configured: !!p.key() })) });
};
