// Web-demo controls: list personas, move simulated time forward (to show expiry), reset. Every action is audited.
require("../lib/env").loadEnv();
const store = require("../lib/store");
const svc = require("../lib/service");
const { DIRECTORY } = require("../lib/data");
const { actorFrom } = require("./_identity");
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const action = (req.query && req.query.action) || (req.body && req.body.action) || "personas";
  try {
    if (action === "personas") { store.load(); return res.status(200).json({ now: new Date(store.now()).toISOString(), people: DIRECTORY.people.filter((p) => p.active).map((p) => ({ id: p.id, name: p.name, title: p.title, persona: p.persona })) }); }
    if (req.method !== "POST") return res.status(405).json({ error: "POST only" });
    if (action === "advance") { const days = Math.min(Math.max(Number(req.body.days) || 0, 1), 120); return res.status(200).json(svc.advanceClock(actorFrom(req), days)); }
    if (action === "reset") { store.resetDemo(); store.append("demo_reset", actorFrom(req) || "demo", { note: "Demo state reset. The previous audit log was archived, not deleted." }); return res.status(200).json({ ok: true }); }
    res.status(400).json({ error: "unknown action" });
  } catch (e) { res.status(500).json({ error: e.message }); }
};
