// State (requests, grants) and the append-only, hash-chained audit log.
// The audit module exposes append() and read() only: there is no update or delete path in code.
// Storage: STATE_DIR (default ./.state locally, /tmp/accesspilot on Vercel). Files: state.json, audit.jsonl.
const fs = require("fs"), path = require("path"), crypto = require("crypto");

const DIR = process.env.STATE_DIR || (process.env.VERCEL ? "/tmp/accesspilot" : path.join(__dirname, "..", ".state"));
const STATE = () => path.join(DIR, "state.json");
const AUDIT = () => path.join(DIR, "audit.jsonl");
const GENESIS = "0".repeat(64);

let state = null;
function blank() { return { seq: { req: 1000, grant: 5000 }, clock_offset_ms: 0, requests: [], grants: [] }; }
function load() {
  if (state) return state;
  fs.mkdirSync(DIR, { recursive: true });
  if (fs.existsSync(STATE())) state = JSON.parse(fs.readFileSync(STATE(), "utf8"));
  else { state = blank(); require("./seed").seed(state, now()); save(); }
  return state;
}
function save() { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(STATE(), JSON.stringify(state, null, 1)); }
function now() { return Date.now() + ((state && state.clock_offset_ms) || 0); }
function nextId(kind) { const s = load(); s.seq[kind] += 1; return `${kind === "req" ? "REQ" : "GR"}-${s.seq[kind]}`; }

// ---- audit ----
function hashOf(entry) { return crypto.createHash("sha256").update(JSON.stringify(entry)).digest("hex"); }
function readAudit() {
  if (!fs.existsSync(AUDIT())) return [];
  return fs.readFileSync(AUDIT(), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
}
let tail = null;
function lastEntry() { if (tail) return tail; const all = readAudit(); tail = all[all.length - 1] || null; return tail; }
function append(event, actor, data = {}) {
  load();
  const prev = lastEntry();
  const body = { seq: prev ? prev.seq + 1 : 1, ts: new Date(now()).toISOString(), event, actor, ...data, prev_hash: prev ? prev.hash : GENESIS };
  const entry = { ...body, hash: hashOf(body) };
  fs.appendFileSync(AUDIT(), JSON.stringify(entry) + "\n");
  tail = entry;
  return entry;
}
function verifyChain(entries = readAudit()) {
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const { hash, ...body } = entries[i];
    if (body.prev_hash !== prev || hashOf(body) !== hash || body.seq !== i + 1) return { valid: false, entries: entries.length, broken_at_seq: body.seq ?? i + 1 };
    prev = hash;
  }
  return { valid: true, entries: entries.length, head: prev.slice(0, 12) };
}

// Demo only: archive (never delete) the current log and start fresh.
function resetDemo() {
  fs.mkdirSync(DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  if (fs.existsSync(AUDIT())) fs.renameSync(AUDIT(), path.join(DIR, `audit-archived-${stamp}.jsonl`));
  tail = null; state = blank(); require("./seed").seed(state, now()); save();
}
function _forTests() { state = null; tail = null; }

module.exports = { load, save, now, nextId, append, readAudit, verifyChain, resetDemo, DIR, AUDIT, _forTests };
