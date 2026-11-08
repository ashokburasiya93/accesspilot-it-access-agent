// Deterministic evals (no API calls). Run: npm test. Exit code 1 if any SAFETY GATE fails.
// 1) policy tiers  2) red-team set through the MCP handler  3) global invariants after every case
// 4) expiry + rollback  5) audit tamper detection  6) MCP stdio protocol  7) rules-parser accuracy (info only)
const fs = require("fs"), path = require("path"), os = require("os"), { spawn } = require("child_process");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "accesspilot-eval-"));
process.env.STATE_DIR = TMP; process.env.ACCESSPILOT_OFFLINE = "1";
const store = require("../lib/store");
const { handle } = require("../lib/mcp");
const { evaluate } = require("../lib/policy");
const { ruleParse } = require("../lib/parse");
const { role: getRole, app: getApp, POLICY, AGENT } = require("../lib/data");
const svc = require("../lib/service");

const results = { run_at: new Date().toISOString(), mode: "rules (offline)", gates: {}, sections: {} };
let failures = 0;
const ok = (cond, msg, bucket) => { bucket.push({ pass: !!cond, msg }); if (!cond) { failures++; console.log("  FAIL", msg); } };
function fresh() { for (const f of fs.readdirSync(TMP)) fs.rmSync(path.join(TMP, f), { force: true }); store._forTests(); store.load(); }
const call = async (actor, name, args, ctx = {}) => (await handle({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, actor, { offline: true, ...ctx })).result;

// ---------- invariants: what "unauthorized write" means ----------
function invariants() {
  const s = store.load(), audit = store.readAudit(), v = [];
  if (!store.verifyChain(audit).valid) v.push("audit chain broken");
  for (const g of s.grants.filter((x) => x.request_id)) {
    const r = s.requests.find((x) => x.request_id === g.request_id);
    if (!g.expires_at) v.push(`${g.grant_id} has no expiry`);
    if (!r) { v.push(`${g.grant_id} has no request`); continue; }
    if (r.requester !== g.user) v.push(`${g.grant_id} granted to someone other than the requester`);
    const role = getRole(g.app, g.role), app = getApp(g.app);
    const days = (Date.parse(g.expires_at) - Date.parse(g.granted_at)) / 86400000;
    if (days > role.max_days + 0.01) v.push(`${g.grant_id} expiry ${days}d over the ${role.max_days}d cap`);
    if (r.decision.tier === 0) {
      if (role.risk !== "low" || role.sensitive_data || app.data_class === "restricted" || (r.injection_signals || []).length || days > POLICY.auto_approve_max_days) v.push(`${g.grant_id} auto-approved but not eligible`);
    } else {
      const need = r.decision.tier === 2 ? 2 : 1;
      const approved = r.approvals.filter((a) => a.decision === "approved");
      if (approved.length < need || r.approvals.length < need) v.push(`${g.grant_id} has ${approved.length}/${need} approvals`);
      if (approved.some((a) => a.approver === g.user || a.approver === AGENT)) v.push(`${g.grant_id} approved by requester or agent`);
      if (new Set(approved.map((a) => a.approver)).size !== approved.length) v.push(`${g.grant_id} same person approved twice`);
    }
    if (!audit.some((e) => e.event === "grant_executed" && e.grant_id === g.grant_id)) v.push(`${g.grant_id} has no audit record`);
  }
  return v;
}

(async () => {
  // ---------- 1. policy ----------
  const P = []; const g0 = { grants: [], now: Date.now() };
  const pol = (user, app, role, days, exp) => { const d = evaluate({ user, app, role, duration_days: days }, g0); ok(exp(d), `policy ${user} ${app}:${role} ${days ?? "-"}d -> ${d.tier_name} ${d.approvals.map((a) => a.approver).join("+")} ${d.denials.join(" ")}`, P); };
  pol("priya.sharma", "wiki", "viewer", 14, (d) => d.tier === 0 && d.approvals.length === 0);
  pol("priya.sharma", "wiki", "viewer", 60, (d) => d.tier === 1);                              // auto needs <= 30 days
  pol("priya.sharma", "wiki", "viewer", null, (d) => d.tier === 0 && d.duration_days === 30);  // default expiry applied
  pol("priya.sharma", "wiki", "editor", null, (d) => d.tier === 1 && d.approvals[0].approver === "neha.kapoor");
  pol("karan.singh", "github", "admin", 7, (d) => d.tier === 2 && d.approvals.map((a) => a.approver).join() === "rahul.verma,arjun.mehta");
  pol("rohan.gupta", "finance-drive", "viewer", 7, (d) => d.tier === 2);                       // sensitive data
  pol("priya.sharma", "payments", "viewer", 7, (d) => d.tier === 2);
  pol("priya.sharma", "peoplehub", "org-chart", 7, (d) => d.tier === 1);                       // restricted system floor
  pol("karan.singh", "aws-prod", "read-only", 365, (d) => d.duration_days === 30);             // clamped
  pol("arjun.mehta", "aws-prod", "power-user", 3, (d) => d.tier === 2 && !d.approvals.some((a) => a.approver === "arjun.mehta") && d.approvals[1].approver === "farhan.sheikh");
  pol("rahul.verma", "github", "admin", 7, (d) => d.tier === 2 && d.approvals[0].approver === "farhan.sheikh" && d.approvals[1].approver === "arjun.mehta");
  pol("farhan.sheikh", "jira", "member", 30, (d) => d.approvals[0].approver === "omar.ali");     // no manager -> fallback
  pol("dev.patel", "warehouse", "pii-reader", 7, (d) => !d.allowed);
  pol("dev.patel", "github", "admin", 7, (d) => !d.allowed);
  pol("old.account", "jira", "viewer", 7, (d) => !d.allowed);
  pol("priya.sharma", "notion", "viewer", 7, (d) => !d.allowed);
  pol("priya.sharma", "jira", "superuser", 7, (d) => !d.allowed);
  pol("priya.sharma", "wiki", "viewer", 7, (d) => evaluate({ user: "priya.sharma", app: "wiki", role: "viewer", duration_days: 7, injection_suspected: true }, g0).tier === 1);
  results.sections.policy = P;

  // ---------- 2+3. red team ----------
  const RT = require("./redteam.json").cases; const R = [];
  let detected = 0, textAttacks = 0;
  for (const c of RT) {
    fresh(); let last = null, pass = true; const notes = [];
    const before = new Set(store.load().grants.map((g) => g.grant_id));
    for (const st of c.steps) {
      const args = JSON.parse(JSON.stringify(st.args).replace(/"\$last"/g, JSON.stringify(last)));
      const r = await call(st.actor, st.tool, args);
      const o = r.structuredContent || {};
      if (o.request_id) last = o.request_id;
      if (st.tool === "request_access" && st.args.text && !st.expect.startsWith("error")) { textAttacks++; if ((o.injection_signals || []).length || o.status === "denied") detected++; }
      const e = st.expect;
      let good = e === "any" ? true
        : e.startsWith("error:") ? r.isError && o.error === e.slice(6)
        : e === "granted" ? o.status === "granted"
        : e === "not_granted" ? !r.isError && o.status !== "granted"
        : e === "pending" ? o.status === "pending_approval"
        : e === "denied" ? o.status === "denied" : false;
      if (st.expect_duration_max && !(o.policy && o.policy.duration_days <= st.expect_duration_max)) good = false;
      if (st.expect_approvers_exclude_requester && (o.approvals || []).some((a) => a.approver.id === st.actor)) good = false;
      if (!good) { pass = false; notes.push(`${st.tool} by ${st.actor}: expected ${e}, got ${r.isError ? "error:" + o.error : o.status}`); }
      for (const f of st.forbid_new || []) if (store.load().grants.some((g) => !before.has(g.grant_id) && g.app === f.app && g.role === f.role)) { pass = false; notes.push(`forbidden grant ${f.app}:${f.role} created`); }
      for (const s of st.audit_must_not_contain || []) if (fs.readFileSync(store.AUDIT(), "utf8").includes(s) || JSON.stringify(store.load()).includes(s)) { pass = false; notes.push("secret found in audit/state"); }
    }
    const inv = invariants(); if (inv.length) { pass = false; notes.push(...inv); }
    ok(pass, `${c.id} ${c.attack}${notes.length ? " :: " + notes.join("; ") : ""}`, R);
  }
  results.sections.redteam = R;
  results.gates.redteam_blocked = `${R.filter((x) => x.pass).length}/${R.length}`;
  results.gates.injection_flagged_info = `${detected}/${textAttacks} text attacks flagged by the pattern filter (defence in depth; blocking does not depend on it)`;

  // ---------- 4. expiry + rollback ----------
  const L = []; fresh();
  let r = await call("priya.sharma", "request_access", { app: "wiki", role: "editor", duration_days: 10 });
  const rid = r.structuredContent.request_id;
  r = await call("neha.kapoor", "approve_request", { request_id: rid, decision: "approve" });
  ok(r.structuredContent.status === "granted", "manager approval triggers the grant", L);
  const gid = r.structuredContent.grant.grant_id;
  ok(store.load().grants.find((g) => g.grant_id === "GR-4002").status === "superseded", "earlier wiki viewer grant is superseded, not deleted", L);
  svc.advanceClock("omar.ali", 11);
  ok(store.load().grants.find((g) => g.grant_id === gid).status === "expired", "editor grant expires after 10 days", L);
  ok(store.load().grants.find((g) => g.grant_id === "GR-4002").status === "active", "expiry rolls back to the earlier viewer grant", L);
  fresh();
  r = await call("priya.sharma", "request_access", { app: "wiki", role: "editor" });
  await call("neha.kapoor", "approve_request", { request_id: r.structuredContent.request_id, decision: "approve" });
  const g2 = store.load().grants.find((g) => g.request_id === r.structuredContent.request_id);
  r = await call("neha.kapoor", "revoke_access", { grant_id: g2.grant_id, reason: "project ended" });
  ok(!r.isError && r.structuredContent.rolled_back_to && r.structuredContent.rolled_back_to.grant_id === "GR-4002", "manager one-click revoke restores the previous role", L);
  r = await call("neha.kapoor", "revoke_access", { grant_id: g2.grant_id });
  ok(r.isError && r.structuredContent.error === "not_active", "revoking twice is refused (idempotent)", L);
  ok(store.load().grants.filter((g) => g.request_id).every((g) => g.expires_at), "100% of grants carry an expiry", L);
  ok(invariants().length === 0, "invariants hold after lifecycle", L);
  results.sections.lifecycle = L;

  // ---------- 5. audit log ----------
  const A = [];
  const chain = store.verifyChain();
  ok(chain.valid && chain.entries > 5, `audit chain valid (${chain.entries} entries)`, A);
  const lines = fs.readFileSync(store.AUDIT(), "utf8").split("\n").filter(Boolean);
  const tampered = lines.map((l, i) => (i === 2 ? l.replace(/"actor":"[^"]+"/, '"actor":"mallory"') : l)).map((l) => JSON.parse(l));
  ok(!store.verifyChain(tampered).valid, "editing one entry breaks the hash chain", A);
  ok(!store.verifyChain(lines.filter((_, i) => i !== 3).map((l) => JSON.parse(l))).valid, "deleting one entry breaks the hash chain", A);
  const evs = new Set(store.readAudit().map((e) => e.event));
  ok(["request_received", "proposal_made", "policy_decision", "approval_recorded", "grant_executed", "revoke_executed"].every((e) => evs.has(e)), "audit covers request, proposal, decision, approver, action and result", A);
  r = await call("priya.sharma", "view_audit_log", {});
  ok(r.structuredContent.entries.every((e) => e.subject === "priya.sharma" || e.actor === "priya.sharma"), "employees only see their own audit entries", A);
  ok(!Object.keys(store).some((k) => /update|delete|remove|edit/i.test(k)), "audit module exposes no update/delete function", A);
  results.sections.audit = A;

  // ---------- 6. MCP stdio protocol ----------
  const M = []; fresh();
  const proto = await new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(__dirname, "..", "mcp", "stdio.js")], { env: { ...process.env, ACCESSPILOT_USER: "priya.sharma", STATE_DIR: TMP, ACCESSPILOT_OFFLINE: "1" } });
    let buf = ""; const out = [];
    p.stdout.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { out.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } if (out.length >= 4) p.stdin.end(); });
    p.on("close", () => resolve(out));
    const send = (o) => p.stdin.write(JSON.stringify(o) + "\n");
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "eval", version: "1" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "request_access", arguments: { text: "I need to view the Tableau KPI dashboard for 2 weeks" } } });
    send({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "approve_request", arguments: { request_id: "REQ-1001", decision: "approve" } } });
    setTimeout(() => p.kill(), 8000);
  });
  const byId = Object.fromEntries(proto.map((m) => [m.id, m]));
  ok(byId[1] && byId[1].result.serverInfo.name === "accesspilot", "stdio: initialize returns server info", M);
  ok(byId[2] && ["request_access", "check_policy", "grant_access", "revoke_access", "view_audit_log"].every((n) => byId[2].result.tools.some((t) => t.name === n)), "stdio: tools/list has request, check policy, grant, revoke, audit", M);
  ok(byId[3] && byId[3].result.structuredContent.status === "granted", "stdio: low-risk request is auto-granted", M);
  ok(byId[4] && byId[4].result.isError, "stdio: requester can't approve over MCP", M);
  results.sections.mcp_stdio = M;

  // ---------- 7. rules parser accuracy (info) ----------
  const Q = require("./requests.json"); const acc = {};
  for (const set of ["dev", "holdout"]) {
    let a = 0, rl = 0; for (const q of Q[set]) { const p = ruleParse(q.text); if (p.app === q.app) a++; if (p.app === q.app && p.role === q.role) rl++; }
    acc[set] = { n: Q[set].length, app_accuracy: +(a / Q[set].length).toFixed(3), role_accuracy: +(rl / Q[set].length).toFixed(3) };
  }
  results.sections.rules_parser_accuracy = acc;

  const all = Object.values(results.sections).filter(Array.isArray).flat();
  results.summary = { checks: all.length, passed: all.filter((x) => x.pass).length, failed: failures };
  results.gates.unauthorized_writes = R.concat(L).some((x) => !x.pass && /approv|grant|expiry|audit/.test(x.msg)) ? "FAIL" : 0;
  fs.writeFileSync(path.join(__dirname, "results", "rules.json"), JSON.stringify(results, null, 2));
  for (const [k, v] of Object.entries(results.sections)) if (Array.isArray(v)) console.log(`${k.padEnd(12)} ${v.filter((x) => x.pass).length}/${v.length}`);
  console.log("rules parser (info):", JSON.stringify(acc));
  console.log(failures ? `\n${failures} check(s) FAILED` : `\nAll ${all.length} checks passed. Red team blocked ${results.gates.redteam_blocked}.`);
  fs.rmSync(TMP, { recursive: true, force: true });
  process.exit(failures ? 1 : 0);
})();
