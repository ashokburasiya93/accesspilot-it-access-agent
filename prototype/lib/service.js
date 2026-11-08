// AccessPilot core: the tool logic behind the MCP server. Every write goes through here.
// The caller's identity (actor) comes from the session, never from tool arguments.
const store = require("./store");
const { evaluate, DAY } = require("./policy");
const { person, app: getApp, role: getRole, isPrivileged, reports, AGENT, CATALOG, POLICY } = require("./data");
const guard = require("./guard");
const { parseRequest } = require("./parse");

class ToolError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const pub = (p) => (p ? { id: p.id, name: p.name, title: p.title } : null);
const label = (a, r) => `${(getApp(a) || {}).name || a} ${(getRole(a, r) || {}).name || r}`;

function blocked(actor, tool, code, reason, extra = {}) {
  store.append("action_blocked", actor, { tool, code, reason, ...extra });
  throw new ToolError(code, reason);
}

function requireHuman(actor, tool) {
  if (actor === AGENT) blocked(actor, tool, "agent_not_allowed", "The AccessPilot agent can't take this action itself. A named person must do it.");
  const p = person(actor);
  if (!p || !p.active) blocked(actor, tool, "unknown_actor", "This session is not linked to an active employee.");
  return p;
}

// Lazy expiry: runs before every tool call. Expired grants are removed and any earlier grant is restored.
function sweepExpired() {
  const s = store.load(); const now = store.now(); let changed = false;
  for (const g of s.grants) if (g.status === "active" && Date.parse(g.expires_at) <= now) {
    g.status = "expired"; g.ended_at = new Date(now).toISOString(); changed = true;
    const restored = rollback(s, g, now);
    store.append("grant_expired", AGENT, { grant_id: g.grant_id, subject: g.user, app: g.app, role: g.role, request_id: g.request_id, rolled_back_to: restored });
  }
  if (changed) store.save();
}

function rollback(s, g, now) {
  if (!g.previous_grant_id) return null;
  const prev = s.grants.find((x) => x.grant_id === g.previous_grant_id);
  if (prev && prev.status === "superseded" && Date.parse(prev.expires_at) > now) { prev.status = "active"; return prev.grant_id; }
  return null;
}

function activeGrants() { return store.load().grants.filter((g) => g.status === "active"); }

// ---------------- tools ----------------

async function requestAccess(actor, args) {
  const me = requireHuman(actor, "request_access");
  const s = store.load(); const now = store.now();
  const rawText = guard.clean(args.text || ""), rawWhy = guard.clean(args.justification || "");
  if (!rawText && !args.app) throw new ToolError("bad_request", "Describe the access you need, or give an app and role.");
  const red = guard.redactSecrets([rawText, rawWhy].filter(Boolean).join("\n"));
  const text = guard.redactSecrets(rawText).text, why = guard.redactSecrets(rawWhy).text;
  const signals = guard.detectInjection(red.text);
  const id = store.nextId("req");
  const req = { request_id: id, requester: me.id, text, justification: why, created_at: new Date(now).toISOString(), status: "received", injection_signals: signals, approvals: [], grant_id: null };
  s.requests.push(req);
  store.append("request_received", actor, { request_id: id, subject: me.id, text, justification: why, channel: args._channel || "mcp", injection_signals: signals, credentials_redacted: red.found });
  const warnings = [];
  if (red.found.length) { warnings.push("It looks like you included a password or key. I removed it and never store or use credentials. Please rotate it."); store.append("credential_redacted", AGENT, { request_id: id, kinds: red.found }); }
  if (signals.length) warnings.push("Your message included instructions aimed at the system. They were ignored, and a person will review this request.");

  const nr = guard.nonRequestable(red.text);
  if (nr) return finish(req, "denied", { decision: { allowed: false, denials: [nr], tier_name: "Denied" } }, warnings);

  // Proposal: structured args from an MCP client, or free text interpreted by the model (or rules).
  let parsed;
  if (args.app) parsed = { proposal: guard.validateProposal({ app: args.app, role: args.role, duration_days: args.duration_days }), source: "structured" };
  else parsed = await parseRequest(red.text, me, { offline: args._offline });
  const p = parsed.proposal;
  if (Number.isInteger(args.duration_days) && args.duration_days > 0) p.duration_days = args.duration_days;
  req.proposal = { app: p.app, role: p.role, duration_days: p.duration_days, need: p.need, source: parsed.source, model: parsed.model || null, dropped_fields: p.dropped_fields };
  req.usage = parsed.usage || null;
  store.append("proposal_made", parsed.source === "model" ? AGENT : "rules", { request_id: id, subject: me.id, app: p.app, role: p.role, duration_days: p.duration_days, source: parsed.source, model: parsed.model || null, dropped_fields: p.dropped_fields });
  if (!p.app || !p.role) { req.status = "needs_clarification"; req.clarification = p.clarification; store.save(); return view(req, warnings, p.clarification); }

  const decision = evaluate({ user: me.id, app: p.app, role: p.role, duration_days: p.duration_days, injection_suspected: signals.length > 0 }, { grants: activeGrants(), now });
  req.app = p.app; req.role = p.role; req.decision = decision;
  store.append("policy_decision", "policy-engine", { request_id: id, subject: me.id, app: p.app, role: p.role, policy_version: POLICY.version, allowed: decision.allowed, tier: decision.tier, tier_name: decision.tier_name, approvers: decision.approvals.map((x) => `${x.step}:${x.approver}`), duration_days: decision.duration_days, reasons: decision.reasons, denials: decision.denials });
  if (!decision.allowed) return finish(req, "denied", {}, warnings);
  req.approvals = decision.approvals.map((x) => ({ ...x, decision: "pending", at: null, comment: "" }));
  if (decision.tier === 0) { req.status = "approved"; store.append("auto_approved", "policy-engine", { request_id: id, subject: me.id, reason: decision.reasons.join(" ") }); executeGrant(req, actor); return view(req, warnings); }
  req.status = "pending_approval"; store.save();
  return view(req, warnings);
}

function finish(req, status, extra, warnings) { Object.assign(req, extra); req.status = status; store.save(); return view(req, warnings); }

function approveRequest(actor, args) {
  const req = store.load().requests.find((r) => r.request_id === args.request_id);
  if (actor === AGENT) blocked(actor, "approve_request", "agent_not_allowed", "The agent can never approve a request. Only the named approver can.", { request_id: args.request_id });
  const me = requireHuman(actor, "approve_request");
  if (!req) throw new ToolError("not_found", `No request ${args.request_id}.`);
  if (req.requester === me.id) blocked(actor, "approve_request", "self_approval", "You can't approve your own request.", { request_id: req.request_id, subject: req.requester });
  if (req.status !== "pending_approval") blocked(actor, "approve_request", "not_pending", `${req.request_id} is ${req.status}, not waiting for approval.`, { request_id: req.request_id, subject: req.requester });
  const step = req.approvals.find((a) => a.decision === "pending" && a.approver === me.id);
  if (!step) blocked(actor, "approve_request", "not_an_approver", `You are not a pending approver for ${req.request_id}. Waiting on: ${req.approvals.filter((a) => a.decision === "pending").map((a) => a.approver).join(", ")}.`, { request_id: req.request_id, subject: req.requester });
  const decision = args.decision === "reject" ? "rejected" : "approved";
  const comment = guard.clean(args.comment || "").slice(0, 500);
  step.decision = decision; step.at = new Date(store.now()).toISOString(); step.comment = comment;
  store.append(decision === "approved" ? "approval_recorded" : "approval_rejected", actor, { request_id: req.request_id, subject: req.requester, step: step.step, comment });
  if (decision === "rejected") { req.status = "rejected"; store.save(); return view(req); }
  if (req.approvals.every((a) => a.decision === "approved")) { req.status = "approved"; executeGrant(req, actor); }
  else store.save();
  return view(req);
}

function grantAccess(actor, args) {
  const me = requireHuman(actor, "grant_access");
  const req = store.load().requests.find((r) => r.request_id === args.request_id);
  if (!req) throw new ToolError("not_found", `No request ${args.request_id}.`);
  const involved = req.requester === me.id || req.approvals.some((a) => a.approver === me.id) || isPrivileged(me.id);
  if (!involved) blocked(actor, "grant_access", "not_involved", "Only the requester, an approver or IT can trigger this grant.", { request_id: req.request_id, subject: req.requester });
  if (req.status === "granted") return view(req, ["Already granted. Nothing to do."]);
  if (req.status !== "approved") {
    const missing = req.approvals.filter((a) => a.decision !== "approved").map((a) => `${a.step} (${a.approver})`);
    blocked(actor, "grant_access", "approvals_missing", `Can't grant ${req.request_id}: it is ${req.status}.${missing.length ? " Missing approvals: " + missing.join(", ") + "." : ""}`, { request_id: req.request_id, subject: req.requester });
  }
  executeGrant(req, actor);
  return view(req);
}

// The only function that writes an entitlement. It re-checks policy at write time.
function executeGrant(req, triggeredBy) {
  const s = store.load(); const now = store.now();
  const d = evaluate({ user: req.requester, app: req.app, role: req.role, duration_days: req.decision.duration_days, injection_suspected: (req.injection_signals || []).length > 0 }, { grants: activeGrants(), now });
  const approvedBy = req.approvals.filter((a) => a.decision === "approved").map((a) => `${a.step}:${a.approver}`);
  const missing = d.allowed ? d.approvals.filter((x) => !approvedBy.includes(`${x.step}:${x.approver}`)) : [];
  if (!d.allowed || missing.length || approvedBy.some((a) => a.endsWith(":" + req.requester))) {
    req.status = "failed"; req.failure = !d.allowed ? d.denials.join(" ") : "Approvals no longer match the policy.";
    store.append("grant_failed", AGENT, { request_id: req.request_id, subject: req.requester, reason: req.failure });
    store.save(); return;
  }
  if (!d.expires_at) throw new Error("invariant: every grant needs an expiry");
  const existing = s.grants.find((g) => g.user === req.requester && g.app === req.app && g.status === "active");
  if (existing) existing.status = "superseded";
  const g = { grant_id: store.nextId("grant"), request_id: req.request_id, user: req.requester, app: req.app, role: req.role, previous_grant_id: existing ? existing.grant_id : null,
    granted_at: new Date(now).toISOString(), expires_at: d.expires_at, status: "active", approved_by: approvedBy.length ? approvedBy : ["auto (tier 0)"], tier: d.tier, executed_by: AGENT };
  s.grants.push(g); req.status = "granted"; req.grant_id = g.grant_id;
  store.append("grant_executed", AGENT, { request_id: req.request_id, grant_id: g.grant_id, subject: g.user, app: g.app, role: g.role, tier: d.tier, approved_by: g.approved_by, expires_at: g.expires_at, replaced_grant: g.previous_grant_id, triggered_by: triggeredBy, target: "identity-provider (simulated)" });
  store.save();
}

function revokeAccess(actor, args) {
  const me = requireHuman(actor, "revoke_access");
  const s = store.load(); const g = s.grants.find((x) => x.grant_id === args.grant_id);
  if (!g) throw new ToolError("not_found", `No grant ${args.grant_id}.`);
  const a = getApp(g.app);
  const allowed = me.id === g.user || (person(g.user) || {}).manager === me.id || [a.owner, a.backup_owner].includes(me.id) || isPrivileged(me.id);
  if (!allowed) blocked(actor, "revoke_access", "not_allowed", "Only the holder, their manager, the app owner or IT/security can revoke this grant.", { grant_id: g.grant_id, subject: g.user });
  if (g.status !== "active") blocked(actor, "revoke_access", "not_active", `${g.grant_id} is already ${g.status}.`, { grant_id: g.grant_id, subject: g.user });
  const now = store.now();
  g.status = "revoked"; g.ended_at = new Date(now).toISOString(); g.revoked_by = me.id; g.revoke_reason = guard.clean(args.reason || "").slice(0, 300);
  const restored = rollback(s, g, now);
  store.append("revoke_executed", actor, { grant_id: g.grant_id, request_id: g.request_id, subject: g.user, app: g.app, role: g.role, reason: g.revoke_reason, rolled_back_to: restored, executed_by: AGENT, target: "identity-provider (simulated)" });
  store.save();
  const prev = restored && s.grants.find((x) => x.grant_id === restored);
  return { grant: grantView(g), rolled_back_to: prev ? grantView(prev) : null, message: prev ? `Revoked ${label(g.app, g.role)}. ${person(g.user).name} is back on ${label(prev.app, prev.role)} (${prev.grant_id}).` : `Revoked ${label(g.app, g.role)} for ${person(g.user).name}.` };
}

function checkPolicy(actor, args) {
  const me = requireHuman(actor, "check_policy");
  const user = args.user || me.id;
  if (user !== me.id && !isPrivileged(me.id) && !reports(me.id).includes(user)) blocked(actor, "check_policy", "not_allowed", "You can only check policy for yourself or your direct reports.", { subject: user });
  const p = guard.validateProposal({ app: args.app, role: args.role });
  if (!p.app || !p.role) return { allowed: false, message: p.clarification };
  const d = evaluate({ user, app: p.app, role: p.role, duration_days: args.duration_days }, { grants: activeGrants(), now: store.now() });
  return { user: pub(person(user)), app: p.app, role: p.role, access: label(p.app, p.role), ...d, approvals: d.approvals.map((x) => ({ ...x, approver: pub(person(x.approver)) })), note: "Dry run. Nothing was requested or written." };
}

function viewAuditLog(actor, args) {
  const me = requireHuman(actor, "view_audit_log");
  const all = store.readAudit();
  const chain = store.verifyChain(all);
  const scope = isPrivileged(me.id) ? null : new Set([me.id, ...reports(me.id)]);
  // Approvers also see the trail of requests they were asked to approve; app owners see their apps.
  const myReqs = new Set(store.load().requests.filter((r) => (r.approvals || []).some((a) => a.approver === me.id)).map((r) => r.request_id));
  const owned = new Set(CATALOG.apps.filter((a) => a.owner === me.id || a.backup_owner === me.id).map((a) => a.id));
  let rows = all.filter((e) => !scope || scope.has(e.subject) || e.actor === me.id || myReqs.has(e.request_id) || owned.has(e.app));
  if (args.request_id) rows = rows.filter((e) => e.request_id === args.request_id);
  if (args.user) rows = rows.filter((e) => e.subject === args.user || e.actor === args.user);
  const limit = Math.min(Math.max(Number(args.limit) || 50, 1), 500);
  return { chain, scope: scope ? "you, your direct reports, requests you approve and apps you own" : "everything (IT/security)", total: rows.length, entries: rows.slice(-limit).reverse() };
}

function listRequests(actor, args) {
  const me = requireHuman(actor, "list_requests");
  const s = store.load(); const scope = args.scope || "mine";
  if (scope === "all" && !isPrivileged(me.id)) blocked(actor, "list_requests", "not_allowed", "Only IT and security can list every request.");
  const team = new Set([me.id, ...reports(me.id)]);
  const reqs = s.requests.filter((r) => scope === "all" || (scope === "approvals" ? r.status === "pending_approval" && r.approvals.some((a) => a.approver === me.id && a.decision === "pending") : scope === "team" ? team.has(r.requester) : r.requester === me.id));
  const ownedApps = CATALOG.apps.filter((a) => a.owner === me.id || a.backup_owner === me.id).map((a) => a.id);
  const grants = s.grants.filter((g) => scope === "all" || (scope === "team" ? team.has(g.user) || ownedApps.includes(g.app) : scope === "mine" ? g.user === me.id : false));
  return { me: pub(me), scope, requests: reqs.slice().reverse().map((r) => view(r)), grants: grants.slice().reverse().map(grantView) };
}

function listCatalog() {
  return { apps: CATALOG.apps.map((a) => ({ id: a.id, name: a.name, data_class: a.data_class, owner: pub(person(a.owner)), roles: a.roles.map((r) => ({ id: r.id, name: r.name, can: r.can, risk: r.risk, sensitive_data: r.sensitive_data, default_days: r.default_days, max_days: r.max_days })) })), policy_version: POLICY.version };
}

// ---------------- views ----------------
function grantView(g) {
  const now = store.now();
  return { grant_id: g.grant_id, user: pub(person(g.user)), app: g.app, role: g.role, access: label(g.app, g.role), status: g.status, granted_at: g.granted_at, expires_at: g.expires_at,
    days_left: g.status === "active" ? Math.max(0, Math.ceil((Date.parse(g.expires_at) - now) / DAY)) : null, approved_by: g.approved_by, request_id: g.request_id, previous_grant_id: g.previous_grant_id, revoked_by: g.revoked_by || null };
}
function view(req, warnings = [], question) {
  const d = req.decision || {};
  const pending = (req.approvals || []).filter((a) => a.decision === "pending");
  const g = req.grant_id ? store.load().grants.find((x) => x.grant_id === req.grant_id) : null;
  const next = { received: "Processing.", needs_clarification: question || req.clarification, denied: `Not allowed: ${(d.denials || []).join(" ")}`, pending_approval: `Waiting for ${pending.map((a) => `${(person(a.approver) || {}).name} (${a.step.replace("_", " ")})`).join(" and ")}. Nobody needs to chase them: they see it in their approvals inbox.`,
    approved: "Approved; granting now.", granted: g ? `Granted ${label(g.app, g.role)} until ${g.expires_at.slice(0, 10)}. It is removed automatically then, or revoke it any time with ${g.grant_id}.` : "Granted.", rejected: "Rejected by the approver.", failed: `Not granted: ${req.failure}` }[req.status];
  return { request_id: req.request_id, requester: pub(person(req.requester)), status: req.status, text: req.text, access: req.app ? label(req.app, req.role) : null, app: req.app || null, role: req.role || null,
    proposal: req.proposal || null, policy: req.decision ? { tier: d.tier, tier_name: d.tier_name, duration_days: d.duration_days, reasons: d.reasons, denials: d.denials } : null,
    approvals: (req.approvals || []).map((a) => ({ step: a.step, approver: pub(person(a.approver)), decision: a.decision, at: a.at, comment: a.comment })),
    injection_signals: req.injection_signals || [], grant: g ? grantView(g) : null, created_at: req.created_at, next_step: next, warnings };
}

// ---------------- demo controls (web demo only, audited) ----------------
function advanceClock(actor, days) {
  const s = store.load(); s.clock_offset_ms += Math.round(days * DAY); store.save();
  store.append("demo_clock_advanced", actor || "demo", { days, note: "Demo only: simulated time moved forward to show expiry." });
  sweepExpired();
  return { now: new Date(store.now()).toISOString() };
}

module.exports = { requestAccess, approveRequest, grantAccess, revokeAccess, checkPolicy, viewAuditLog, listRequests, listCatalog, sweepExpired, advanceClock, ToolError, view, grantView };
