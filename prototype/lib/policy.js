// The access policy, enforced in code. The model never sets the tier, the approvers or the expiry.
// evaluate() is pure: same inputs, same decision. It is called at request time AND again right before any write.
const { POLICY, DIRECTORY, person, app, role } = require("./data");
const DAY = 86400000;

const TIER_NAMES = { 0: POLICY.tiers["0"].name, 1: POLICY.tiers["1"].name, 2: POLICY.tiers["2"].name };

/**
 * @param {object} req   { user, app, role, duration_days?, injection_suspected? }
 * @param {object} ctx   { grants: active grants array, now: ms }
 * @returns decision     { allowed, tier, tier_name, approvals:[{step,approver,why}], duration_days, expires_at, reasons[], denials[] }
 */
function evaluate(req, ctx) {
  const reasons = [], denials = [];
  const u = person(req.user), a = app(req.app), r = role(req.app, req.role);
  const now = ctx.now;
  if (!u) denials.push(`Unknown requester "${req.user}".`);
  else if (!u.active) denials.push(`${u.name} is not an active employee.`);
  if (!a) denials.push(`"${req.app}" is not an app in the access catalog.`);
  else if (!r) denials.push(`"${req.role}" is not a role in ${a.name}. Roles: ${a.roles.map((x) => x.id).join(", ")}.`);
  if (denials.length) return deny(denials);

  // Contractors never get sensitive-data or admin roles.
  if (u.type === "contractor" && ((POLICY.contractor_blocked.sensitive_data && r.sensitive_data) || (POLICY.contractor_blocked.admin && r.risk === "admin")))
    denials.push(`Contractors can't hold ${r.sensitive_data ? "sensitive-data" : "admin"} roles such as ${a.name} ${r.name}.`);

  const active = (ctx.grants || []).filter((g) => g.user === u.id && g.status === "active");
  if (active.some((g) => g.app === a.id && g.role === r.id)) denials.push(`${u.name} already has ${a.name} ${r.name}.`);

  // Segregation of duties.
  for (const c of r.conflicts_with || []) {
    const [ca, cr] = c.split(":");
    if (active.some((g) => g.app === ca && g.role === cr)) denials.push(`Segregation of duties: ${a.name} ${r.name} can't be held together with ${role(ca, cr).name}.`);
  }
  if (denials.length) return deny(denials);

  // Expiry: every grant gets one. Missing -> role default; too long -> clamped to the role maximum.
  let days = Number.isInteger(req.duration_days) && req.duration_days > 0 ? req.duration_days : null;
  if (days == null) { days = r.default_days; reasons.push(`No end date given, so the role default of ${days} day${days === 1 ? "" : "s"} applies.`); }
  const max = Math.min(r.max_days, POLICY.absolute_max_days);
  if (days > max) { reasons.push(`Asked for ${days} days; ${a.name} ${r.name} is capped at ${max} days.`); days = max; }

  // Tier.
  let tier = { low: 0, standard: 1, admin: 2 }[r.risk];
  if (r.risk === "admin") reasons.push(`${r.name} is an admin role.`);
  if (r.sensitive_data) { tier = 2; reasons.push(`${a.name} ${r.name} can read sensitive data.`); }
  const minTier = POLICY.data_class_min_tier[a.data_class] || 0;
  if (tier < minTier) { tier = minTier; reasons.push(`${a.name} is a ${a.data_class} system.`); }
  if (tier === 0 && days > POLICY.auto_approve_max_days) { tier = 1; reasons.push(`Auto-approval needs an expiry within ${POLICY.auto_approve_max_days} days.`); }
  if (req.injection_suspected && tier < POLICY.injection_min_tier) { tier = POLICY.injection_min_tier; reasons.push("The request text contained instructions aimed at the system, so a person must review it."); }
  if (tier === 0) reasons.push(`Low-risk ${r.name} role with a ${days}-day expiry.`);

  // Approvers. Never the requester; distinct people for each step.
  const approvals = [];
  const used = new Set([u.id]);
  const pick = (candidates) => candidates.find((c) => c && !used.has(c) && person(c) && person(c).active);
  if (tier >= 1) {
    const m = pick([u.manager, DIRECTORY.fallback_approver]);
    approvals.push({ step: "manager", approver: m, why: m === u.manager ? "Line manager" : "Fallback approver (no eligible manager)" }); used.add(m);
  }
  if (tier >= 2) {
    const o = pick([a.owner, a.backup_owner, DIRECTORY.fallback_approver]);
    approvals.push({ step: "app_owner", approver: o, why: o === a.owner ? `Owner of ${a.name}` : `Backup owner of ${a.name}` }); used.add(o);
  }
  return { allowed: true, tier, tier_name: TIER_NAMES[tier], approvals, duration_days: days, expires_at: new Date(now + days * DAY).toISOString(), reasons, denials: [] };
}

function deny(denials) { return { allowed: false, tier: null, tier_name: "Denied", approvals: [], duration_days: null, expires_at: null, reasons: [], denials }; }

module.exports = { evaluate, TIER_NAMES, DAY };
