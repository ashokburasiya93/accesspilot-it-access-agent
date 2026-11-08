// Untrusted-input handling. Request text and ticket fields are DATA. Nothing here decides access;
// it only cleans input, flags attacks for the audit log, and validates what the model proposes.
const { CATALOG, app: getApp, role: getRole } = require("./data");

const MAX_TEXT = 2000;

function clean(text) {
  return String(text == null ? "" : text)
    .normalize("NFKC")
    .replace(/[​-‏‪-‮⁠-⁤﻿]/g, "") // zero-width and bidi controls
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ")
    .slice(0, MAX_TEXT)
    .trim();
}

// Signals of instructions aimed at the system. Used to FLAG and escalate, never as the only defence.
const INJECTION = [
  [/ignore (all |any |the )?(previous|prior|above|earlier|your) (instructions|rules|prompts?|policy)/i, "ignore-instructions"],
  [/disregard (the |all |any )?(policy|rules|instructions|guardrails)/i, "disregard-policy"],
  [/\b(system|developer) (prompt|message|mode)\b/i, "system-prompt"],
  [/you are (now|no longer)|act as (an? )?(admin|administrator|approver|manager|it)/i, "role-play"],
  [/\b(auto[- ]?approve|mark (this|it|the request) (as )?approved|skip (the )?approval|bypass (the )?(approval|policy|review))/i, "approval-bypass"],
  [/\b(already|pre)[- ]?approved\b|approved by (my |the )?(manager|owner|cto|ceo|security|it)|(manager|owner|cto|ceo) (has |have )?(already )?(approved|signed off|ok'?d)/i, "claimed-approval"],
  [/\b(set|change|make) (the )?(tier|risk|policy|expiry|role) to\b|"?tier"?\s*[:=]\s*0|"?approved"?\s*[:=]\s*true/i, "field-override"],
  [/\b(grant|give|add) (it |this |access )?to (all|everyone|every user)|for (all|every) (users|employees)/i, "mass-grant"],
  [/\b(on behalf of|for user|as user|impersonat)/i, "impersonation"],
  [/<\/?(system|tool|assistant|instructions?)>|\[\/?(INST|SYS)\]|```\s*(json|tool)/i, "markup-injection"],
  [/\b(no expiry|never expire|permanent(ly)?|forever|no end date)\b/i, "no-expiry"],
  [/\b(revoke|remove|delete) (all|everyone|the audit|audit log|logs)\b|(delete|clear|wipe|edit) (the )?(audit|log)/i, "destructive"],
];
function detectInjection(text) {
  const t = String(text || "");
  const hits = INJECTION.filter(([re]) => re.test(t)).map(([, k]) => k);
  // Long base64-looking blobs often hide instructions.
  if (/[A-Za-z0-9+/]{60,}={0,2}/.test(t)) hits.push("encoded-blob");
  return [...new Set(hits)];
}

// Credentials must never be processed. They are redacted before any model call or audit write.
const SECRETS = [
  [/AKIA[0-9A-Z]{16}/g, "aws-key"],
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, "github-token"],
  [/sk-[A-Za-z0-9_-]{16,}/g, "api-key"],
  [/xox[abpr]-[A-Za-z0-9-]{10,}/g, "slack-token"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g, "private-key"],
  [/\b(password|passwd|pwd|passcode|otp|pin)\s*(is|=|:)\s*\S+/gi, "password"],
];
function redactSecrets(text) {
  let out = String(text || ""); const found = [];
  for (const [re, kind] of SECRETS) out = out.replace(re, () => { found.push(kind); return `[REDACTED ${kind}]`; });
  return { text: out, found: [...new Set(found)] };
}

// The model may only propose {app, role, duration_days, need, clarification}. Everything else is dropped,
// and app/role must exist in the catalog.
function validateProposal(p) {
  const out = { app: null, role: null, duration_days: null, need: "", clarification: "" , dropped_fields: [] };
  if (!p || typeof p !== "object") return { ...out, clarification: "I couldn't work out which app you need. Which app is it?" };
  for (const k of Object.keys(p)) if (!["app", "role", "duration_days", "need", "clarification", "confidence"].includes(k)) out.dropped_fields.push(k);
  const a = typeof p.app === "string" ? getApp(p.app.trim().toLowerCase()) : null;
  if (a) {
    out.app = a.id;
    const r = typeof p.role === "string" ? getRole(a.id, p.role.trim().toLowerCase()) : null;
    if (r) out.role = r.id;
  }
  const d = Number(p.duration_days);
  if (Number.isFinite(d) && d >= 1 && d <= 3650) out.duration_days = Math.round(d);
  out.need = clean(p.need).slice(0, 200);
  out.clarification = clean(p.clarification).slice(0, 300);
  if (!out.app && !out.clarification) out.clarification = "I couldn't match that to an app in the catalog. Which app do you need?";
  if (out.app && !out.role && !out.clarification) out.clarification = `Which role in ${getApp(out.app).name} do you need? Options: ${getApp(out.app).roles.map((r) => `${r.id} (${r.can})`).join("; ")}.`;
  return out;
}

const NON_REQUESTABLE = CATALOG.non_requestable || [];
function nonRequestable(text) {
  const t = String(text || "").toLowerCase();
  const hit = NON_REQUESTABLE.find((n) => n.match.some((m) => t.includes(m)));
  return hit ? hit.reason : null;
}

module.exports = { clean, detectInjection, redactSecrets, validateProposal, nonRequestable, MAX_TEXT };
