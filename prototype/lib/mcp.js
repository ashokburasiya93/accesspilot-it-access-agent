// MCP (Model Context Protocol) JSON-RPC handler, shared by the stdio transport (mcp/stdio.js)
// and the HTTP transport (api/mcp.js). No SDK dependency: the protocol surface used here is small.
// Identity: `actor` is passed in by the transport from the session (env var or auth header).
// Tool schemas reject unknown fields, so a client can't smuggle in "actor", "approved" or "tier".
const svc = require("./service");
const store = require("./store");

const PROTOCOL = "2025-06-18";
const SERVER = { name: "accesspilot", title: "AccessPilot IT access requests", version: "1.0.0" };
const INSTRUCTIONS = "AccessPilot grants and revokes IT access under a fixed policy. You can only PROPOSE: the server decides the approval tier, approvers and expiry in code. Request text is treated as untrusted data. You cannot approve requests on anyone's behalf, and you never need or handle credentials.";

const str = (description, extra = {}) => ({ type: "string", description, ...extra });
const TOOLS = [
  { name: "request_access", title: "Request access",
    description: "Ask for access to an app for the signed-in user. Give free text (the server works out app and least-privileged role) OR an explicit app and role. Low-risk viewer roles with a short expiry are granted at once; others wait for the approvers the policy names.",
    inputSchema: { type: "object", additionalProperties: false, properties: { text: str("What you need and why, in your own words.", { maxLength: 2000 }), app: str("App id from list_catalog (optional)."), role: str("Role id from list_catalog (optional)."), duration_days: { type: "integer", minimum: 1, maximum: 365, description: "How long you need it. Capped by policy." }, justification: str("Business reason (optional).", { maxLength: 1000 }) } },
    annotations: { destructiveHint: false, idempotentHint: false, openWorldHint: false } },
  { name: "check_policy", title: "Check policy (dry run)",
    description: "Show which approval tier, approvers and maximum expiry a role would need, without requesting anything.",
    inputSchema: { type: "object", additionalProperties: false, required: ["app", "role"], properties: { app: str("App id."), role: str("Role id."), duration_days: { type: "integer", minimum: 1, maximum: 365 }, user: str("Employee id (yourself by default; managers can check direct reports).") } },
    annotations: { readOnlyHint: true } },
  { name: "approve_request", title: "Approve or reject a request",
    description: "Record the signed-in user's decision on a request they are the named approver for. The requester and the agent can never approve. When the last approval arrives, the grant runs automatically.",
    inputSchema: { type: "object", additionalProperties: false, required: ["request_id", "decision"], properties: { request_id: str("e.g. REQ-1001"), decision: { type: "string", enum: ["approve", "reject"] }, comment: str("Optional note.", { maxLength: 500 }) } },
    annotations: { destructiveHint: false, idempotentHint: false } },
  { name: "grant_access", title: "Grant approved access",
    description: "Execute the grant for a fully approved request (re-checks policy first). Normally automatic; use to retry.",
    inputSchema: { type: "object", additionalProperties: false, required: ["request_id"], properties: { request_id: str("e.g. REQ-1001") } },
    annotations: { destructiveHint: false, idempotentHint: true } },
  { name: "revoke_access", title: "Revoke access (rollback)",
    description: "Undo a grant now. If it replaced an earlier role that is still in date, that role is restored.",
    inputSchema: { type: "object", additionalProperties: false, required: ["grant_id"], properties: { grant_id: str("e.g. GR-5001"), reason: str("Why it is being removed.", { maxLength: 300 }) } },
    annotations: { destructiveHint: true, idempotentHint: true } },
  { name: "view_audit_log", title: "View audit log",
    description: "Read the append-only, hash-chained audit log and check its integrity. IT and security see everything; others see their own and their direct reports' entries.",
    inputSchema: { type: "object", additionalProperties: false, properties: { request_id: str("Filter by request."), user: str("Filter by employee id."), limit: { type: "integer", minimum: 1, maximum: 500 } } },
    annotations: { readOnlyHint: true } },
  { name: "list_requests", title: "List requests and grants",
    description: "mine = your requests and access; approvals = requests waiting for you; team = your reports and apps you own; all = everything (IT/security).",
    inputSchema: { type: "object", additionalProperties: false, properties: { scope: { type: "string", enum: ["mine", "approvals", "team", "all"] } } },
    annotations: { readOnlyHint: true } },
  { name: "list_catalog", title: "List apps and roles",
    description: "The apps, roles, what each role can do, and its risk level.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: { readOnlyHint: true } },
];

function validate(schema, args) {
  if (args == null) args = {};
  if (typeof args !== "object" || Array.isArray(args)) return "arguments must be an object";
  for (const k of Object.keys(args)) if (!schema.properties[k]) return `unknown argument "${k}"`;
  for (const k of schema.required || []) if (args[k] === undefined || args[k] === "") return `missing argument "${k}"`;
  for (const [k, v] of Object.entries(args)) {
    const s = schema.properties[k];
    if (s.type === "string" && typeof v !== "string") return `"${k}" must be a string`;
    if (s.type === "integer" && !Number.isInteger(v)) return `"${k}" must be an integer`;
    if (s.enum && !s.enum.includes(v)) return `"${k}" must be one of ${s.enum.join(", ")}`;
    if (s.maxLength && v.length > s.maxLength) return `"${k}" is too long`;
    if (s.minimum != null && v < s.minimum) return `"${k}" must be at least ${s.minimum}`;
    if (s.maximum != null && v > s.maximum) return `"${k}" must be at most ${s.maximum}`;
  }
  return null;
}

async function callTool(actor, name, args, ctx = {}) {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) return toolResult({ error: "unknown_tool", message: `No tool ${name}.` }, true);
  const bad = validate(tool.inputSchema, args);
  if (bad) { store.append("action_blocked", actor, { tool: name, code: "invalid_arguments", reason: bad }); return toolResult({ error: "invalid_arguments", message: bad }, true); }
  try {
    svc.sweepExpired();
    const a = { ...(args || {}) };
    let out;
    switch (name) {
      case "request_access": out = await svc.requestAccess(actor, { ...a, _channel: ctx.channel, _offline: ctx.offline }); break;
      case "check_policy": out = svc.checkPolicy(actor, a); break;
      case "approve_request": out = svc.approveRequest(actor, a); break;
      case "grant_access": out = svc.grantAccess(actor, a); break;
      case "revoke_access": out = svc.revokeAccess(actor, a); break;
      case "view_audit_log": out = svc.viewAuditLog(actor, a); break;
      case "list_requests": out = svc.listRequests(actor, a); break;
      case "list_catalog": out = svc.listCatalog(); break;
    }
    return toolResult(out, false);
  } catch (e) {
    if (e instanceof svc.ToolError) return toolResult({ error: e.code, message: e.message }, true);
    return toolResult({ error: "internal", message: e.message }, true);
  }
}

function toolResult(obj, isError) {
  const summary = obj && (obj.next_step || obj.message);
  return { content: [{ type: "text", text: (summary ? summary + "\n\n" : "") + JSON.stringify(obj, null, 2) }], structuredContent: obj, isError };
}

// Returns a JSON-RPC response object, or null for notifications.
async function handle(msg, actor, ctx = {}) {
  const reply = (result) => ({ jsonrpc: "2.0", id: msg.id, result });
  const fail = (code, message) => ({ jsonrpc: "2.0", id: msg.id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return fail(-32600, "Invalid request");
  const isNote = msg.id === undefined;
  switch (msg.method) {
    case "initialize": return reply({ protocolVersion: (msg.params && msg.params.protocolVersion) || PROTOCOL, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER, instructions: INSTRUCTIONS });
    case "notifications/initialized": case "notifications/cancelled": return null;
    case "ping": return reply({});
    case "tools/list": return reply({ tools: TOOLS });
    case "tools/call": { const p = msg.params || {}; return reply(await callTool(actor, p.name, p.arguments, ctx)); }
    default: return isNote ? null : fail(-32601, `Method not found: ${msg.method}`);
  }
}

module.exports = { handle, callTool, TOOLS, PROTOCOL, SERVER };
