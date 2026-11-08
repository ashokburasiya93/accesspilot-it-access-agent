// Loads the synthetic catalog, directory and policy once, and gives small lookup helpers.
const fs = require("fs"), path = require("path");
const DATA = path.join(__dirname, "..", "data");
const read = (f) => JSON.parse(fs.readFileSync(path.join(DATA, f), "utf8"));

const CATALOG = read("catalog.json");
const DIRECTORY = read("directory.json");
const POLICY = read("policy.json");

const person = (id) => DIRECTORY.people.find((p) => p.id === id) || null;
const app = (id) => CATALOG.apps.find((a) => a.id === id) || null;
const role = (appId, roleId) => { const a = app(appId); return (a && a.roles.find((r) => r.id === roleId)) || null; };
const inGroup = (id, g) => { const p = person(id); return !!(p && (p.groups || []).includes(g)); };
const isPrivileged = (id) => inGroup(id, "security") || inGroup(id, "it-admin");
const reports = (managerId) => DIRECTORY.people.filter((p) => p.manager === managerId).map((p) => p.id);

module.exports = { CATALOG, DIRECTORY, POLICY, person, app, role, inGroup, isPrivileged, reports, AGENT: DIRECTORY.agent_principal };
