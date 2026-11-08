// Who is calling. DEMO ONLY: the web demo sends the persona picked in the header switcher as X-AccessPilot-User.
// In production this is replaced by the identity in a verified SSO/OAuth token. Tool arguments never set it.
const { person } = require("../lib/data");
function actorFrom(req) {
  const h = (req.headers["x-accesspilot-user"] || "").toString().trim().toLowerCase();
  return person(h) ? h : null;
}
module.exports = { actorFrom };
