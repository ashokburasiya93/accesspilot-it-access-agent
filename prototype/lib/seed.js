// SYNTHETIC starting state: a few existing grants so the demo has something to revoke and roll back.
const DAY = 86400000;
function seed(state, now) {
  const g = (id, user, app, role, grantedDaysAgo, expiresInDays, by) => ({
    grant_id: id, request_id: null, user, app, role, previous_grant_id: null,
    granted_at: new Date(now - grantedDaysAgo * DAY).toISOString(), expires_at: new Date(now + expiresInDays * DAY).toISOString(),
    status: "active", approved_by: by, source: "seed (synthetic, pre-AccessPilot)",
  });
  state.grants.push(
    g("GR-4001", "priya.sharma", "jira", "viewer", 20, 10, ["neha.kapoor"]),
    g("GR-4002", "priya.sharma", "wiki", "viewer", 5, 25, ["auto"]),
    g("GR-4003", "karan.singh", "github", "write", 60, 30, ["rahul.verma"]),
    g("GR-4004", "rohan.gupta", "payments", "creator", 40, 50, ["kavya.nair", "vikram.rao"]),
    g("GR-4005", "aisha.khan", "salesforce", "sales-user", 30, 2, ["meera.joshi", "vikram.rao"]),
    g("GR-4006", "dev.patel", "warehouse", "analyst", 10, 80, ["vikram.rao"]),
  );
}
module.exports = { seed };
