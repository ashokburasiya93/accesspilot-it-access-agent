**Working title: AccessPilot, an IT access-request agent that acts on approval (published as an MCP server)**

**Problem statement**
Employees ask for access to apps, shared drives and repos through Slack messages, emails and tickets. IT then has to work out the right role, find the right approver, chase the approval and grant the access by hand. Access requests are a large share of service desk work: one vendor puts them at 30–40% of volume for most IT teams. Employees wait days to get the access they need. Access is often granted at the wrong level, because most users do not know whether they need "Editor" or "Viewer." It is also rarely removed afterwards, because access deprovisioning fails most often because it is separate from granting. A read-only chatbot can explain the access policy, but the waiting, the errors and the access nobody removes all come from manual steps.

**Who it's for**
- **Primary:** employees who need access, and IT service desk analysts.
- **Secondary:** managers and app owners who approve requests.
- **Also:** security and audit teams, who need evidence of who approved what and when.

**Current state**
1. The request arrives through a free-text message.
2. An analyst works out which app and role are meant.
3. The analyst finds the approver and chases them by email.
4. The analyst grants the access by hand in the identity system or the app.
5. The ticket is closed with no expiry date and only a partial record of the approval.

**Pain points**
- Employees can't do their work while they wait for access.
- Analysts spend their time on repetitive, low-skill tickets.
- Users are over-provisioned, and access that should expire never does.
- Audits are weak because approvals sit in email threads.

**Why the agent must write, and why that's risky**
The value only comes once the agent can grant and revoke access itself. That is also where the risk sits. OWASP lists prompt injection as the top LLM risk, and it expanded Excessive Agency because unchecked permissions can lead to unintended or risky actions. OWASP also acknowledges that no fool-proof prevention for prompt injection is known. So safety can't depend on the model refusing bad instructions. It has to be built into the design:

- **Approval tiers:** low-risk viewer roles with an expiry date are auto-approved; standard roles need the manager; admin or sensitive-data roles need the manager plus the app owner. Policy is enforced in code, not by the model.
- **Rollback:** every grant has an expiry date and a one-click revoke action that undoes it.
- **Audit log:** an append-only record of each request, policy decision, approver, action and result.
- **Threat model:** request text and ticket content are treated as untrusted data. The model can only propose an action; the server checks it against policy before anything is written. The agent can never approve its own request, and it never touches credentials.
- **MCP server:** the tools (request, check policy, grant, revoke, view audit log) are published as an MCP server, so any MCP client can use them and the same guardrails apply everywhere.

**Job to be done**
"When I need access to do my job, get me exactly the right access quickly, without me having to know the role name or chase anyone, and remove it when I no longer need it."

**How we'll know it worked**
- **North Star:** correctly scoped grants delivered without an IT analyst touching them.
- **Illustrative targets:**
  - Median time to access from about 2 days to under 1 hour for standard apps.
  - 70% of requests handled end to end.
  - 100% of grants with an expiry date and an audit record.
- **Safety targets:** 0 unauthorized writes, and 100% of injection attacks blocked on the red-team eval set.
