# AccessPilot: an IT access-request agent that acts on approval

AccessPilot turns a plain-language access request into the right app and least-privileged role, applies an approval policy enforced in code, grants on approval with an expiry, revokes in one click with rollback, and records every step in an append-only, hash-chained audit log. Its tools are published as an **MCP server**, so any MCP client gets the same tools and the same guardrails.

> **All company data is synthetic.** Kestrel Fintech, its people and every number about it are made up for an AI PM course project. The 30–40% share of service desk volume is a vendor figure quoted in the problem statement.

- **Live app:** https://accesspilot-it-access-agent.vercel.app (no sign-in; pick a persona in the header)
- **Miro opportunity board:** https://miro.com/app/board/uXjVEQ8_0Rg=/
- **Problem statement:** [PROBLEM_STATEMENT.md](PROBLEM_STATEMENT.md)

## Deliverables in this repo

| # | Deliverable | File |
|---|---|---|
| 1 | Problem discovery and user research | [deliverables/1. Problem Discovery - AccessPilot.xlsx](deliverables/) |
| 2 | AI opportunity map (Excel + Miro import CSV) | [deliverables/2. AI Opportunity Map - AccessPilot.xlsx](deliverables/) |
| 3 | AI PRD with North Star & Metrics | [deliverables/3. AI PRD - AccessPilot.docx](deliverables/) |
| 4 | Cost estimation | [deliverables/4. Cost Estimation - AccessPilot.xlsx](deliverables/) |
| 5 | Working prototype + README | [prototype/](prototype/) |
| 6 | Presentation | [deliverables/6. Presentation - AccessPilot.pptx](deliverables/) |

## Results at a glance

- Red team: **32/32 attacks blocked, 0 unauthorized writes** (prompt injection, claimed approvals, self- and agent-approval, smuggled fields, SoD, contractor PII…).
- Live model (Groq `openai/gpt-oss-120b`): **100%** app and least-privilege role on 30 dev + 20 held-out requests; 0% over-provisioned.
- **100%** of grants carry an expiry and an audit record; edits and deletions of the log are detected.
- Model cost about **$0.21 a month** at 1,100 requests; about $60 a month all-in.

## Run the prototype

```bash
cd prototype
npm test        # safety gates and evals, no API calls
npm run dev     # web demo on http://localhost:3000
```

See [prototype/README.md](prototype/README.md) for the MCP setup, the policy, the threat model and the full eval results. API keys live only in environment variables (Vercel), never in this repo.
