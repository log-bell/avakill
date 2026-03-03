# AvaKill Platform Deep Research Prompt

Copy-paste the prompt below into a deep research session.

---

## Prompt

I'm building a commercial SaaS platform on top of AvaKill, an open-source safety firewall for AI agents. The open-source core is shipped (v1.0.0, Python, AGPL-3.0, installable via `pipx install avakill`). I need you to research and produce a comprehensive technical architecture recommendation for the platform layer I'm building on top of it.

### What AvaKill Is Today

AvaKill intercepts AI agent tool calls, evaluates them against a YAML policy file in <1ms (deterministic, no ML, no API calls), and either allows, denies, or requires human approval. It has three independent enforcement paths:

1. **Hooks** — Direct integration into AI coding agents (Claude Code, Cursor, Windsurf, Gemini CLI, OpenAI Codex). These intercept tool calls before execution inside the agent process.
2. **MCP Proxy** — Transparent JSON-RPC proxy that sits between MCP clients and upstream MCP servers, evaluating every tool call in transit.
3. **OS Sandbox** — Launches agents inside kernel-level sandboxes (Linux Landlock, macOS sandbox-exec, eBPF/Tetragon, Windows AppContainer).

An optional daemon (Unix domain socket server) centralizes policy evaluation, audit logging (SQLite), rate limiting, approval queues, and Prometheus metrics across all three paths. The daemon is not required — each path works standalone.

The core includes:
- 81 pre-built safety rules across 27 categories
- Policy signing (HMAC + Ed25519) and integrity verification
- Shell analysis, path resolution, content scanning (secrets, prompt injection)
- Cross-call correlation and behavioral analysis
- Compliance assessment against SOC 2 Type II, NIST AI RMF, EU AI Act, ISO 42001
- Framework interceptors for OpenAI, Anthropic, and LangChain SDKs
- Self-protection rules that prevent agents from tampering with guardrails
- 2,108 passing tests, 63/63 red team attacks blocked

The current website is pure static HTML/CSS/JS — a marketing landing page, docs (generated from markdown), a rule catalog, and a dev dashboard (aiohttp + WebSocket, no auth). No SaaS layer exists.

### What I'm Building

I'm migrating the website into a Next.js application and building a full SaaS platform with three user surfaces:

**1. Internal Admin Panel (my team)**
- Business operations, project planning, team management
- Customer account management and support tooling
- System health, deployment status, infrastructure monitoring
- Content management for docs, blog, changelog
- Financial dashboards (revenue, churn, usage metrics)

**2. Developer/Membership Dashboards (self-serve customers)**
- Monthly subscription and/or usage-based billing tiers
- YAML policy management via web UI (create, edit, deploy, version)
- Real-time and historical analytics: tool calls intercepted, policies triggered, attacks blocked, latency distributions
- Agent activity feeds and audit logs
- Compliance reports (SOC 2, NIST, etc.) generated on demand
- API key management for programmatic access
- Team/org management with RBAC

**3. Enterprise Dashboards (dedicated/custom deployments)**
- Everything in the developer tier, plus:
- Custom subdomains (e.g., acme.avakill.com)
- Custom agent development — we build and deploy security-hardened agents for enterprise clients
- "Ava as an Agent" — a behind-the-scenes security agent that reduces blast radius when YAML policies are bypassed
- Dedicated telemetry collection and isolated data
- Advanced behavioral analytics and threat intelligence
- Custom compliance reporting and audit trails
- SLA monitoring and incident management
- SSO/SAML integration

**Key architectural requirements:**
- Multi-tenancy with strong data isolation (especially for enterprise)
- RBAC that scales from solo developer to enterprise org hierarchies
- High-volume telemetry ingestion (every tool call evaluation is a potential event)
- Real-time dashboards (WebSocket or SSE for live event streams)
- The open-source CLI must remain fully functional without any platform dependency
- Opt-in telemetry: users who link their account get dashboards; enterprise gets dedicated collection
- The platform must be extensible — we don't fully know all the products yet, so the foundation must support adding new agent services, new enforcement paths, and new data products without rearchitecting

### What I Need You To Research

Research the current state of the art (as of February 2026) across all of the following areas and produce a unified architecture recommendation. For each area, I want:
- Your recommended approach with specific technologies/services
- Why you recommend it over alternatives
- How it integrates with the other pieces
- What to avoid and why
- Cost considerations at different scales (startup → growth → enterprise)

**1. Application Framework & Frontend**
- Next.js version, App Router patterns, and project structure for a platform of this scope
- Component library (shadcn/ui, Radix, etc.) — what's the current best practice?
- State management for real-time dashboards
- How to structure the migration from static HTML while preserving the current site's performance on marketing pages
- Monorepo structure (turborepo, nx, or similar) if the platform spans multiple packages

**2. Backend & API Layer**
- Should the API layer be Next.js API routes, a separate service (FastAPI, Express, Go), or a hybrid?
- GraphQL vs REST vs tRPC for different use cases (admin CRUD vs high-volume telemetry vs real-time)
- How to bridge the existing Python core (Guard, PolicyEngine, daemon) with the platform's API layer
- Background job processing (policy deployments, compliance report generation, billing events)

**3. Database Architecture**
- Primary datastore for relational data (users, orgs, policies, billing) — Postgres, PlanetScale, CockroachDB, Neon, etc.
- Time-series / analytics store for high-volume telemetry (ClickHouse, TimescaleDB, Tinybird, etc.)
- How to handle multi-tenant data isolation (schema-per-tenant, row-level security, separate databases for enterprise)
- Caching layer (Redis, Upstash, Dragonfly)
- Search (if needed for audit log querying, policy search, etc.)

**4. Authentication & Authorization**
- Auth provider: NextAuth/Auth.js, Clerk, WorkOS, Auth0, Supabase Auth, or custom
- RBAC implementation that scales from solo dev to enterprise org hierarchies
- SSO/SAML for enterprise customers
- API key management and scoping
- How admin auth should differ from customer auth
- Session management and token strategy

**5. Multi-Tenancy**
- Tenant isolation architecture
- Custom subdomain routing and configuration
- Data partitioning strategy
- Tenant-aware middleware patterns
- How to handle enterprise vs self-serve tenants differently at the infrastructure level

**6. Telemetry & Analytics Pipeline**
- How the open-source CLI should send telemetry to the platform (opt-in, protocol, batching, retry)
- Ingestion pipeline for high-volume events (thousands of tool call evaluations per second across all tenants)
- Real-time processing for live dashboards
- Aggregation and rollup strategies for historical analytics
- Data retention policies per tier

**7. Real-Time Infrastructure**
- WebSocket vs SSE vs other approaches for live dashboards
- How to fan out real-time events to the right tenant/user
- Connection management at scale
- What infrastructure this requires (Redis Pub/Sub, Ably, Pusher, custom)

**8. Billing & Subscriptions**
- Stripe integration patterns for hybrid billing (monthly subscription + usage-based metering)
- How to meter usage (what counts as a billable event?)
- Webhook handling, idempotency, failure recovery
- Free tier / trial mechanics
- Enterprise contract billing (invoicing, custom pricing)

**9. Deployment & Infrastructure**
- Hosting: Vercel, AWS, Fly.io, Railway, or hybrid
- How to deploy the Next.js app, the Python backend services, and the telemetry pipeline
- CI/CD pipeline design
- Environment strategy (preview deployments, staging, production)
- Observability: logging, tracing, error tracking, uptime monitoring
- How to handle enterprise custom subdomains at the infrastructure level (wildcard DNS, reverse proxy, SSL)

**10. Security**
- We're a security product — our own platform security must be best-in-class
- Secrets management
- Supply chain security
- Penetration testing considerations
- Data encryption (at rest, in transit, per-tenant encryption keys for enterprise)
- Audit logging for the platform itself (who changed what, when)
- SOC 2 compliance for the platform (not just the policies we evaluate)

**11. Developer Experience & Extensibility**
- API design for third-party integrations
- Webhook system for customers to receive events
- SDK/client library strategy
- Plugin architecture for future agent services
- Documentation platform (API docs, guides, changelog)

### Output Format

Produce a single cohesive architecture document that:

1. Opens with a one-page executive summary of the recommended stack
2. Covers each area above with specific technology choices, rationale, and integration points
3. Includes a data flow diagram showing how events move from the open-source CLI → telemetry pipeline → storage → dashboards
4. Includes a system architecture diagram showing all services and how they connect
5. Identifies the critical path — what must be built first and what can be deferred
6. Flags risks, unknowns, and decisions that need more information
7. Provides a rough cost model at three scales: launch (0-1K users), growth (1K-50K users), enterprise (50K+ users with dedicated deployments)
8. Recommends what to build vs buy vs use open-source for each component

Do not give me generic advice. Give me specific, opinionated recommendations based on the current state of these technologies as of February 2026. Name exact versions, services, and libraries. If something has emerged as a clear winner in its category, say so. If there are genuine trade-offs, present the top 2 options with a clear recommendation.
