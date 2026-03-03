# Platform Architecture Research

# AvaKill SaaS platform: production architecture blueprint

**The optimal architecture for AvaKill combines Next.js 16.1 on Vercel with a Hono telemetry service, Neon Postgres with row-level security, ClickHouse for analytics, and Clerk for auth — all wired through gRPC and NATS to the existing Python AGPL core.** This stack starts at roughly **$200–600/month** for launch, scales to $3,500/month at 50K users, and reaches $15,000+/month at enterprise scale — while maintaining a clean upgrade path from shared multi-tenancy to physical isolation. The critical insight: a small AI-assisted team should buy everything except the core safety engine and the platform UX. Every recommendation below reflects the state of the art as of early 2026, with specific versions, exact pricing, and opinionated rationale.

---

## Area 1: Application framework and frontend

### Next.js 16.1 with Turbopack is the foundation

**Next.js 16.1** (released December 18, 2025) ships with Turbopack as the default bundler for both dev and production builds, delivering **2–5× faster production builds** and up to 10× faster Fast Refresh. The key architectural shift is **Cache Components** using the `"use cache"` directive — replacing the old experimental PPR flag with explicit, opt-in caching. All dynamic code runs at request time by default. The `proxy.ts` file replaces `middleware.ts` (now deprecated), running on Node.js rather than Edge runtime. React 19.2 comes bundled, bringing View Transitions, `useEffectEvent()`, and the `<Activity/>` component. The React Compiler is stable and built-in via `reactCompiler: true`.

For AvaKill's four surfaces (marketing site, admin dashboard, developer dashboard, enterprise dashboard), use a **monorepo with separate Next.js apps per surface** connected through shared packages. This beats a single mega-app because each surface has different rendering strategies — SSG for marketing, dynamic/SSR for dashboards — and can be deployed independently. Route groups within each app handle sub-navigation.

**Component library: shadcn/ui v3.5+ with Base UI primitives.** shadcn/ui now has **107,000+ GitHub stars** and supports both Radix UI and Base UI as headless primitive layers. The critical development: Radix UI's maintenance has significantly slowed (the original co-creator called it a "liability"), while **Base UI v1.0** (December 2025), built by the same people who created Radix and Material UI, has emerged as the preferred primitive layer. For new projects, choose Base UI at initialization. Add **Tremor** for dashboard charts and KPIs, and **Kibo UI** from the shadcn registry for advanced data tables.

**State management: TanStack Query v5 + Zustand v5 + nuqs.** This is the 2026 community default. TanStack Query handles all server/async state with built-in WebSocket/SSE integration via `queryClient.setQueryData`. Zustand v5 (~1KB) manages UI-only state — sidebar toggles, active filters, modal state. nuqs provides type-safe URL state for shareable dashboard views. **Avoid Recoil** (archived by Meta in early 2025) and Redux for server state.

**Monorepo: Turborepo 2.7+ with pnpm 9.x workspaces.** For fewer than 15 packages and a small team, Turborepo is **3× faster** than Nx on small monorepos with dramatically less configuration (~20 lines vs 200+). Turborepo's composable configuration, Rust-powered hashing, `--affected` flag, and native Vercel remote caching make it the clear winner. Only evaluate Nx if you scale past 50 packages or 10+ developers.

Recommended monorepo structure:
```
avakill/
├── apps/
│   ├── marketing/           # SSG marketing site
│   ├── admin-dashboard/     # Internal admin
│   ├── developer-dashboard/ # Developer portal
│   └── enterprise-dashboard/# Enterprise client
├── packages/
│   ├── ui/                  # Shared shadcn/ui components
│   ├── config-tailwind/     # Shared Tailwind v4 config
│   ├── auth/                # Shared auth logic (Clerk)
│   ├── api-client/          # Shared tRPC/TanStack Query hooks
│   └── types/               # Shared TypeScript types
├── turbo.json
└── pnpm-workspace.yaml
```

**Marketing site migration**: Use Static Site Generation for all marketing pages with Incremental Static Regeneration for blog/changelog. Audit all existing URLs and set up 301 redirects in `next.config.ts`. Use `generateMetadata()` for SEO. Marketing pages via Turbopack + CDN will match or exceed the performance of the static HTML site. The #1 migration risk is losing SEO equity from broken URLs.

| Component | Choice | Version |
|-----------|--------|---------|
| Framework | Next.js | 16.1 |
| React | React | 19.2 |
| Bundler | Turbopack | Stable (default) |
| Styling | Tailwind CSS | 4.x |
| Components | shadcn/ui + Base UI | v3.5+ / v1.0 |
| Server state | TanStack Query | v5 |
| Client state | Zustand | v5 |
| URL state | nuqs | Latest |
| Monorepo | Turborepo + pnpm | 2.7+ / 9.x |

---

## Area 2: Backend and API layer

### A hybrid architecture avoids serverless bottlenecks

The API layer should split into two services: **Next.js Route Handlers as a Backend-for-Frontend** (BFF) for dashboard operations, and **Hono v4.x as a dedicated telemetry ingestion service**. Next.js handles admin CRUD, auth, webhooks, and dashboard SSR. Hono handles high-volume telemetry ingestion and serves as the public developer API.

Hono is the 2025-2026 standout framework: ultrafast (~402K ops/sec on Workers benchmarks), **<14KB minified**, built on Web Standards (Fetch API/WinterCG), and runs on Node.js, Bun, Cloudflare Workers, Deno, and AWS Lambda. It has built-in RPC-style type-safe clients, Zod validation, and OpenAPI generation via `@hono/zod-openapi`. Do not put high-throughput telemetry through Next.js API routes — serverless cold starts, Vercel timeout limits, and connection pooling issues make this a non-starter at scale.

**API protocol: use three protocols, each optimized for its consumer.**

- **tRPC v11** for internal frontend-to-backend: end-to-end TypeScript type safety, SSE-based subscriptions (new in v11, eliminates WebSocket complexity), native React Server Component integration, and TanStack Query v5 pairing. Use for all dashboard data.
- **REST + OpenAPI 3.1** for public developer API: universal compatibility, CDN cacheability, and auto-generated SDKs. Hono's `@hono/zod-openapi` generates the spec from Zod schemas.
- **gRPC** for Python-TypeScript bridge: binary Protobuf serialization with ~60-80% bandwidth savings vs JSON, **p50 latency ~4ms** vs REST's ~12ms, and strongly typed `.proto` contracts shared between languages.

**Avoid GraphQL** for this product. It adds schema definitions, resolver complexity, N+1 problems, and query cost analysis overhead without sufficient benefit. REST's CDN cacheability saves money at scale.

### Python-TypeScript bridge: gRPC + NATS JetStream

This is the most architecturally critical decision. The AGPL-3.0 Python core **must run as a separate process/container**, communicating only via network APIs (gRPC/NATS). This creates the legal boundary where the TypeScript platform layer is not a derivative work of the AGPL code. Never import Python AGPL code into the TypeScript process. Docker containerization reinforces this separation. Consult an IP attorney for your specific deployment model.

**gRPC** handles synchronous request-response (policy evaluation: "is this action allowed?" needs immediate answer). Use `@grpc/grpc-js` (Node.js) and `grpcio` (Python). **NATS JetStream** handles async event streaming — telemetry events flow from Hono → NATS → Python policy engine, and policy violations flow back through NATS to the TypeScript layer for dashboard SSE updates. NATS is a single Go binary (~20MB) with sub-millisecond latency, built-in persistence via JetStream, and official clients for both Python (`nats-py`) and TypeScript (`nats.js`).

Avoid Kafka at this stage (massive operational complexity), Redis Pub/Sub alone (no persistence), and subprocess calls (terrible for production — no connection pooling, process startup overhead, doesn't scale).

### Background jobs: Inngest for event-driven workflows

**Inngest** is the recommended choice for launch. It's an event-driven durable workflow engine where each `step.run()` is individually retryable. Key features: one-click Vercel Marketplace install, local development via `npx inngest-cli@latest dev`, TypeScript/Python/Go SDKs, and Apache 2.0 licensing (self-hostable). Free tier includes **100K executions/month** via Vercel Marketplace.

Add **Trigger.dev v4** for long-running tasks (compliance scans, AI processing, report generation). v4 shipped with Run Engine 2.0, warm starts (100-300ms), no timeout limits, and "Waitpoints" for human-in-the-loop approval flows. Self-hostable via official Helm chart.

Avoid Temporal (massive operational complexity requiring Cassandra/Postgres/Elasticsearch — overkill for a small team) and BullMQ (requires managing Redis, no built-in observability dashboard, no step-based retries).

| Scale | Backend cost |
|-------|-------------|
| Launch (0-1K) | Vercel Pro $20 + Hono on Fly.io $5-15 + Inngest free = **~$40/mo** |
| Growth (1K-50K) | Self-hosted Next.js + Hono + Inngest paid + Trigger.dev = **$100-400/mo** |
| Enterprise (50K+) | Dedicated infra + self-hosted Inngest/Trigger.dev = **$500-1,500/mo** |

---

## Area 3: Database architecture

### Neon Postgres for relational data, ClickHouse for telemetry

**Neon Postgres** is the clear winner for the primary relational store. Acquired by Databricks in May 2025 for ~$1B, Neon received **15-25% compute price drops** and storage pricing fell from $1.75 to **$0.35/GB-month**. Enterprise features (Private Link, SOC 2 Type II, HIPAA, SSO, 30-day PITR) moved into the Scale plan at no extra cost. Key advantages for AvaKill: instant copy-on-write database branching for CI/CD preview environments, scale-to-zero (dev databases cost nothing when idle, resume <500ms), built-in connection pooling supporting 10K+ clients, autoscaling from 0.25 to 56 vCPU, and the `@neondatabase/serverless` driver for Vercel Edge Functions.

Avoid CockroachDB (complex pricing via Request Units, not standard Postgres), Supabase as a pure database (you'd pay for a BaaS stack you don't need), and Aurora (can't scale to zero, $24+ minimum/month).

**For time-series telemetry analytics, start with Tinybird, graduate to ClickHouse Cloud.** Tinybird is managed ClickHouse with streaming ingestion (1M+ events/second), instant SQL-to-REST API publishing, and automatic schema migrations. It saves 3-5 engineers of infrastructure work versus self-hosted ClickHouse. Developer plans start at ~$1/month. When you outgrow Tinybird's abstraction or need more control, migrate to ClickHouse Cloud directly — same underlying engine, straightforward transition.

**ORM: Drizzle ORM over Prisma.** Drizzle is TypeScript-first with a SQL-like query builder, **~7.4KB minified+gzipped**, zero dependencies, and no codegen step. Its SQL-first approach makes it natural to integrate with Postgres RLS — you can `SET app.tenant_id` before queries and write RLS-aware code directly. Drizzle has first-class Neon support via `drizzle-orm/neon-serverless`. Prisma 7 (announced November 2025) removed the Rust query engine and is now pure TypeScript, but still requires `prisma generate` after schema changes and has a larger bundle. Drizzle's 14x lower latency on complex joins seals the deal.

**Caching: Upstash Redis** for launch/growth (serverless, pay-per-request at $0.2/100K commands, free tier included). Migrate to **Dragonfly Cloud or ElastiCache** at enterprise scale when you need high-throughput dedicated resources.

**Audit log search: start with Postgres full-text search** (GIN indexes, zero additional cost), add **Typesense** at growth stage. Typesense is C++, <50ms search, MIT-licensed, self-hostable, with built-in typo tolerance — and Cloud plans start at just **$12/month**. Avoid Elasticsearch until you have billions of documents.

| Component | Launch cost | Growth cost | Enterprise cost |
|-----------|-----------|------------|----------------|
| Neon Postgres | $5-50/mo | $100-500/mo | $700-3,000/mo |
| Tinybird/ClickHouse | $0-50/mo | $200-800/mo | $1,000-10,000/mo |
| Upstash Redis | $0-10/mo | $10-60/mo | $200-1,500/mo |
| Search | $0 (PG FTS) | $12-60/mo | $100-500/mo |

---

## Area 4: Authentication and authorization

### Clerk Pro is the right choice for a security product

**Clerk** provides the best balance of developer experience, enterprise features, and Next.js integration. As of February 2026: **Free up to 10,000 MAUs**, Pro at $25/month base with $0.02/MAU beyond 10K. SAML/OIDC SSO is included in Pro (key differentiator) at **$50/connection/month** — metered as of the February 2026 pricing restructure. SOC 2/HIPAA artifacts now require the Business plan.

Clerk's pre-built Organization components (`<OrganizationSwitcher/>`, `<OrganizationProfile/>`) save months of B2B UI development. RBAC with custom roles/permissions is embedded directly in session tokens — no extra network requests for authorization checks. The native Next.js middleware integration (`auth.protect()`) reduces the surface area for auth bugs, which matters enormously for a security product.

**Avoid Auth0** — documented 15.54x cost increases from modest user growth, and Cursor explicitly migrated away citing "customer-hostile and opaque pricing." **Avoid NextAuth/Auth.js v5** — no organization management, no pre-built enterprise features, too much custom work for a security product.

**RBAC model**: Use Clerk's built-in roles and permissions (org_owner, org_admin, developer, viewer, billing_admin) with **CASL v6** on the frontend for UI permission gating. Clerk embeds org ID, role, and permissions directly in session JWTs — zero database lookups at auth time. When you need ABAC (attribute-based access control), add **Permit.io** as the policy engine. Do not build a custom RBAC system from scratch — it's a 2-3 month project that inevitably needs rebuilding.

**API key management: Unkey Pro at $25/month.** Unkey provides key creation with prefixes (`avk_live_xxxxx`), one-API-call verification with role/permission checks, per-key rate limiting, usage credits for tiered access, and an open-source self-host option. As of December 2025, Unkey rebuilt from serverless Cloudflare Workers to stateful Go servers — achieving **6x performance improvement**. Building custom API key management for a security product (secure generation, one-way hashing, rotation, revocation, audit logging) takes 4-6 weeks minimum. Unkey eliminates this.

**Session strategy**: Admin dashboard gets stricter policies (1-hour token lifetime, mandatory MFA, IP restrictions). Customer dashboards get configurable session lifetime (24h default) with MFA optional per organization. Both use the same Clerk instance but with different per-organization security policies. API keys via Unkey are separate from user sessions — different lifecycle, different revocation model.

---

## Area 5: Multi-tenancy architecture

### Defense-in-depth with three isolation layers

For a security product, tenant isolation must be airtight. Implement three layers:

**Layer 1 — Middleware (request level)**: Next.js `proxy.ts` extracts tenant context from subdomain, validates it against a cached tenant registry, and sets `x-tenant-id` / `x-tenant-tier` headers for downstream components.

**Layer 2 — Application (query level)**: Drizzle ORM middleware auto-injects `tenant_id` into every query. Even with RLS, always include tenant_id in application queries as belt-and-suspenders.

**Layer 3 — Database (Postgres RLS)**: Enable Row Level Security on all tenant-scoped tables. Create policies using `current_setting('app.current_tenant')::UUID`. Use `SET LOCAL` for transaction-scoped tenant context (compatible with connection pooling). RLS adds ~5-10% overhead with proper indexing — negligible. Critical: use a non-superuser application role (RLS is bypassed for superusers).

**Custom subdomain routing** uses Next.js middleware to extract the subdomain from the Host header, look up the tenant, and rewrite the URL to `/tenant/[slug]/...`. Vercel handles wildcard SSL automatically with a `*.avakill.com` CNAME to `cname.vercel-dns.com`. For enterprise custom domains (`security.acme.com`), use **Cloudflare for SaaS** — 100 custom hostnames free, then $0.10/hostname/month with automatic TLS provisioning.

**The enterprise upgrade path is architected from day one.** Include `tenant_id` as the first column in all composite primary keys and indexes — this makes future hash/list partitioning trivial. The `tenants` table tracks `tier` (shared/dedicated) and `database_url` (NULL for shared, connection string for dedicated). When an enterprise customer pays for physical isolation, provision a new Neon project (~$5-50/month), migrate their data via `pg_dump` with tenant_id filter, update the tenant record, and the connection router automatically sends queries to the dedicated instance. Zero application code changes needed.

---

## Area 6: Telemetry and analytics pipeline

### OTLP/HTTP for ingestion, ClickHouse Materialized Views for processing

The open-source CLI should send opt-in telemetry via **OTLP/HTTP (Protobuf)** — the industry standard as of 2026. HTTP works through corporate firewalls (unlike gRPC), OTLP has built-in batching, retry with exponential backoff, and gzip compression. Use opt-out telemetry (env var `AVAKILL_TELEMETRY=0` or `--no-telemetry` flag) — pure opt-in yields ~3% participation, making data statistically useless. Never collect personal info, IP addresses, file contents, or persistent identifiers.

**Ingestion pipeline scales in three phases:**

- **Launch**: Direct HTTP inserts to ClickHouse Cloud with `async_insert=1`. At <1K events/second, no queue is needed. ClickHouse handles native HTTP batch inserts.
- **Growth**: **Upstash Kafka** ($0.60/100K messages, price cap at $360/month) feeding ClickHouse via ClickPipes. Serverless Kafka with REST API works from Vercel serverless functions.
- **Enterprise**: **Redpanda Cloud** (10x lower tail latencies than Kafka, C++ thread-per-core architecture, Kafka API compatible) or Confluent Cloud feeding ClickHouse.

**Real-time processing uses ClickHouse Materialized Views**, not a separate stream processor. Events land in a raw `events_raw` table (MergeTree, partitioned by month). Materialized Views fire on INSERT and write pre-aggregated data into rollup tables using `AggregatingMergeTree`. Dashboard queries hit the rollup tables for sub-second response. This pattern — validated by Mux at 500K writes/second — replaced Apache Flink entirely, eliminating a stream processing runtime.

**Three-tier rollup strategy:** 1-minute rollups (live dashboards, 30-180 day retention), 1-hour rollups (historical trends, 1-2 year retention), 1-day rollups (long-term analytics, forever). Use `AggregateFunction` states for chainable, mergeable partial aggregates. Apply `ZSTD(3)` compression and `ttl_only_drop_parts=1` for efficient expiration.

**Data retention by billing tier** is enforced via ClickHouse TTL. Recommended: Free (24h raw / 7d rollup), Starter (7d / 30d), Pro (30d / 90d), Enterprise (90d / 1yr+). Use tiered storage: hot SSD for last 7 days, warm for 7-30 days, cold S3 for 30-365 days.

Run an **OpenTelemetry Collector** as the server-side ingestion gateway. Configure processors in order: `memory_limiter` → `redaction` (PII scrubbing) → `attributes` (tenant enrichment from API key) → `filter` (drop noise) → `batch` (1024 events, 5s timeout) → export to ClickHouse or Kafka.

---

## Area 7: Real-time infrastructure

### SSE beats WebSockets for this use case

**Server-Sent Events (SSE)** is the right transport for AvaKill dashboards. SSE is experiencing a renaissance driven by AI streaming (ChatGPT normalized it), Vercel/serverless compatibility (WebSockets don't work on Vercel natively), and the fact that **95% of "real-time" dashboard updates are server-to-client only**. SSE works through every proxy, CDN, and load balancer without special configuration. HTTP/2 multiplexing means multiple SSE streams share one TCP connection. The `EventSource` API provides automatic reconnection with `Last-Event-ID`.

Vercel Edge Functions support SSE with a **25-second timeout**. Mitigation is simple: send heartbeat comments every 15 seconds, and `EventSource` auto-reconnects transparently. This is a well-known, reliable pattern.

**Fan-out architecture: channel-per-tenant with Redis Pub/Sub backing.** When new events are inserted into ClickHouse, a lightweight worker publishes to Redis channel `tenant:{id}:events`. SSE endpoints subscribe to the appropriate tenant channel. At launch, use **Upstash Redis Pub/Sub** (free tier). At growth stage, upgrade to **Ably** ($29-399/month) for global edge delivery, 99.999% SLA, message ordering, history, and delta compression. Ably's token authentication ensures tenants can only subscribe to their own channels.

Avoid Socket.IO on Vercel (explicitly unsupported), Pusher (single-region, history of outages), and Liveblocks (purpose-built for collaboration, not event streaming).

---

## Area 8: Billing and subscriptions

### Stripe Billing with the new Meters API, evolving to Stripe + Orb

**Stripe acquired Metronome for ~$1B in December 2025**, signaling that usage-based billing is becoming Stripe's native model. The legacy `usage_records` API is deprecated as of API version `2025-03-31.basil`. All new usage-based billing must use **Billing Meters** — which support up to **100M usage events/month** at no extra metering cost.

**Primary billable metric: events processed.** Every event flowing through the AvaKill firewall equals one billable event. This directly correlates with protection delivered (customer value) and compute consumed (your cost). Secondary metrics include policy evaluations, active agents monitored, and seats.

**Recommended pricing tiers:**

| Tier | Events/mo | Agents | Seats | Retention | Price |
|------|----------|--------|-------|-----------|-------|
| Free | 10K | 2 | 1 | 7 days | $0 |
| Starter | 100K | 10 | 5 | 30 days | $49/mo |
| Pro | 1M | 50 | 20 | 90 days | $199/mo |
| Enterprise | Custom | Unlimited | Unlimited | 1 year | Custom |
| Overage | — | — | — | — | $0.50/1K events |

**Use a reverse trial**: 14-day full Pro access on signup → drop to genuinely useful free tier after trial. Developer tools achieve **11.7% freemium conversion** (highest of any category), and warning users before hitting limits increases conversion by **31.4%**.

**Billing platform phasing**: Use Stripe Billing alone through ~$500K ARR. Add **Orb** ($0 for up to 250 invoices/month, then $1/invoice) when you need pricing experimentation and real-time metering. Orb is used by Perplexity and Vercel, provides no-code pricing changes, and can simulate pricing changes against historical data. Avoid Lago unless you need to self-host (it's AGPL-licensed, adding complexity). Watch for Metronome features to appear natively in Stripe Billing.

**Webhook handling is non-negotiable**: verify every webhook signature, use `event.id` for idempotency (Stripe delivers at-least-once), return 2xx immediately before any complex logic, and process asynchronously via Inngest. Always fetch current state from Stripe API rather than relying on event ordering. Implement a reconciliation job that periodically checks for missed events.

**Enterprise contracts**: Use Stripe Quotes API for formal proposals → auto-create Subscription Schedules on acceptance → Revenue Contracts for GAAP/ASC 606 compliance → Net-30/60 payment terms via Invoice settings. Never create unique Products/Prices per enterprise customer.

---

## Area 9: Deployment and infrastructure

### Vercel for frontend, AWS ECS Fargate for Python backend

**Vercel** handles the Next.js frontend with zero-config deployment, automatic preview deployments per PR, global CDN, and Fluid Compute. But Vercel cannot run the Python backend services, long-lived gRPC servers, NATS subscribers, or the telemetry pipeline.

**AWS ECS Fargate** is recommended for the Python core and backend services. A security product needs enterprise-grade infrastructure with compliance certifications (SOC 2, HIPAA, FedRAMP), VPC isolation, IAM integration, and private networking. A 1 vCPU/2GB Fargate task costs ~$42/month. Fly.io is a viable alternative for faster iteration ($3-15/month for small VMs) but has fewer compliance certifications.

**CI/CD: Turborepo + GitHub Actions with Vercel Remote Caching.** Use `turbo build lint test` with `--filter='...[origin/main...HEAD]'` for affected-only execution. Vercel auto-deploys the frontend via Git integration. Separate GitHub Actions workflows trigger Docker builds and ECS deployments when backend code changes, using path filters.

**Environment strategy**: PR → automatic Vercel preview + Neon database branch → merge to main → auto-deploy to staging (full production mirror) → manual gate → production with blue/green deployments on ECS. This flow satisfies SOC 2 change management requirements.

### Observability: split-stack for cost efficiency

| Concern | Tool | Why | Cost |
|---------|------|-----|------|
| Logs | **Axiom** | Serverless, 95%+ compression, native Vercel integration | Free: 500GB/mo |
| Metrics/Traces | **Grafana Cloud** | OpenTelemetry-native, Prometheus/PromQL | Free: 10K series |
| Errors | **Sentry** | Best-in-class with session replay | Free: 5K errors/mo |
| Uptime | **BetterStack** | Status pages + on-call | Free tier |

**Instrument everything with OpenTelemetry from day one** — this prevents vendor lock-in and enables switching backends later. Avoid Datadog (extremely expensive, unpredictable billing, a small config mistake can blow your monthly budget).

---

## Area 10: Security posture for a security product

### Your own security IS your product's credibility

**Secrets management: Infisical** (MIT-licensed, 12,700+ GitHub stars, self-hostable, zero-knowledge architecture). Free for up to 5 members, Pro at $6/user/month. Native integrations with GitHub Actions, Vercel, Kubernetes, and Docker. PKI and SSH key management are bonus features. Use AWS Secrets Manager alongside for AWS-native secrets (RDS passwords, ECS task secrets). Avoid HashiCorp Vault (BSL license, overkill complexity).

**Supply chain security is achievable in 4 weeks:**
1. Week 1: Pin all dependencies with `pnpm-lock.yaml` + `--frozen-lockfile`, pin Docker base images by digest, pin GitHub Actions by commit SHA
2. Week 2: Add SBOM generation (Syft) + Cosign signing in CI
3. Week 3: Add SLSA provenance generation via `slsa-github-generator` (targets SLSA Level 2-3)
4. Week 4: Add deploy-time verification gates rejecting unsigned artifacts

**Data encryption follows a tiered approach**: platform-managed encryption keys (single KMS key, AWS RDS encryption at rest) for Free/Pro tiers. **Per-tenant KMS keys** managed by AvaKill for Enterprise. **BYOK** (customer provides their own AWS KMS key) for Enterprise+ at $1/key/month + $0.03/10K API calls.

**Platform audit logging** uses an append-only Postgres table with hash chaining (each row includes `hash = SHA-256(previous_hash + event_data)`). Revoke DELETE/UPDATE permissions for all roles. Replicate to S3 with Object Lock (WORM). Log every authentication event, authorization change, policy modification, data access, and configuration change. Every entry includes timestamp, actor, tenant_id, action, target, outcome, and before/after state.

**SOC 2 Type II is table stakes** for selling to enterprise. Start with **Vanta** (Core plan, ~$10K/year) for speed. Pursue Type I within 6 months of launch, then immediately begin the Type II observation period. Total Year 1 cost: **$30,000-80,000** including compliance platform, audits, pen testing, and security tooling.

**Penetration testing and bug bounty**: Commission a formal pen test from a reputable firm (Bishop Fox, Cobalt, NCC Group) at $10,000-30,000 before GA launch. After fixing initial findings, launch a **private bug bounty on HackerOne** with 20-50 vetted researchers. Set bounty ranges higher than typical SaaS — researchers expect this from security companies. Critical: $2,000-10,000, High: $500-2,000. Budget $20K-60K for Year 1. Do NOT launch a bug bounty before cleaning up findings from the formal pen test.

---

## Area 11: Developer experience and extensibility

### REST + OpenAPI for the public API, Svix for webhooks, Fumadocs for docs

**Public API: REST with OpenAPI 3.1.** 83% of public APIs use REST. Every successful developer tool (Stripe, Twilio, Cloudflare, OpenAI, Anthropic) ships REST + OpenAPI for the public API. This enables SDK auto-generation, automatic documentation, standard HTTP caching, and a familiar developer experience. Do not expose GraphQL publicly — it introduces query complexity attacks, caching challenges, and a steeper learning curve.

**Outbound webhooks: Svix** (free tier: 50K messages/month, Starter ~$10/month). Svix is purpose-built for the "webhook-as-a-feature" pattern — sending notifications to your customers when events occur (agent blocked, policy violation detected). It provides an embeddable consumer portal for self-service endpoint management, built-in HMAC signature verification, SOC 2 Type II compliance, and a 10-line integration. Building a custom webhook system to feature parity takes ~1 year. Use **Hookdeck** separately if you need to receive and route incoming webhooks (e.g., from Stripe).

**SDK generation: Speakeasy** (free for 250 endpoints). Speakeasy is OpenAPI-native, CLI-first, and generates type-safe, idiomatic SDKs for TypeScript, Python, Go, Java, and C#. It integrates directly into GitHub Actions. Both Speakeasy and Stainless now generate **MCP servers** (Model Context Protocol) from your API spec — critical for AI agent integration. Prioritize TypeScript and Python SDKs first.

**Documentation: Fumadocs** ($0, open-source, 10.7K GitHub stars). Fumadocs integrates directly into your Next.js codebase as a `/docs` route — no separate deployment needed. It supports React Server Components, Tailwind CSS, TypeScript Twoslash, OpenAPI docs generation, and Orama built-in search. Used by shadcn/ui, Million.js, and Arktype. If budget allows ($300/month), Mintlify offers AI-powered doc maintenance and a more polished out-of-the-box experience, but Fumadocs delivers 90% of the value at $0.

**Plugin architecture: defer the full marketplace**, but lay the foundation now. Every system action (agent request intercepted, policy evaluated, block triggered) emits an internal event via NATS. Customers subscribe to event types via Svix webhooks — this is the first extensibility layer. Custom policy plugins follow a simple pattern: standardized request/response schema, customer-hosted HTTP endpoints, strict timeout with fail-open/fail-closed configuration. A full plugin marketplace and sandboxed execution runtime are Phase 4 features.

---

## The critical path: what to build in what order

**Phase 1 — Revenue critical (Weeks 1-4):**
Authentication and authorization (Clerk + Unkey), core product stability (the safety firewall itself), billing and subscriptions (Stripe with Meters API), basic REST API with OpenAPI spec, and audit logging. Everything here either generates revenue or unblocks the first enterprise contract.

**Phase 2 — Enterprise enablement (Weeks 4-8):**
Multi-tenancy with RLS, webhook notifications via Svix, API documentation on Fumadocs, basic dashboard analytics (TanStack Query + Tremor charts), and custom subdomain routing.

**Phase 3 — Developer experience (Weeks 8-16):**
SDK generation via Speakeasy (Python + TypeScript), changelog and status page, telemetry pipeline (Hono + OTEL Collector + ClickHouse), real-time dashboard updates via SSE, and background job workflows via Inngest.

**Phase 4 — Scale and platform (3-6+ months):**
ClickHouse rollup optimizations, Ably for global real-time, Orb for pricing experimentation, plugin/extensibility framework, SOC 2 Type II completion, multi-region deployment, and BYOK encryption.

---

## Consolidated cost model across all 11 areas

### Launch phase (0-1K users): $200-600/month

| Service | Monthly cost |
|---------|-------------|
| Vercel Pro | $20 |
| Neon Postgres (Launch) | $5-50 |
| Tinybird / ClickHouse Cloud | $0-50 |
| AWS ECS Fargate (Python) | $42-100 |
| Clerk (free tier) | $0 |
| Unkey Pro | $25 |
| Stripe Billing | Transaction fees only |
| Upstash Redis + Kafka | $0-10 |
| Inngest Cloud (free) | $0 |
| Svix (free) | $0 |
| Infisical (free) | $0 |
| Axiom + Grafana + Sentry (free tiers) | $0 |
| Domain + Cloudflare | $15 |
| **Total infrastructure** | **~$110-320/mo** |

### Growth phase (1K-50K users): $2,000-5,000/month

| Service | Monthly cost |
|---------|-------------|
| Vercel Pro (3-5 seats) | $60-100 |
| Neon Postgres (Scale) | $100-500 |
| ClickHouse Cloud / Tinybird | $200-800 |
| AWS ECS Fargate (Python cluster) | $200-500 |
| Clerk Pro | $25-825 |
| Unkey Pro | $25 |
| Stripe Billing (0.7%) | $350-700 |
| Upstash Redis + Kafka | $60-400 |
| Inngest + Trigger.dev (paid) | $20-200 |
| Ably (real-time) | $29-399 |
| Svix (Business) | $10-490 |
| Observability stack | $270 |
| NATS cluster | $30-100 |
| **Total infrastructure** | **~$1,400-5,300/mo** |

### Enterprise phase (50K+ users): $10,000-25,000/month

| Service | Monthly cost |
|---------|-------------|
| Vercel Enterprise | $1,700+ |
| Neon Postgres (Business) | $700-3,000 |
| ClickHouse Cloud (dedicated) | $1,000-5,000 |
| AWS ECS Fargate (scaled) | $1,000-3,000 |
| Clerk Enterprise | $2,000-5,000 |
| Stripe (volume discounts) | $1,500-5,000 |
| Ably Enterprise | Custom |
| SOC 2 / compliance (amortized) | $2,000-5,000 |
| Observability (upgraded) | $1,200-3,000 |
| **Total infrastructure** | **~$12,000-30,000/mo** |

**Infrastructure should remain below 15% of revenue.** At enterprise pricing ($5K-50K/month per customer), 5-10 enterprise customers more than cover the full infrastructure. Clerk is the fastest-growing line item as MAUs scale — at 100K MAUs it reaches ~$2,025/month. If Clerk costs become problematic, WorkOS (free to 1M MAUs) is the migration path.

---

## Build vs buy vs open-source decision matrix

| Component | Decision | Service | Rationale |
|-----------|----------|---------|-----------|
| Core safety engine | **BUILD** | Custom Python | Your competitive advantage. Never outsource. |
| Policy engine | **BUILD** | Custom Python | Core differentiator. |
| Dashboard/UX | **BUILD** | Next.js + shadcn/ui | Your product surface. Own it. |
| API layer | **BUILD** (with frameworks) | tRPC + Hono | Core infrastructure, framework-assisted. |
| Auth/Identity | **BUY** | Clerk | 5-15 minute setup vs 3-6 months custom. |
| Billing | **BUY** | Stripe | Industry standard. Don't build payments. |
| Database (OLTP) | **BUY** (managed) | Neon Postgres | Serverless, scale-to-zero, branching. |
| Database (Analytics) | **BUY** (managed) | Tinybird → ClickHouse | Saves 3-5 engineers of infrastructure. |
| API keys | **BUY** | Unkey | 4-6 weeks custom build eliminated for $25/mo. |
| Webhooks (outbound) | **BUY** | Svix | ~1 year to build equivalent. |
| Secrets | **OPEN-SOURCE** | Infisical | MIT-licensed, self-hostable, zero-knowledge. |
| Background jobs | **OPEN-SOURCE** | Inngest + Trigger.dev | Apache 2.0, self-hostable when needed. |
| Docs | **OPEN-SOURCE** | Fumadocs | Free, Next.js-native, full control. |
| SDKs | **BUY** | Speakeasy | Hand-writing multi-language SDKs is unsustainable. |
| Observability | **BUY** | Axiom + Grafana + Sentry | Free tiers, avoid self-hosting ELK/Prometheus. |
| Compliance | **BUY** | Vanta | SOC 2 in months vs years. |

**The golden rule: build only what creates competitive advantage. Buy everything else.**

---

## Risks, unknowns, and decisions requiring more information

**Highest-risk decisions:**
- **AGPL boundary interpretation**: The Python core running as a separate Docker container communicating via gRPC/NATS is the industry-accepted practice for AGPL isolation, but the "derivative work" question in microservices is legally unsettled. **Engage an IP attorney before launch.**
- **Clerk pricing trajectory**: The February 2026 pricing restructure (metered SSO connections, SOC 2 behind Business plan) signals increasing monetization. Model a WorkOS migration scenario as insurance.
- **ClickHouse Cloud price volatility**: January 2025 saw ~30% price increases with new egress fees. Lock in committed-use pricing at growth stage.

**Key unknowns:**
- Stripe's Metronome integration timeline — may make Orb unnecessary if Metronome features ship natively in Stripe Billing
- Vercel's WebSocket support evolution — Rivet (October 2025) is experimental but could eliminate the need for external real-time services
- Radix UI's future — shadcn/ui's Base UI migration path mitigates this, but watch for ecosystem fragmentation
- Next.js 16's `proxy.ts` stability — it's a renamed middleware with Node.js runtime, but the rename may cause ecosystem confusion

**Decisions to make with more data:**
- Exact ClickHouse schema design depends on the specific event types and query patterns the AvaKill firewall produces
- Whether to use Cloudflare Workers for edge telemetry ingestion (latency benefit) versus centralizing in AWS (simplicity)
- When to trigger the Neon → dedicated database migration for enterprise tenants — define the SLA/compliance threshold
- Bug bounty reward ranges should be calibrated against your pricing — if enterprise contracts are $50K+/year, bounty ranges should reflect that value


---


