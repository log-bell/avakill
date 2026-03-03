# AvaKill Viral Growth Deep Research Prompt

Copy-paste the prompt below into a deep research session.

---

## Prompt

I need a comprehensive go-to-market and viral growth strategy for AvaKill, an open-source safety firewall for AI agents that just launched at v1.0.0. Research what's working right now (as of February 2026) for developer tool launches and open-source virality, and produce a detailed, actionable playbook.

### What AvaKill Is

AvaKill intercepts AI agent tool calls, evaluates them against a YAML policy file in <1ms (deterministic, no ML, no API calls), and either allows, denies, or requires human approval. Three independent enforcement paths:

1. **Hooks** — Direct integration into AI coding agents (Claude Code, Cursor, Windsurf, Gemini CLI, OpenAI Codex)
2. **MCP Proxy** — Transparent proxy between MCP clients and servers
3. **OS Sandbox** — Kernel-level sandboxing (Landlock, sandbox-exec, eBPF, AppContainer)

Key stats: 2,108 tests passing, 63/63 red team attacks blocked, <1ms evaluation, 81 built-in safety rules, compliance assessment for SOC 2/NIST/EU AI Act/ISO 42001. The entire product was built in one week. It's on PyPI (`pipx install avakill`), licensed AGPL-3.0.

### Current Public Presence

- **Website**: avakill.com — static landing page with animated demo, docs, rule catalog
- **GitHub**: github.com/log-bell/avakill — full source, README with quickstart, CONTRIBUTING.md
- **PyPI**: Published, installable
- **Discord**: Server exists (discord.gg/gTBvbkSV2)
- **Pitch Deck**: HTML-based investor deck (private, noindex)
- **Welcome Email**: MJML template for onboarding
- **Social**: No Twitter/X, LinkedIn, YouTube, or blog presence yet
- **Testimonials**: None yet (placeholder in HTML)
- **Newsletter/Mailing List**: None

### The Market Context

AI agent safety is exploding as a concern. Real production disasters have made headlines:
- Replit agent dropped a production database
- Google Gemini CLI wiped a user's entire D: drive (8,000+ files)
- Amazon Q deleted critical infrastructure
- 75% of real-world AI agent tasks fail catastrophically (research stat)

Every major AI company (Anthropic, OpenAI, Google, Cursor, Windsurf) is shipping agents with tool-use capabilities, and none of them have built-in safety firewalls. AvaKill is the first dedicated, cross-agent safety layer.

We're also building a commercial SaaS platform on top (developer dashboards, enterprise deployments, "Ava as an Agent" security layer), but the open-source core launch is the immediate priority.

### What I Need You To Research

Research each of the following areas thoroughly, looking at what's actually working for developer tools and open-source projects right now (February 2026), not generic marketing advice from 2023. For each area, give me specific, actionable tactics with examples of projects that executed them well.

**1. Hacker News Strategy**

- What types of Show HN posts are performing well for dev tools in 2025-2026? Analyze recent successful launches.
- Optimal posting time, title format, and description structure
- How to write the Show HN post — what angle resonates? (technical deep dive vs problem statement vs demo vs "I built this in a week")
- Comment strategy — how founders engage in the thread to maximize traction
- What gets flagged or buried and how to avoid it
- Should we do multiple HN posts over time? (Show HN, then a technical blog post, then a "lessons learned" post?)
- Research recent successful HN launches for security tools, CLI tools, and AI safety tools specifically
- The "built in one week" angle — is this an asset or does it undermine trust for a security product? How to frame it

**2. Product Hunt Launch**

- Current state of Product Hunt in 2026 — is it still relevant for developer tools, or has its influence declined?
- If relevant: optimal launch day, preparation timeline, maker community engagement
- How to get hunters, what makes a winning product page
- Product Hunt alternatives that may have emerged (other launch platforms)
- How to coordinate PH launch with HN launch (same day? staggered?)

**3. Reddit Strategy**

- Which subreddits are most relevant? (r/programming, r/MachineLearning, r/LocalLLaMA, r/ClaudeAI, r/ChatGPT, r/cursor, r/devtools, r/netsec, r/cybersecurity, etc.)
- What type of posts work in each subreddit? (some want demos, some want discussions, some want technical deep dives)
- How to post without getting flagged as self-promotion
- Reddit's current algorithm and what drives visibility
- Case studies of dev tools that grew through Reddit

**4. Twitter/X Developer Community**

- Current state of dev Twitter/X in 2026 — who are the key voices in AI agent safety, AI dev tools, and open-source?
- Thread format vs single post vs video demo — what's performing?
- How to build an audience from zero
- Which AI/dev influencers should we be engaging with?
- Hashtags, timing, engagement tactics that actually work now
- Should we have a personal account (founder) vs brand account vs both?

**5. YouTube & Video Content**

- Short-form (Shorts/TikTok) vs long-form — what's working for dev tools?
- Demo video strategy: what format, length, and style gets developer attention?
- "Built in a week" documentary/timelapse — is this compelling content?
- Technical deep dive videos — architecture walkthroughs, security breakdowns
- Which dev-focused YouTube channels accept sponsored content or features?

**6. Technical Content & SEO**

- Blog post topics that would drive organic traffic (what are developers searching for around AI agent safety?)
- "Awesome list" inclusion strategy (awesome-llm, awesome-security, awesome-cli, etc.)
- Technical comparison posts (AvaKill vs prompt-based guardrails vs no protection)
- Guest posting opportunities on dev blogs (Dev.to, Hashnode, Medium, company blogs)
- SEO keyword opportunities in the AI agent safety space
- llms.txt as a distribution mechanism — how to leverage the fact that we have one

**7. Community Building**

- Discord vs Slack vs GitHub Discussions — what's working for open-source dev tool communities in 2026?
- How to seed initial community activity (it's empty right now)
- Contributor growth strategy — how to attract first contributors
- Community-led content (user stories, policy sharing, agent profiles)
- Ambassador/champion programs that work at early stage

**8. Conference & Event Strategy**

- Which conferences and meetups are most relevant? (DEF CON, Black Hat, AI Engineer Summit, PyCon, local meetups)
- Lightning talk vs full talk vs workshop — what's most effective for launches?
- Virtual vs in-person — what's the landscape in 2026?
- CFP timelines for relevant 2026 conferences
- Unconference and hackathon opportunities

**9. Developer Relations & Partnerships**

- Integration partnerships: getting AvaKill mentioned in Claude Code, Cursor, Windsurf, Gemini, Codex docs or marketplaces
- MCP ecosystem: how to get listed in MCP directories, registries, and tooling guides
- Security researcher engagement: bug bounties, red team challenges, CTF integration
- Academic outreach: AI safety research groups, university courses
- How other open-source security tools built their initial developer community

**10. Viral Mechanics & Growth Loops**

- What natural viral loops exist in the product? (e.g., the "blocked by AvaKill" message agents see, policy sharing, compliance reports)
- Badge/shield strategy (like "tested with AvaKill" badges for README files)
- GitHub Actions / CI integration as a distribution channel
- Can the `avakill setup` wizard itself drive sharing? (e.g., "share your policy" or "star on GitHub" prompts)
- Referral mechanics for the upcoming paid tiers
- "Powered by AvaKill" attribution in MCP proxy responses
- The AGPL-3.0 license as a growth mechanism (copyleft forces attribution in derivative works)

**11. Leveraging the "Built in One Week" Narrative**

- This is unusual for a security product with 2,100+ tests and 63/63 red team results. How to tell this story compellingly without undermining trust.
- AI-assisted development as a story angle — we used Claude Code to build AvaKill, and AvaKill protects Claude Code. The ouroboros angle.
- "Solo founder ships production security tool in a week" — where does this story resonate? (indie hackers, AI dev community, startup press)
- Risk: does speed undermine confidence in a security product? How to frame it as "fast because deterministic and well-scoped" rather than "rushed"

**12. Press & Media**

- Which tech journalists cover AI agent safety, developer tools, and open-source?
- How to pitch to TechCrunch, The Verge, Ars Technica, etc. — what angle?
- Developer-focused newsletters that cover new tools (TLDR, Changelog, Console.dev, DevOps Weekly, etc.)
- Podcast appearances — which podcasts cover AI tools, security, open source?
- The "AI agents are dangerous and nobody is doing anything about it" angle for mainstream tech press

### Output Format

Produce an actionable growth playbook that:

1. Opens with a prioritized launch sequence — what to do first, second, third (calendar-style, week by week for the first 60 days)
2. For each channel, provides: specific tactics, example copy/titles/threads, timing, expected impact, and effort level
3. Identifies the 3-5 highest-leverage moves that will drive the most visibility for the least effort
4. Includes draft copy for: the Show HN post, the first 3 tweets/X posts, the Reddit posts for top 3 subreddits, and a Product Hunt tagline
5. Maps out content dependencies (e.g., "need a demo video before the HN launch")
6. Flags what requires preparation vs what can be done immediately
7. Identifies risks (e.g., "security community backlash if framing is wrong") and how to mitigate them
8. Recommends tools/services for execution (scheduling, analytics, community management)

Be specific and opinionated. Don't give me a generic "post on social media" playbook. Tell me exactly what to post, where, when, and why — based on what's actually working for developer tools in February 2026.
