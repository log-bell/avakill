# Viral Growth & Go-To-Market Research

# AvaKill viral growth playbook: 60 days to developer mindshare

**AvaKill's launch window is exceptional, but the AI agent firewall space on Hacker News is already crowding.** At least 7 similar tools have posted Show HN in the past year — Cordum, SentinelGate, ClawShield, FailCore, OpenClaw Harness — all earning between 2 and 7 points. Meanwhile, AI agent disasters are accelerating monthly (Replit's production database deletion, Amazon Kiro's 13-hour AWS outage, Claude Code wiping home directories), creating massive demand for exactly what AvaKill does. The strategy must be: differentiate sharply on technical merits, ride the incident-response narrative cycle, and hit GitHub Trending within the first 72 hours. Everything in this playbook is calibrated to that goal.

---

## The five highest-leverage moves

Before diving into the full calendar, these are the actions with the most outsized impact relative to effort. Everything else supports them.

**1. Hit GitHub Trending in the first week.** Analysis of Froala Design Blocks, ScrapeGraphAI, and Preevy shows that hitting Trending yields 500+ stars/day for up to two weeks. A burst of 80–120 stars in 24 hours triggers the algorithm. Seed the first 100 via personal network (research shows **60% conversion on direct asks**), then time the Show HN post to amplify that spike.

**2. Get Simon Willison to notice AvaKill.** Willison coined the "Lethal Trifecta for AI agents," his blog posts are cited by Martin Fowler, Fortune, and InfoWorld, and he's the single most influential voice in AI agent safety. One mention from him could drive thousands of stars. The approach: engage authentically on Bluesky and his blog comments for 2–3 weeks before launch, then share AvaKill directly when it ships.

**3. Publish to the official MCP Registry and every MCP directory.** The MCP ecosystem is exploding. The official registry (registry.modelcontextprotocol.io), PulseMCP (8,600+ servers, weekly newsletter), GitHub's MCP Registry, mcp.so, and MCP Market are all discovery surfaces where developers actively look for tools. AvaKill's MCP proxy mode makes this a natural fit.

**4. Create a 60-second terminal demo video.** Every channel — HN, Reddit, Twitter/X, Product Hunt — converts better with visual proof. A terminal recording showing `pipx install avakill` → YAML policy → Claude Code attempting a dangerous `rm -rf` → **BLOCKED** in <1ms is the single most reusable asset across all channels.

**5. Own the incident-response content cycle.** AI agent disasters happen monthly. The next one is a marketing event. Have a blog post template ready: "How AvaKill would have prevented [X incident]" with a concrete YAML policy walkthrough. Publish within hours of the next headline. This is AvaKill's unfair advantage — a deterministic tool that maps cleanly to specific, documented disasters.

---

## 60-day launch calendar

### Pre-launch: Days −14 to −1 (preparation phase)

**Content dependencies must be resolved before any public launch:**

| Asset | Status | Priority | Notes |
|-------|--------|----------|-------|
| 60-second terminal demo video | MUST HAVE | P0 | Record with asciinema or Screen Studio. Show install → configure → attack blocked. Add captions. |
| 3–5 minute full demo video | MUST HAVE | P0 | Expand the 60-sec version: show all three enforcement paths (Hooks, MCP Proxy, OS Sandbox) |
| Blog: incident timeline post | MUST HAVE | P0 | "Every documented AI agent disaster, October 2024 to February 2026" — the definitive reference |
| README polish | MUST HAVE | P0 | GIF at top, badges, one-line install, clear architecture diagram, social preview card |
| GitHub Discussions enabled | MUST HAVE | P0 | Pre-populate with FAQ, 5–10 YAML policy examples, integration guides |
| 10+ "good first issues" created | HIGH | P1 | Policy template additions, doc improvements, new MCP server compatibility |
| Blog hosted on avakill.com/blog | HIGH | P1 | For SEO. Dev.to cross-posts for distribution |
| Discord roles and channels configured | MEDIUM | P2 | #general, #help, #policies, #show-your-setup, #contributing |
| Founder's Twitter/X account active | HIGH | P1 | Start engaging in AI safety threads NOW, not at launch |
| Founder's Bluesky account active | HIGH | P1 | Custom domain handle (@avakill.com). Engage with Willison |
| llms.txt and llms-full.txt on avakill.com | LOW | P3 | Minutes to implement, marginal benefit, but no downside |
| Email capture on avakill.com | HIGH | P1 | Lightweight, non-styled. NOT on the GitHub repo (HN rules) |

**Pre-launch engagement work (founder personally, days −14 to −1):**
- Spend 30 minutes daily on Twitter/X and Bluesky replying to AI safety discussions. Add genuine insight. Build "RealGraph" score with key accounts (Willison, Johann Rehberger, Andrej Karpathy, Ethan Mollick).
- Comment on 3–5 Reddit threads in r/ClaudeAI, r/cursor, r/netsec about AI agent risks. Build karma. Do not mention AvaKill yet.
- Personally reach out to 20–30 developers who tweet about Claude Code or Cursor safety concerns. Simple DM: "I've been building an open-source safety firewall for AI agents — would love your early feedback."
- Seed first 50–80 GitHub stars via personal network. Research shows 60% conversion on direct, personal asks ("I built something that solves [problem]. Would you mind starring it?").

---

### Week 1: Show HN launch + GitHub Trending push

**Day 1 (Sunday or Monday, 12:00 UTC / 8 AM Eastern)**

Post Show HN. Link to **GitHub repo**, not landing page. This is the consensus recommendation from every successful launch analyzed.

**Show HN draft post:**

> **Title:** `Show HN: AvaKill – Open-source safety firewall for AI agents (<1ms, deterministic, no ML)`
>
> **Body:**
>
> Hi HN, I'm [name]. After watching Replit's agent delete a production database, Claude Code wipe a user's home directory, and Amazon Kiro cause a 13-hour AWS outage, I built the tool I wished existed.
>
> AvaKill intercepts AI agent tool calls — file writes, shell commands, API requests — and evaluates them against a YAML policy file before they execute. No ML, no API calls, no latency. Deterministic policy evaluation in under 1 millisecond.
>
> Three enforcement paths:
> - **Hooks**: Direct integration into Claude Code, Cursor, Windsurf, Gemini CLI, OpenAI Codex
> - **MCP Proxy**: Transparent proxy between any MCP client and server
> - **OS Sandbox**: Kernel-level enforcement via Landlock (Linux), sandbox-exec (macOS), AppContainer (Windows)
>
> The architecture is deliberately simple. YAML policy files define what's allowed, denied, or requires human approval. No probabilistic guardrails — if your policy says "deny rm -rf /", it's denied every time, in every context, regardless of what the LLM says.
>
> Current state: 2,108 tests passing, 63/63 red team attack scenarios blocked, 81 built-in safety rules, compliance mapping for SOC 2, NIST AI RMF, EU AI Act, and ISO 42001. AGPL-3.0 licensed.
>
> `pipx install avakill` — you're protected in under a minute.
>
> I'd love feedback on what's missing, what policies you'd want, and which agent integrations to prioritize. The whole policy catalog is at avakill.com/rules.
>
> GitHub: [link]

**Critical note on the title:** Do NOT use "firewall for AI agents" — at least 5 Show HN posts have used this exact framing with 2–7 points. The title above differentiates on technical specifics (<1ms, deterministic, no ML). If testing an alternative: `Show HN: AvaKill – Deterministic safety rules for AI agents, evaluated in <1ms from YAML`.

**Day 1 comment strategy:**
- Be online and responding within seconds of posting. The first 2 hours determine everything.
- Prepare 3–4 "follow-up" comments to post when relevant: architecture deep-dive, comparison to LLM-based guardrails, specific attack scenarios blocked, and the AGPL licensing rationale.
- When criticized ("isn't this overkill?" or "just don't give agents root access"), agree first, then explain. "You're right that limiting permissions is the first step. AvaKill is for the cases where agents need some access but you want policy-level control over exactly what."
- Do NOT have friends post booster comments. HN detects voting rings with high accuracy, and users can spot coordinated support instantly.
- Share the HN link in Discord, but do NOT ask people to upvote. Ask them to comment with genuine questions instead (comments are weighted **1.5x** more than upvotes in HN's ranking algorithm).

**Days 2–4: Reddit rollout (staggered by subreddit)**

Post to different subreddits on consecutive days — not all at once. Adapt framing for each community.

**Reddit post for r/ClaudeAI (Day 2, Tuesday 7 AM ET):**

> **Title:** I built an open-source safety layer for Claude Code after it deleted a user's entire home directory
>
> **Body:** Last December, Claude Code ran a deletion command that included ~/ and wiped a user's Mac home directory. Before that, Replit's agent deleted a production database during a code freeze. Amazon Kiro deleted an entire AWS environment and caused a 13-hour outage.
>
> The common thread: no interception layer between the agent's intent and the tool's execution.
>
> I built AvaKill — an open-source tool that sits between Claude Code (or any AI coding agent) and your system. You write YAML policies that define what's allowed, what's blocked, and what requires your approval. Evaluation is deterministic and takes <1ms — no ML, no API calls, no added latency.
>
> Works with Claude Code via hooks, MCP proxy, or OS-level sandboxing.
>
> [Demo GIF]
>
> GitHub: [link]
>
> Genuinely curious what safety rules you'd want. The whole policy catalog is at avakill.com/rules — suggestions welcome.

**Reddit post for r/netsec (Day 3, Monday — Soapbox Monday only):**

> **Title:** The emerging attack surface of AI coding agents: tool call interception as a defense pattern
>
> **Body:** [Technical write-up framing AI agent tool calls as an attack surface. Reference OWASP Top 10 for Agentic AI. Reference Johann Rehberger's "Month of AI Bugs" series documenting prompt injection in Claude Code, Cursor, Windsurf. Present interception-layer architecture. Include code-level details of how AvaKill's policy evaluation works. Link to GitHub.]

**Reddit post for r/Python (Day 4, Wednesday 8 AM ET):**

> **Title:** I open-sourced a <1ms YAML policy engine for securing AI coding agents (Python, AGPL-3.0)
>
> **Body:** [Lead with the Python-specific angle. Show the YAML policy format. Discuss architecture decisions (why Python, how <1ms is achieved). Include installation: `pipx install avakill`. Link to repo.]

**Additional subreddits (Days 5–7):** r/opensource, r/selfhosted, r/LocalLLaMA, r/commandline. One per day. Adapt framing for each audience.

**Day 5: Twitter/X launch thread**

**Thread (7 tweets):**

> **Tweet 1:** In 2025, AI coding agents:
>
> • Deleted a production database during a code freeze (Replit)
> • Wiped a user's entire home directory (Claude Code)
> • Caused a 13-hour AWS outage (Amazon Kiro)
> • Fabricated 4,000 fake database records
> • Ran destructive commands after "DO NOT RUN ANYTHING" (Cursor)
>
> Every incident shared one architectural flaw. 🧵

> **Tweet 2:** No interception layer between the agent's intent and the tool's execution.
>
> Your AI agent has the same permissions as you. When it decides to run `rm -rf /` or `DROP TABLE users`, nothing stops it.
>
> Prompt engineering is not a security strategy.

> **Tweet 3:** I built AvaKill — an open-source safety firewall for AI agents.
>
> It intercepts every tool call, evaluates it against a YAML policy file in <1ms, and allows, denies, or requires your approval.
>
> No ML. No API calls. Deterministic. Every time.
>
> [60-second demo video — uploaded natively, NOT a YouTube link]

> **Tweet 4:** Three enforcement paths:
>
> 🪝 Hooks — direct integration into Claude Code, Cursor, Windsurf, Gemini CLI, OpenAI Codex
> 🔀 MCP Proxy — transparent proxy between any MCP client and server
> 🏰 OS Sandbox — kernel-level via Landlock, sandbox-exec, AppContainer

> **Tweet 5:** Current state:
>
> ✅ 2,108 tests passing
> ✅ 63/63 red team attacks blocked
> ✅ <1ms evaluation latency
> ✅ 81 built-in safety rules
> ✅ Compliance mapping: SOC 2, NIST, EU AI Act, ISO 42001
> ✅ AGPL-3.0 licensed

> **Tweet 6:** The meta angle: AvaKill was built with Claude Code.
>
> An AI coding agent built its own safety firewall.
>
> And yes — AvaKill now protects Claude Code from itself.

> **Tweet 7 (reply, contains link):** `pipx install avakill`
>
> GitHub: [link]
> Docs: avakill.com
> Discord: [link]
>
> Every YAML policy in the catalog: avakill.com/rules

**Important X algorithm notes:** The thread format gets **40–60% more total impressions** than equivalent single tweets. Retweets are worth **20x a like** in X's algorithm — the disaster-list opening tweet is designed to be retweeted as a standalone. Put all external links in the final reply tweet, never in tweet 1 (X deprioritizes posts with outbound links). Upload the demo video natively. Consider X Premium ($8–16/mo) for 2–4x more initial impressions.

**Day 5 also: Bluesky post**

> Every major AI agent disaster in 2025 had the same root cause: agents executing tool calls without guardrails.
>
> I built AvaKill — an open-source safety firewall that sits between AI agents and their tools. YAML policies, <1ms evaluation, deterministic enforcement.
>
> 2,108 tests. 63/63 red team attacks blocked. AGPL-3.0.
>
> GitHub: [link]

**Days 6–7: Monitor, engage, and submit to directories**

- Respond to every HN comment, Reddit comment, and tweet. Engagement velocity determines long-tail reach on all platforms.
- Publish AvaKill to the **Official MCP Registry** using `mcp-publisher` CLI (highest-priority directory listing).
- Submit to PulseMCP, mcp.so, MCP Market, mcpservers.org, GitHub MCP Registry.
- Submit to awesome lists (PRs): awesome-ai-security (TalEliyahu, brinhosa, ottosulin versions), awesome-llm-security, awesome-llmsecops, awesome-mcp-security. Note: TalEliyahu's list requires 220+ stars and 3+ contributors — may need to wait.
- Submit to Console.dev (editorial review, 2–3 tools per week).
- Submit to goodfirstissue.dev (requires 3+ open beginner issues).

---

### Week 2: Content amplification + newsletter push

**Day 8: Publish the definitive incident timeline blog post**

> **Title:** "Every documented AI coding agent disaster: October 2024 to February 2026"
>
> Chronological, well-sourced, technical analysis of every incident: Replit (July 2025), Claude Code home directory deletion (December 2025), Amazon Kiro (December 2025), Amazon Q CVE-2025-8217 (July 2025), Cursor YOLO mode incidents, Gemini CLI false confirmations. For each: what happened, root cause, what policies would have prevented it, specific AvaKill YAML configuration.

Submit this blog post to HN as a **regular post** (not Show HN). Different URL means it won't be greyed out for people who saw the Show HN. This is the multi-post strategy — research shows it's effective when spaced by a week and using different content.

**Days 9–11: Newsletter submissions**

| Newsletter | Audience | Submission method | Priority |
|-----------|---------|------------------|----------|
| **TLDR** (main + InfoSec + AI editions) | 1.25M+ readers | Editorial curation. Best path: be featured on HN first, then email tips. Paid sponsorship also available. | CRITICAL |
| **Console.dev** | Dev tools audience | Submit via website. They review 2–3 tools weekly with detailed writeups. Beta/early-stage eligible. | HIGH |
| **Changelog** (newsletter + podcast) | 17K email, 350K podcast/month | Email news@changelog.com or submit via GitHub. Open-source focused. | HIGH |
| **Python Weekly** | Large Python community | Submit at pythonweekly.com. Hand-curated. | HIGH |
| **Hacker Newsletter** | 60K subscribers | Curates top HN links. Automatic if you hit HN front page. | INDIRECT |
| **Ben's Bites** | AI tool enthusiasts | Submit via site. Fast-paced, tool-centric. | HIGH |
| **Import AI** (Jack Clark) | AI researchers, policymakers | Email submission. Harder to get featured. | STRETCH |

**Day 12: Dev.to cross-post**

> **Title:** "I built an AI safety firewall in one week — here's the architecture behind <1ms deterministic policy evaluation"
>
> Tags: #ai #security #opensource #python
>
> Focuses on technical architecture decisions: why YAML over Rego, why deterministic over probabilistic, how <1ms is achieved, the three enforcement paths. Include architecture diagrams, code snippets. End with call for contributors.

**Day 14: Publish GitHub Action**

Create `avakill/avakill-action@v1` and publish to GitHub Marketplace. This creates a **passive distribution channel** — every repo that adds the action exposes AvaKill to all contributors. Follow Ruff's model with pre-commit hook integration as well.

---

### Week 3: Product Hunt launch + podcast/press outreach

**Day 15–16: Product Hunt launch**

**Product Hunt tagline:** `Open-source safety firewall for AI coding agents — blocks dangerous actions in <1ms`

PH preparation:
- Find a Hunter. Flo Merian is the top hunter for developer tools — Aikido Security used him and hit #1 Product of the Day. Reach out via Twitter/X or PH DM.
- Gallery images: Problem (incident screenshots) → Solution (AvaKill demo) → Features (three enforcement paths) → Outcome (compliance badges, test results).
- Demo video: 20–45 seconds, crisp. The 60-second terminal demo trimmed down.
- Launch at **12:01 AM Pacific Time**. Activate community immediately. Post in Discord, tweet, email early supporters.
- PH evaluates: Useful, Well-built, Novel, Community-fit. AvaKill scores well on all four.

**Product Hunt is secondary to Hacker News for dev tools.** Watermelon's data showed HN produced more active installs and paying interest. PH's main value: SEO backlinks, the Product Hunt badge (social proof), and reaching technical founders who don't read HN. **Staggering by 2 weeks** is intentional — PH launch benefits from the social proof accumulated during the HN week (star count, testimonials from HN thread, blog post traffic).

**Day 17–21: Podcast and press outreach**

**Podcast targets (ranked by fit):**

| Podcast | Fit | Approach |
|---------|-----|----------|
| **Open Source Security Podcast** (Josh Bressers) | PERFECT — already covered Goose/AAIF and Anubis AI firewall in Feb 2026 | Direct pitch. They actively feature OSS security tools weekly. |
| **Latent Space** (Swyx & Alessio Fanelli) | Strong — covers MCP, agent architecture, security regularly | Pitch via Twitter DM to Swyx. "Built with Claude Code to protect Claude Code" angle. |
| **Practical AI** (Changelog network) | Strong — real-world AI deployment, safety | Email changelog network. |
| **Unsupervised Learning** (Daniel Miessler) | Strong — AI + security intersection | Email pitch. |
| **The AI Native Developer** (Guy Podjarny) | Strong — AI-native development focus | Pitch via LinkedIn. |

**Press targets (if pursuing media coverage):**

The strongest pitch angle: **"AI agents have destroyed production at Replit, Amazon, and Google. This open-source tool stops them."** Tie directly to documented incidents, cite the 63/63 red team stat, and position AvaKill as the first dedicated solution.

| Journalist | Outlet | Why |
|-----------|--------|-----|
| Sharon Goldman | VentureBeat | Senior writer covering AI safety specifically |
| Rosalie Chan | Business Insider | Covers developer tools, DevOps, open source — highest-priority target |
| Ina Fried | Axios (AI+ newsletter) | Chief tech correspondent, daily AI newsletter |
| Fortune tech team | Fortune | Ran the definitive "AI coding tools security" piece in December 2025 — pitch follow-up |
| Help Net Security team | Help Net Security | Already covered Superagent (direct competitor) in December 2025 |

---

### Weeks 4–5: Conference submissions + second content wave

**Conference submissions (time-sensitive):**

| Conference | Dates | CFP Status | Action |
|-----------|-------|-----------|--------|
| **Black Hat USA 2026 Arsenal** | August 1–6, Las Vegas | CFP opened January 27, 2026 | Submit NOW. Arsenal is specifically for open-source tool demos — perfect for AvaKill. |
| **DEF CON 34 AI Village** | August 6–9, Las Vegas | Open calls announced | Submit when CFP opens. AI Village is the highest-relevance venue. |
| **AI Engineer World's Fair** | June 4–5, San Francisco | Check ai.engineer | Submit immediately if CFP open. Exactly AvaKill's target audience. MCP track, Agent Reliability track. |
| **BSides Las Vegas** | Same week as DEF CON/Black Hat | Rolling | Low barrier, community-driven. Submit lightning talk. |
| **PyCon US 2026** | May 13–19, Long Beach, CA | CFP closed Dec 19, 2025 | Main talks closed, but: Poster sessions (May 14–17) may still accept. Sprints (May 18–19, free) — run an AvaKill contributor sprint. Startup Row may be available. |
| **KubeCon NA 2026** | November 9–12, Salt Lake City | CFP opens ~June | Submit to Open Source SecurityCon co-located event. |

**Second content wave (Days 22–35):**

- **Blog post:** "Deterministic vs. LLM-based guardrails: why your AI safety tool shouldn't use an LLM" — positions AvaKill against LlamaFirewall (Meta) and NeMo Guardrails (NVIDIA). Target SEO keyword: "AI guardrails comparison."
- **Blog post:** "MCP security in 5 minutes: why your AI coding assistant has root access" — educational content targeting "MCP security" keyword.
- **YouTube video (8–12 minutes):** "Why I built a firewall for AI agents in one week" — founder story, architecture walkthrough, red team demonstration. Post natively on YouTube AND as native video clips on X.
- **Second HN post:** Submit the "deterministic vs. LLM-based" blog post as a regular HN link. Different URL, different angle, reaches different audience segment.

---

### Weeks 6–8: Community deepening + partnership outreach

**Community acceleration:**
- Launch a **"Break AvaKill" red team challenge** — invite security researchers to bypass policies. Offer recognition (Hall of Fame page) and swag for successful bypasses. Security researchers love this format, and it generates credibility content ("N researchers tried, here's what they found").
- Create a **YAML policy sharing library** — community-contributed policies for specific use cases (protect against file deletion, block network exfiltration, prevent credential access). This becomes a valuable resource that draws traffic.
- Start a weekly **"AI Agent Incident of the Week"** thread on Twitter/X and in Discord. Curate the latest disaster with technical analysis and the AvaKill policy that would prevent it.

**Partnership outreach:**
- **Claude Code ecosystem:** Submit AvaKill to awesome-claude-code repos (3 exist with 1K–5.5K stars). Create a Claude Code plugin (`.claude-plugin/plugin.json` + hooks). Reach out to Anthropic's alignment team — they'd naturally be interested in a safety layer for their flagship product.
- **Cursor:** AvaKill's MCP proxy works via Cursor Settings → MCP → Add New MCP Server. Create a one-click setup guide. Cursor has 300+ employees and a partnership team at their **$29.3B valuation**.
- **Windsurf:** Contact about inclusion in their curated MCP server list (one-click setup in Windsurf settings).
- **Gemini CLI:** `gemini mcp add avakill` integration documentation.
- **OpenAI Codex CLI:** `codex mcp add` integration documentation. Codex has **62,365 GitHub stars** — large community overlap.

**Academic outreach:**
- Contact **MIRI**, **CHAI** (UC Berkeley, Stuart Russell), **MIT AI Alignment (MAIA)**, **Stanford HAI**, **FAR.AI**, and **METR** about AvaKill as a practical safety tool for AI agent research.
- Create teaching-edition policy examples for university AI safety courses.

---

## Channel-by-channel tactical reference

### Hacker News: what the data says

Analysis of 157,000+ Show HN posts (Myriade, July 2025) reveals optimal parameters: **Sunday** has the highest breakout rate at **11.75%** versus 9.45–9.90% on weekdays. The **12:00 UTC** slot (8 AM Eastern) hits **12.2% breakout rate**. The best single window is Sunday 0–2 UTC at **15.7%**.

An ArXiv paper analyzing 138 AI/LLM tool launches found the average HN launch produces **121 GitHub stars within 24 hours** and **289 within a week**. But the distribution is heavily skewed — a few posts go viral and pull the average up.

Key rules: Link to GitHub repo (not landing page). Say "open-source" in the title. Use personal voice, not corporate. Be ready to engage in comments within seconds. **Never** orchestrate upvotes — HN's detection is sophisticated and the penalties are severe.

The multi-post strategy is officially supported by HN and demonstrably effective. Onlook got 1,000+ stars from their first Show HN. Space posts by at least a week and **always use a different URL** (greyed-out titles kill repeat posts).

### Product Hunt: diminished but still worth it

Product Hunt has **2.7 million monthly uniques** and a 91 domain rating. But it now favors well-funded startups with marketing teams. The PH team **manually selects** homepage products. For developer tools specifically, HN produces more engaged users — Watermelon's data showed HN generated more installs and paying interest than PH.

PH's value for AvaKill is social proof, SEO backlinks, and reaching technical founders who don't browse HN. Aikido Security hit **#1 Product of the Day** using hunter Flo Merian. Kilo Code hit #1 and later raised $8M. Both are security/AI dev tools.

**Launch day rules:** All products go live at 12:01 AM Pacific. First 4 hours are critical — PH hides vote counts during this window. The 20–45 second demo video is the most important asset.

### Reddit: the goldmine hiding in plain sight

The AI agent safety conversation on Reddit is white-hot. The Replit incident generated front-page threads across r/ChatGPT, r/programming, and LinkedIn. Every incident creates a natural discussion thread where AvaKill is the answer to "why don't these tools have guardrails?"

**Reddit's engagement velocity algorithm** means the first 15–30 minutes determine everything. A post getting 10 upvotes in the first hour dramatically outranks one with 50 upvotes over 24 hours. Comments are weighted more heavily than upvotes. Best posting time: **6–9 AM Eastern, Tuesday through Thursday**.

The **9:1 rule** is non-negotiable: for every promotional post, contribute 9 genuinely helpful comments. The founder's account should have genuine contribution history before any product mention. Use Reddit's designated promo windows: r/netsec's **Soapbox Monday**, r/webdev's **Showoff Saturday**, r/cybersecurity's weekly self-promotion thread.

**Set up F5Bot** (free service) immediately with keyword alerts for: "AI agent safety," "Claude Code dangerous," "coding agent deleted," "MCP security," "AI agent firewall." When relevant threads appear, reply with genuine technical insight that naturally leads to AvaKill.

### Twitter/X and Bluesky: the dual-platform approach

X remains the primary real-time platform for developer discourse with **540M+ monthly active users**, but meaningful migration to Bluesky has occurred — especially among open-source developers, AI safety researchers, and the exact audience AvaKill needs. Simon Willison is active on both platforms. AvaKill should maintain presence on both.

X's algorithm scoring: **(Likes × 1) + (Retweets × 20) + (Replies × 13.5) + (Profile Clicks × 12) + (Link Clicks × 11) + (Bookmarks × 10)**. Retweets are worth **20x** a like. Create shareable content — the incident list tweet is designed to be retweeted standalone. Never put links in the main tweet; X deprioritizes outbound links. Use native video uploads only.

**Lead with the founder's personal account.** Every successful OSS project (Directus, Wasp, Coolify, Cursor) grew through founder personality accounts. "I built..." is 10x more engaging than "We launched..." The brand @AvaKill account handles announcements, release notes, and amplification.

On Bluesky, AvaKill gets **disproportionate visibility** — smaller accounts (0–100K followers) get more interactions per post on Bluesky than X. Use a custom domain handle (@avakill.com) for free verification.

### Technical content and SEO: the keywords that matter

The highest-opportunity SEO keywords, based on competitive analysis and search volume:

- **"MCP security"** and **"MCP gateway"** — booming category. An Integrate.io article already lists "15 Best MCP Gateways and AI Agent Security Tools (2026)." Get on this list.
- **"AI agent guardrails"** — high volume but competitive (NVIDIA, Google, Guardrails AI, LangChain all rank). Target long-tail: "AI agent guardrails for coding tools."
- **"Claude Code safety"** / **"Cursor security"** — specific, high purchase intent, and underserved.
- **"prevent AI agent from deleting files"** — extremely high intent, almost no content exists.
- **"deterministic AI guardrails"** — AvaKill's unique technical differentiator. No competition.
- **"vibe coding safety"** / **"vibe coding risks"** — trending after Replit incident.

The most direct competitor to monitor is **mcpwall** (GitHub: behrensd/mcpwall), which also positions itself as "iptables for MCP" with deterministic YAML policies. AvaKill's differentiation: three enforcement paths (not just MCP proxy), cross-agent support, 63/63 red team results, compliance mapping, and the 2,108-test suite.

### Video: terminal-first, hooks-second

Fireship's "100 Seconds of Code" format is the gold standard for developer tool videos — **4.1M subscribers**, **706K average views**. For AvaKill, the format translates directly to a 60-second terminal demo.

The three video assets needed (in priority order):

1. **60-second terminal demo** (YouTube Short + X native video + Reddit embed): Install → configure → attack blocked. No talking head. Text overlays. Captions for muted viewing. Use asciinema or Screen Studio.
2. **3–5 minute full demo** (YouTube): All three enforcement paths. Multiple attack scenarios. YAML policy walkthrough. End with `pipx install avakill` CTA.
3. **8–12 minute founder story** (YouTube): "Why I built a firewall for AI agents in one week." Personal narrative, architecture decisions, red team results, the ouroboros angle. This is for podcast-style audiences.

Target YouTube channels for organic coverage: **Fireship** (4.1M — AvaKill is a natural "Code Report" topic), **Theo/t3.gg** (~500K — covers AI tools), **NetworkChuck** (4M — security tutorials), **AI Code King** (~200K — reviews exactly this type of tool), **John Hammond** (~1.5M — cybersecurity demos).

### Community building: Discord + GitHub Discussions

The consensus across successful OSS AI projects (LangChain, CrewAI, AutoGPT) is **Discord for real-time community** and **GitHub Discussions for async, searchable, SEO-indexed Q&A**. This dual-platform approach mirrors what OPA uses (Slack + GitHub) and what Falco uses.

**Seeding the first community activity:**
- Pre-populate GitHub Discussions with FAQ, 10+ YAML policy examples, and integration guides before any public launch.
- Create a private Discord channel for top 50 earliest contributors (ScrapeGraphAI's model for 0→20K stars). Monthly office hours for feedback.
- The **"good first issue" strategy** is critical for contributor growth. Create 10+ issues labeled `good-first-issue`: adding YAML policy templates, documentation improvements, integration test additions, new MCP server compatibility. Register on goodfirstissue.dev.
- Plan for **Hacktoberfest** (October 2026) — tag issues with `hacktoberfest` label well in advance.

---

## Viral mechanics built into the product

### The badge/attribution loop

Shields.io serves **1.6 billion images per month**. Every badge in a README is a permanent, passive brand impression. Create and promote these badges:

```markdown
[![Protected by AvaKill](https://img.shields.io/badge/🛡️_Protected_by-AvaKill-brightgreen)](https://github.com/log-bell/avakill)
```

```markdown
[![AvaKill: 63/63 Attacks Blocked](https://img.shields.io/badge/Red_Team-63%2F63_Blocked-brightgreen)](https://github.com/log-bell/avakill)
```

Provide copy-paste badge markdown in the README, docs, and post-install CLI output. Auto-generate custom badges based on user's policy configuration. Every badge links back to the repo.

### CI/CD as distribution

Publish `avakill/avakill-action@v1` to GitHub Marketplace. Create a pre-commit hook integration (following Ruff's `ruff-pre-commit` model, which is widely adopted). Every CI run shows AvaKill output in PR checks, exposing the tool to every contributor on every PR. This is **passive, compounding distribution**.

### AGPL-3.0 as commercial moat and growth engine

AGPL is a strategic asset, not just a license choice. **Google bans all AGPL code internally.** Any company wrapping AvaKill in their product must open-source their modifications OR purchase a commercial license. This creates the dual-licensing revenue model used by MongoDB (pre-SSPL), Grafana, Plausible, and OpenObserve.

Plausible Analytics switched from MIT to AGPL specifically to prevent corporations from forking without contributing: "The goal of the AGPL license is to maximize user freedom and encourage companies to contribute to open source." OpenObserve moved from Apache 2.0 to AGPL 3.0, reasoning that "open source projects capture 1–5% of the value they create — AGPL plus a commercial version ensures we can do that."

For AvaKill, AGPL means cloud providers can't offer "AvaKill-as-a-service" without open-sourcing their wrapper. Enterprise customers who need proprietary integration must purchase a commercial license. This is the conversion path to the planned SaaS platform.

### The incident-response content flywheel

The single most sustainable growth mechanic: **every AI agent disaster is a marketing event**. These happen monthly and generate massive discussion across HN, Reddit, Twitter/X, and mainstream press.

**Create a template and process:**
1. Monitor for incidents via F5Bot (Reddit), Twitter/X lists, and HN keyword alerts.
2. Within 2–4 hours of a new incident: publish a blog post titled "How AvaKill would have prevented [incident]" with the specific YAML policy.
3. Post the analysis (not AvaKill promo — the analysis) to relevant Reddit threads and Twitter/X.
4. Link to AvaKill as one approach in the solution section.

This positions AvaKill as the authoritative voice on AI agent safety, not as a product hawking itself.

---

## How to tell the "built in one week" story

The "built in one week" narrative is a **net positive** but requires precise framing. For general developer tools, speed signals scrappiness and skill. For security tools, it can trigger skepticism about thoroughness. The key is **leading with evidence, then revealing the timeline**.

**The winning frame:** "2,108 tests. 63/63 red team attacks blocked. <1ms evaluation. Built in one week — because the architecture is deliberately simple. No ML. No API calls. YAML policies evaluated deterministically. The tool is fast to build because it's fast to run."

Test count BEFORE timeline. Evidence BEFORE the claim. Simplicity-as-security-model BEFORE speed-as-efficiency.

**The ouroboros angle is AvaKill's strongest narrative hook.** "Built with Claude Code to protect Claude Code" is a perfect meta-story that resonates with the vibe coding movement and Anthropic's own "antfooding" culture (70–80% of Anthropic technical employees use Claude Code daily). This narrative works because:
- It proves Claude Code can build production-grade security tools.
- It proves AvaKill works in the environment it protects.
- It creates "AI that guards AI" — inherently shareable and memorable.

**Where this story resonates most:** Hacker News (loves technical underdog stories), Indie Hackers (solo founder angle), Twitter/X (the meta narrative is tweet-native), and podcasts (10-minute story arc).

**Where to be careful:** r/netsec and security conferences expect maturity signals — audit results, formal threat models, SECURITY.md, CVD process. Lead with technical credibility there, mention timeline only in passing.

---

## Risk register and mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| HN crowding — "yet another AI agent firewall" | HIGH | Show HN gets 2–7 points like competitors | Differentiate sharply in title (<1ms, deterministic, no ML). Lead with specific incidents. Post on Sunday for lower competition. |
| Security community backlash on "built in one week" | MEDIUM | Credibility damage in r/netsec, security conferences | Never lead with timeline in security contexts. Lead with 2,108 tests and 63/63 red team. Commission third-party audit within 90 days. |
| Reddit self-promotion removal | MEDIUM | Posts deleted, account flagged | Build karma for 2+ weeks before any product mention. Use designated promo threads. Follow 9:1 rule. |
| mcpwall or other competitor launches first with HN traction | MEDIUM | AvaKill perceived as copycat | Differentiate on three enforcement paths (not just MCP proxy). Publish comparison content early. |
| X algorithm buries launch thread | LOW-MEDIUM | Thread gets <1K impressions | Use native video (2–4x reach boost). No external links in main tweets. Engage in first 30 minutes. Consider X Premium ($8/mo). |
| "Built by AI" undermines human credibility | LOW | "If an AI wrote the security tool, can we trust it?" | Frame as "AI-assisted, human-directed." Emphasize the 2,108 hand-designed tests and human-crafted policy architecture. |
| AGPL scares away enterprise users | LOW | Fewer corporate installs | This is a feature, not a bug — AGPL drives commercial license revenue. Address with clear dual-licensing FAQ page. |

---

## Recommended tools for execution

| Category | Tool | Why |
|----------|------|-----|
| Social scheduling | **Typefully** | Built by indie hackers, optimized for Twitter/X threads. Analytics. |
| Reddit monitoring | **F5Bot** | Free keyword alerts. Set up for "AI agent safety," "Claude Code dangerous," "MCP security." |
| Terminal recording | **asciinema** or **Screen Studio** | For demo videos. asciinema is open-source and terminal-native. |
| Analytics | **PostHog** (open-source) or **Plausible** (AGPL-licensed) | Track website + GitHub star events. PostHog has GitHub star tracking built in. |
| Star tracking | **star-history.com** | Free, shareable star growth visualizations. Embed in README once growth starts. |
| Community | **Discord** (real-time) + **GitHub Discussions** (async) | Industry standard for OSS. |
| Newsletter | **ConvertKit/Kit** or **Buttondown** | For developer newsletter. Buttondown is simpler and developer-friendly. |
| Docs | **Mintlify** | Auto-generates llms.txt. Modern, developer-focused docs platform. |
| Email outreach | **Resend** | For transactional emails and press/podcast pitches. Developer-built. |

---

## Conclusion: the window is now but it's closing

AvaKill has a rare convergence of product-market timing: documented AI agent disasters making monthly headlines, zero established open-source safety standard, and a product architecture (deterministic, <1ms, YAML) that maps cleanly to the problem. But the window is closing — **at least 7 competitors have already posted on HN**, mcpwall directly competes on the "iptables for MCP" positioning, and Meta's LlamaFirewall gives the category enterprise legitimacy.

The highest-leverage sequence is clear: **polish the demo video and README → seed 100 GitHub stars → launch on HN Sunday morning → ride to GitHub Trending → follow with Reddit, X, and newsletters in the same week → Product Hunt two weeks later → podcasts and press in week three → conference submissions in week four.** Every subsequent action amplifies the previous one.

The single most important relationship to build is with **Simon Willison**. The single most important asset to create is the **60-second terminal demo**. The single most important narrative frame is **"2,108 tests, 63/63 attacks blocked, built in one week — because deterministic security should be simple."** Execute these three correctly and the rest follows.

---


