/**
 * Deck Variant System — Structured slide data for slides 1–4.
 *
 * Slides 5–12 are shared across all variants and stay as static HTML.
 * Each variant defines slides 1–4 as structured data that the deck
 * builder renders into the existing CSS class system.
 *
 * SECURITY NOTE: All content is hardcoded constants — no user input,
 * no external data. DOM updates from trusted source only.
 */

const VARIANTS = [
  // ─── VARIANT 1: GENERAL (current deck, optimized for generalist VCs) ───
  {
    id: "general",
    meta: {
      name: "General",
      audience: "Generalist VCs and pre-seed investors evaluating AI infrastructure opportunities",
      summary: "Use for broad fundraising outreach and first meetings with generalist funds",
    },
    slides: [
      {
        number: 1,
        type: "title",
        headline: "The AI Safety Firewall.",
        subline:
          "An open-source firewall that intercepts every AI agent tool call and enforces safety policies before damage is done.",
      },
      {
        number: 2,
        type: "problem",
        headline:
          "AI Agents Execute Code Autonomously \u2014 With Zero Safety Enforcement",
        stats: [
          {
            number: "1,184",
            desc: "Malicious skills uploaded to ClawHub in 72 hours (ClawHavoc, Jan 2026)",
          },
          {
            number: "9,000+",
            desc: "Installations compromised \u2014 credentials, SSH keys, wallets stolen",
          },
          {
            number: "17,500+",
            desc: "Instances exposed to one-click RCE via CVE-2026-25253 (CVSS 8.8)",
          },
        ],
        contextParts: [
          { text: "Every engineering team shipping AI agents has zero policy enforcement between the agent and their infrastructure.", bold: true },
          { text: " 91% of ClawHavoc payloads used prompt injection to execute commands autonomously \u2014 no human clicked \u201capprove.\u201d", bold: false },
        ],
      },
      {
        number: 3,
        type: "why-now",
        headline: "Three Forces Converging in 2026",
        columns: [
          {
            date: "Jan 27, 2026",
            title: "The Crisis",
            anchor: "9,000+ compromised in 72 hours",
            points: [
              "First large-scale AI agent supply chain attack",
              "Kakao, Naver banned OpenClaw on corporate networks",
            ],
          },
          {
            date: "Aug 2, 2026",
            title: "The Regulation",
            anchor: "\u20ac35M fines activate Aug 2, 2026",
            points: [
              "EU AI Act high-risk AI compliance enforcement",
              "Conformity assessments + national enforcement powers",
            ],
          },
          {
            date: "2024 \u2192 2028",
            title: "The Market",
            anchor: "<$1B \u2192 $51.5B by 2028",
            points: [
              "AI security market at 74% CAGR (Gartner)",
              "$18B invested in cybersecurity startups in 2025",
            ],
          },
        ],
      },
      {
        number: 4,
        type: "solution",
        headline: "One Policy File Controls Every AI Agent",
        policyBox: {
          title: "avakill.yaml",
          sub: "One policy file \u2014 single source of truth",
        },
        paths: [
          {
            title: "Hooks",
            optional: false,
            items: ["Claude Code, Cursor,", "+ 5 more platforms"],
            subtitle: "Standalone \u00b7 In-process",
          },
          {
            title: "MCP Proxy",
            optional: false,
            items: ["Wraps any", "MCP server", "transparently"],
            subtitle: "Standalone \u00b7 In-process",
          },
          {
            title: "OS Sandbox",
            optional: false,
            items: ["Linux, macOS,", "Windows"],
            subtitle: "Standalone \u00b7 OS-level",
          },
          {
            title: "Daemon",
            optional: true,
            optionalTag: "(optional)",
            items: [
              "Shared evaluation",
              "Audit logging",
              "Approvals",
              "Metrics",
            ],
            subtitle: "Optional \u00b7 Shared eval",
          },
        ],
        tagline:
          "Open-source. Deterministic. Zero code changes. Sub-millisecond enforcement.",
      },
    ],
  },

  // ─── VARIANT 2: CISO (for security executives) ───
  {
    id: "ciso",
    meta: {
      name: "CISO",
      audience:
        "CISOs, security executives, and compliance-focused investors who evaluate through risk frameworks",
      summary:
        "Use when pitching security-focused funds or presenting to enterprise security leadership",
    },
    slides: [
      {
        number: 1,
        type: "title",
        headline: "Policy Enforcement for Autonomous AI Agents.",
        subline:
          "Deterministic, auditable policy controls that map to NIST AI RMF, ISO 42001, and OWASP Agentic Security Top 10 \u2014 deployed in under 60 seconds.",
      },
      {
        number: 2,
        type: "problem",
        headline:
          "INCIDENT: ClawHavoc \u2014 The First AI Agent Supply Chain Attack",
        stats: [
          {
            number: "1,184",
            desc: "Malicious payloads bypassed every existing control \u2014 zero detection by EDR, SIEM, or CSPM tools",
          },
          {
            number: "9,000+",
            desc: "Compromised environments \u2014 credential exfiltration, lateral movement, persistent access established",
          },
          {
            number: "0",
            desc: "Existing frameworks covered autonomous AI agent tool execution at time of incident",
          },
        ],
        contextParts: [
          { text: "Root cause:", bold: true },
          { text: " AI agents execute tool calls outside the perimeter \u2014 no approval workflow, no policy gate, no audit trail. OWASP Agentic Security Top 10 classifies this as ", bold: false },
          { text: "AS-01: Excessive Agency", bold: true },
          { text: ".", bold: false },
        ],
      },
      {
        number: 3,
        type: "why-now",
        headline: "Compliance Deadlines Are Forcing the Conversation",
        columns: [
          {
            date: "NIST AI RMF",
            title: "Risk Framework Gap",
            anchor: "MANAGE 2.2 requires pre-deployment controls",
            points: [
              "MAP/MEASURE/MANAGE functions have no tooling for agent actions",
              "Autonomous tool execution is unmapped in most AI risk registers",
            ],
          },
          {
            date: "Aug 2, 2026",
            title: "EU AI Act Enforcement",
            anchor: "\u20ac35M penalties or 7% global revenue",
            points: [
              "High-risk AI systems require conformity assessment + audit logs",
              "Article 14: human oversight mandates for autonomous operations",
            ],
          },
          {
            date: "ISO 42001 \u00b7 SOC 2",
            title: "Audit Requirements",
            anchor: "Auditors asking questions teams can\u2019t answer",
            points: [
              "ISO 42001 A.6.2.6: AI system operation monitoring and controls",
              "SOC 2 CC6.1: logical access controls now include AI agent actions",
            ],
          },
        ],
      },
      {
        number: 4,
        type: "solution",
        headline: "Unified Policy Enforcement Across All AI Agent Surfaces",
        policyBox: {
          title: "avakill.yaml",
          sub: "Declarative policy \u2014 maps to NIST AI RMF MANAGE function",
        },
        paths: [
          {
            title: "Hooks",
            optional: false,
            items: ["Pre-execution gates", "for 8 agent platforms"],
            subtitle: "OWASP AS-01 \u00b7 AS-04",
          },
          {
            title: "MCP Proxy",
            optional: false,
            items: ["Policy enforcement", "at tool boundary"],
            subtitle: "OWASP AS-05 \u00b7 AS-09",
          },
          {
            title: "OS Sandbox",
            optional: false,
            items: ["Kernel-level", "process isolation"],
            subtitle: "NIST MANAGE 2.2",
          },
          {
            title: "Audit Daemon",
            optional: true,
            optionalTag: "(optional)",
            items: [
              "Tamper-proof logs",
              "Approval workflows",
              "Compliance reports",
              "SOC 2 evidence",
            ],
            subtitle: "ISO 42001 A.6.2.6",
          },
        ],
        tagline:
          "Deterministic enforcement. Full audit trail. Maps to NIST AI RMF, ISO 42001, OWASP Agentic Security Top 10, and EU AI Act Article 14.",
      },
    ],
  },

  // ─── VARIANT 3: OSS INFRASTRUCTURE (for open-source / infrastructure investors) ───
  {
    id: "oss-infra",
    meta: {
      name: "OSS Infrastructure",
      audience:
        "Open-source and infrastructure investors who evaluate developer adoption, community dynamics, and dual-license monetization",
      summary:
        "Use for infrastructure-focused funds and investors who backed Elastic, HashiCorp, or MongoDB",
    },
    slides: [
      {
        number: 1,
        type: "title",
        headline: "The Open-Source Standard for AI Agent Security.",
        subline:
          "AGPL-licensed infrastructure that every AI agent hooks into \u2014 the security layer developers install before shipping agents to production.",
      },
      {
        number: 2,
        type: "problem",
        headline:
          "Every Team Is Building Their Own AI Agent Guardrails from Scratch",
        stats: [
          {
            number: "82:1",
            desc: "Machine identities to human employees in the enterprise \u2014 each one an uncontrolled execution surface",
          },
          {
            number: "16,000+",
            desc: "MCP servers deployed in 2025 \u2014 zero standardized policy enforcement across any of them",
          },
          {
            number: "0",
            desc: "Open-source projects that provide agent-agnostic, pre-execution policy enforcement today",
          },
        ],
        contextParts: [
          { text: "The pattern is familiar:", bold: true },
          { text: " every team writes custom middleware, ad-hoc allowlists, and bespoke approval flows. Same fragmentation we saw before Kubernetes standardized container orchestration.", bold: false },
        ],
      },
      {
        number: 3,
        type: "why-now",
        headline:
          "The Playbook Is Proven \u2014 Infrastructure Layer Capture at the Inflection Point",
        columns: [
          {
            date: "The Precedent",
            title: "AGPL Dual-License Playbook",
            anchor: "Elastic, HashiCorp, MongoDB",
            points: [
              "AGPL forces commercial users to buy a license or go copyleft",
              "3 of the 5 largest OSS IPOs used this exact monetization model",
            ],
          },
          {
            date: "The Adoption Mechanics",
            title: "Developer-Led Bottom-Up",
            anchor: "pipx install avakill \u2192 production",
            points: [
              "60-second install, zero config needed \u2014 individual devs adopt first",
              "Teams adopt when one developer\u2019s avakill.yaml blocks a dangerous call",
            ],
          },
          {
            date: "The Inflection",
            title: "Agents Ship Faster Than Controls",
            anchor: "40% of enterprise apps will embed AI agents by 2026",
            points: [
              "Gartner: agent adoption is outpacing every prior enterprise software wave",
              "Security team headcount is flat \u2014 policy-as-code is the only path that scales",
            ],
          },
        ],
      },
      {
        number: 4,
        type: "solution",
        headline: "One YAML File. Three Enforcement Paths. Any AI Agent.",
        policyBox: {
          title: "avakill.yaml",
          sub: "DevOps-native YAML \u2014 teams already know it from Kubernetes",
        },
        paths: [
          {
            title: "Hooks",
            optional: false,
            items: [
              "8 native integrations",
              "Community-extensible",
            ],
            subtitle: "Drop-in \u00b7 Zero config",
          },
          {
            title: "MCP Proxy",
            optional: false,
            items: [
              "Transparent wrapper",
              "for any MCP server",
            ],
            subtitle: "Protocol-native",
          },
          {
            title: "OS Sandbox",
            optional: false,
            items: [
              "Landlock, sandbox-exec,",
              "AppContainer",
            ],
            subtitle: "Kernel-level",
          },
          {
            title: "Daemon",
            optional: true,
            optionalTag: "(enterprise)",
            items: [
              "Central policy mgmt",
              "Audit logging",
              "Fleet enforcement",
              "SSO + RBAC",
            ],
            subtitle: "Paid tier \u00b7 Dual-license",
          },
        ],
        tagline:
          "AGPL-3.0 licensed. Zero vendor lock-in. Community-extensible policy library. 2,108 passing tests.",
      },
    ],
  },
];

// ─── RENDERERS: Build slide DOM from structured data ───
// All content originates from the hardcoded VARIANTS constants above.

const RENDERERS = {
  title(slide, container) {
    container.textContent = "";

    const content = document.createElement("div");
    content.className = "slide-1-content";

    const logoWrap = document.createElement("div");
    logoWrap.className = "slide-1-logo-wrap";
    const logo = document.createElement("img");
    logo.src = "../avakill-logo.png";
    logo.alt = "AvaKill logo";
    logo.className = "slide-1-logo";
    logoWrap.appendChild(logo);
    content.appendChild(logoWrap);

    const brand = document.createElement("div");
    brand.className = "slide-1-brand";
    brand.textContent = "AvaKill";
    content.appendChild(brand);

    const h1 = document.createElement("h1");
    h1.className = "slide-1-headline";
    h1.textContent = slide.headline;
    content.appendChild(h1);

    const sub = document.createElement("p");
    sub.className = "slide-1-subline";
    sub.textContent = slide.subline;
    content.appendChild(sub);

    container.appendChild(content);

    // Bottom bar (same across all variants)
    const bar = document.createElement("div");
    bar.className = "slide-1-bar";
    const items = ["Logan Bell, Founder", "logan@avakill.com", "310-913-1024", "avakill.com"];
    items.forEach((text, i) => {
      if (i > 0) {
        const sep = document.createElement("span");
        sep.className = "sep";
        sep.textContent = "|";
        bar.appendChild(sep);
      }
      const span = document.createElement("span");
      span.textContent = text;
      bar.appendChild(span);
    });
    container.appendChild(bar);
  },

  problem(slide, container) {
    container.textContent = "";

    const content = document.createElement("div");
    content.className = "slide-2-content";

    const h2 = document.createElement("h2");
    h2.className = "slide-2-headline";
    h2.textContent = slide.headline;
    content.appendChild(h2);

    const statsGrid = document.createElement("div");
    statsGrid.className = "slide-2-stats";
    slide.stats.forEach((s) => {
      const stat = document.createElement("div");
      stat.className = "slide-2-stat";

      const num = document.createElement("div");
      num.className = "slide-2-stat-number";
      num.textContent = s.number;
      stat.appendChild(num);

      const desc = document.createElement("div");
      desc.className = "slide-2-stat-desc";
      desc.textContent = s.desc;
      stat.appendChild(desc);

      statsGrid.appendChild(stat);
    });
    content.appendChild(statsGrid);

    const ctx = document.createElement("p");
    ctx.className = "slide-2-context";
    slide.contextParts.forEach((part) => {
      if (part.bold) {
        const strong = document.createElement("strong");
        strong.textContent = part.text;
        ctx.appendChild(strong);
      } else {
        ctx.appendChild(document.createTextNode(part.text));
      }
    });
    content.appendChild(ctx);

    container.appendChild(content);
  },

  "why-now"(slide, container) {
    container.textContent = "";

    const content = document.createElement("div");
    content.className = "slide-3-content";

    const h2 = document.createElement("h2");
    h2.className = "slide-3-headline";
    h2.textContent = slide.headline;
    content.appendChild(h2);

    const cols = document.createElement("div");
    cols.className = "slide-3-columns";

    slide.columns.forEach((col) => {
      const colEl = document.createElement("div");
      colEl.className = "slide-3-col";

      const date = document.createElement("span");
      date.className = "slide-3-col-date";
      date.textContent = col.date;
      colEl.appendChild(date);

      const title = document.createElement("h3");
      title.className = "slide-3-col-title";
      title.textContent = col.title;
      colEl.appendChild(title);

      const anchor = document.createElement("div");
      anchor.className = "slide-3-col-anchor";
      anchor.textContent = col.anchor;
      colEl.appendChild(anchor);

      const points = document.createElement("div");
      points.className = "slide-3-col-points";
      col.points.forEach((p) => {
        const span = document.createElement("span");
        span.className = "slide-3-col-point";
        span.textContent = p;
        points.appendChild(span);
      });
      colEl.appendChild(points);

      cols.appendChild(colEl);
    });

    content.appendChild(cols);
    container.appendChild(content);
  },

  solution(slide, container) {
    container.textContent = "";

    const content = document.createElement("div");
    content.className = "slide-4-content";

    const h2 = document.createElement("h2");
    h2.className = "slide-4-headline";
    h2.textContent = slide.headline;
    content.appendChild(h2);

    const arch = document.createElement("div");
    arch.className = "slide-4-arch";

    // Policy box
    const policyBox = document.createElement("div");
    policyBox.className = "slide-4-policy-box";

    const policyTitle = document.createElement("div");
    policyTitle.className = "slide-4-policy-title";
    // Shield SVG
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z");
    svg.appendChild(path);
    policyTitle.appendChild(svg);
    policyTitle.appendChild(document.createTextNode(" " + slide.policyBox.title));
    policyBox.appendChild(policyTitle);

    const policySub = document.createElement("div");
    policySub.className = "slide-4-policy-sub";
    policySub.textContent = slide.policyBox.sub;
    policyBox.appendChild(policySub);

    arch.appendChild(policyBox);

    // Connector
    const connector = document.createElement("div");
    connector.className = "slide-4-connector";
    arch.appendChild(connector);

    const connectorFan = document.createElement("div");
    connectorFan.className = "slide-4-connector-fan";
    arch.appendChild(connectorFan);

    // Paths
    const pathsGrid = document.createElement("div");
    pathsGrid.className = "slide-4-paths";

    slide.paths.forEach((p) => {
      const pathEl = document.createElement("div");
      pathEl.className = "slide-4-path" + (p.optional ? " slide-4-path--optional" : "");

      const title = document.createElement("div");
      title.className = "slide-4-path-title";
      title.textContent = p.title;
      pathEl.appendChild(title);

      if (p.optionalTag) {
        const tag = document.createElement("div");
        tag.className = "slide-4-path-optional-tag";
        tag.textContent = p.optionalTag;
        pathEl.appendChild(tag);
      }

      const items = document.createElement("div");
      items.className = "slide-4-path-items";
      p.items.forEach((item) => {
        const span = document.createElement("span");
        span.className = "slide-4-path-item";
        span.textContent = item;
        items.appendChild(span);
      });
      pathEl.appendChild(items);

      const subtitle = document.createElement("div");
      subtitle.className = "slide-4-path-subtitle";
      subtitle.textContent = p.subtitle;
      pathEl.appendChild(subtitle);

      pathsGrid.appendChild(pathEl);
    });

    arch.appendChild(pathsGrid);
    content.appendChild(arch);

    const tagline = document.createElement("p");
    tagline.className = "slide-4-tagline";
    tagline.textContent = slide.tagline;
    content.appendChild(tagline);

    container.appendChild(content);
  },
};

// ─── VARIANT SWITCHER ───

function initVariantSystem() {
  const deck = document.querySelector(".deck");
  if (!deck) return;

  // Cache the 4 variant-controlled slide elements (slides 1–4)
  const allSlides = deck.querySelectorAll(".slide");
  const variantSlides = Array.from(allSlides).slice(0, 4);

  // Build tab bar using DOM API
  const tabBar = document.createElement("div");
  tabBar.className = "variant-tab-bar";

  const tabs = document.createElement("div");
  tabs.className = "variant-tabs";

  VARIANTS.forEach((v, i) => {
    const btn = document.createElement("button");
    btn.className = "variant-tab" + (i === 0 ? " variant-tab--active" : "");
    btn.dataset.variant = v.id;
    btn.title = v.meta.summary;

    const name = document.createElement("span");
    name.className = "variant-tab-name";
    name.textContent = v.meta.name;
    btn.appendChild(name);

    const hint = document.createElement("span");
    hint.className = "variant-tab-hint";
    hint.textContent = v.meta.summary;
    btn.appendChild(hint);

    tabs.appendChild(btn);
  });

  tabBar.appendChild(tabs);
  deck.parentElement.insertBefore(tabBar, deck);

  // Render a variant into slides 1–4
  function renderVariant(variantId) {
    const variant = VARIANTS.find((v) => v.id === variantId);
    if (!variant) return;

    variant.slides.forEach((slideData, i) => {
      const renderer = RENDERERS[slideData.type];
      if (renderer && variantSlides[i]) {
        renderer(slideData, variantSlides[i]);
      }
    });

    // Update active tab
    tabBar.querySelectorAll(".variant-tab").forEach((btn) => {
      btn.classList.toggle(
        "variant-tab--active",
        btn.dataset.variant === variantId
      );
    });
  }

  // Tab click handler
  tabBar.addEventListener("click", (e) => {
    const tab = e.target.closest(".variant-tab");
    if (tab) renderVariant(tab.dataset.variant);
  });

  // Don't re-render general on load — the static HTML already has it.
  // Only render on tab switch.
}

// Init when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initVariantSystem);
} else {
  initVariantSystem();
}
