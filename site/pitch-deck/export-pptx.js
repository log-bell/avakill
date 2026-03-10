/**
 * PPTX Export — builds a PowerPoint deck from structured variant data + shared slides.
 *
 * Uses PptxGenJS (loaded via CDN in index.html).
 * Reads the active variant from VARIANTS for slides 1–4,
 * extracts shared slide content from the DOM for slides 5–12 + appendix.
 */

/* global PptxGenJS, VARIANTS */

// ─── Brand constants ───
const BG = "0A0F1E";
const WHITE = "F8F8F8";
const CYAN = "00D4FF";
const GRAY = "9CA3AF";
const RED = "EF4444";
const GREEN = "22C55E";
const DARK_CARD = "111827";
const FONT = "Satoshi";

// Slide dimensions: 16:9 (default for PptxGenJS)
// All positions in inches — slide is 10" x 5.625"

function getActiveVariantId() {
  const active = document.querySelector(".variant-tab--active");
  return active ? active.dataset.variant : "general";
}

function getActiveVariant() {
  const id = getActiveVariantId();
  return VARIANTS.find((v) => v.id === id) || VARIANTS[0];
}

// ─── Shared helpers ───

function addSlideNumber(slide, num, total) {
  slide.addText(`${num} / ${total}`, {
    x: 0, y: 5.2, w: 10, h: 0.4,
    fontSize: 8, color: "4B5563", align: "center", fontFace: FONT,
  });
}

function addSectionTitle(slide, text) {
  slide.addText(text, {
    x: 0.5, y: 0.25, w: 5, h: 0.3,
    fontSize: 8, bold: true, color: "4B5563",
    fontFace: FONT, letterSpacing: 1,
  });
}

// ─── Slide builders for variant slides (1–4) ───

function buildSlide1(pptx, data) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };

  slide.addText("AvaKill", {
    x: 0, y: 1.2, w: 10, h: 0.7,
    fontSize: 42, bold: true, color: CYAN, align: "center", fontFace: FONT,
  });

  slide.addText(data.headline, {
    x: 1, y: 1.95, w: 8, h: 0.6,
    fontSize: 32, bold: true, color: WHITE, align: "center", fontFace: FONT,
  });

  slide.addText(data.subline, {
    x: 1.2, y: 2.7, w: 7.6, h: 0.8,
    fontSize: 16, color: GRAY, align: "center", fontFace: FONT, lineSpacingMultiple: 1.3,
  });

  // Bottom bar
  slide.addText("Logan Bell, Founder  |  logan@avakill.com  |  310-913-1024  |  avakill.com", {
    x: 0, y: 5.1, w: 10, h: 0.4,
    fontSize: 10, color: "4B5563", align: "center", fontFace: FONT,
  });

  return slide;
}

function buildSlide2(pptx, data) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "THE PROBLEM");

  slide.addText(data.headline, {
    x: 0.5, y: 0.55, w: 9, h: 0.55,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT, lineSpacingMultiple: 1.15,
  });

  // Stats row
  data.stats.forEach((stat, i) => {
    const x = 0.5 + i * 3;
    slide.addShape(pptx.ShapeType.roundRect, {
      x, y: 1.3, w: 2.8, h: 1.8,
      fill: { color: "1C1017" },
      line: { color: "7F1D1D", width: 1 },
      rectRadius: 0.1,
    });
    slide.addText(stat.number, {
      x, y: 1.4, w: 2.8, h: 0.8,
      fontSize: 36, bold: true, color: RED, align: "center", fontFace: FONT,
    });
    slide.addText(stat.desc, {
      x: x + 0.2, y: 2.2, w: 2.4, h: 0.8,
      fontSize: 9, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.3,
    });
  });

  // Context line
  const contextText = data.contextParts.map((p) => p.text).join("");
  slide.addText(contextText, {
    x: 0.5, y: 3.4, w: 9, h: 0.6,
    fontSize: 11, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.4,
    bold: false,
  });

  addSlideNumber(slide, 2, 12);
  return slide;
}

function buildSlide3(pptx, data) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "WHY NOW");

  slide.addText(data.headline, {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  data.columns.forEach((col, i) => {
    const x = 0.5 + i * 3;

    slide.addShape(pptx.ShapeType.roundRect, {
      x, y: 1.25, w: 2.8, h: 3.4,
      fill: { color: DARK_CARD },
      line: { color: "0D3B4F", width: 1 },
      rectRadius: 0.1,
    });

    slide.addText(col.date, {
      x: x + 0.2, y: 1.35, w: 2.4, h: 0.25,
      fontSize: 8, bold: true, color: CYAN, fontFace: FONT, letterSpacing: 1,
    });

    slide.addText(col.title, {
      x: x + 0.2, y: 1.6, w: 2.4, h: 0.3,
      fontSize: 12, bold: true, color: WHITE, fontFace: FONT,
    });

    slide.addText(col.anchor, {
      x: x + 0.2, y: 1.95, w: 2.4, h: 0.6,
      fontSize: 18, bold: true, color: WHITE, fontFace: FONT, lineSpacingMultiple: 1.1,
    });

    const points = col.points.map((p) => ({ text: p, options: { bullet: true, color: GRAY, fontSize: 9, fontFace: FONT, lineSpacingMultiple: 1.4 } }));
    slide.addText(points, {
      x: x + 0.2, y: 2.7, w: 2.4, h: 1.6,
    });
  });

  addSlideNumber(slide, 3, 12);
  return slide;
}

function buildSlide4(pptx, data) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "THE SOLUTION");

  slide.addText(data.headline, {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  // Policy box
  slide.addShape(pptx.ShapeType.roundRect, {
    x: 3.2, y: 1.2, w: 3.6, h: 0.6,
    fill: { color: "0A1628" },
    line: { color: "0D6B8A", width: 1.5 },
    rectRadius: 0.08,
  });
  slide.addText(data.policyBox.title, {
    x: 3.2, y: 1.2, w: 3.6, h: 0.35,
    fontSize: 11, bold: true, color: CYAN, align: "center", fontFace: FONT,
  });
  slide.addText(data.policyBox.sub, {
    x: 3.2, y: 1.5, w: 3.6, h: 0.25,
    fontSize: 8, color: GRAY, align: "center", fontFace: FONT,
  });

  // Connector line
  slide.addShape(pptx.ShapeType.line, {
    x: 5, y: 1.8, w: 0, h: 0.25,
    line: { color: "0D6B8A", width: 1.5 },
  });

  // Paths
  data.paths.forEach((p, i) => {
    const x = 0.5 + i * 2.35;
    const borderColor = p.optional ? "0D3B4F" : "0D6B8A";
    const dashType = p.optional ? "dash" : "solid";

    slide.addShape(pptx.ShapeType.roundRect, {
      x, y: 2.2, w: 2.15, h: 2.2,
      fill: { color: DARK_CARD },
      line: { color: borderColor, width: 1, dashType },
      rectRadius: 0.08,
    });

    slide.addText(p.title, {
      x, y: 2.3, w: 2.15, h: 0.3,
      fontSize: 11, bold: true, color: WHITE, align: "center", fontFace: FONT,
    });

    if (p.optionalTag) {
      slide.addText(p.optionalTag, {
        x, y: 2.55, w: 2.15, h: 0.2,
        fontSize: 7, color: "6B7280", align: "center", fontFace: FONT,
      });
    }

    const itemY = p.optionalTag ? 2.75 : 2.65;
    p.items.forEach((item, j) => {
      slide.addText(item, {
        x: x + 0.15, y: itemY + j * 0.22, w: 1.85, h: 0.22,
        fontSize: 8, color: GRAY, align: "center", fontFace: FONT,
      });
    });

    // Subtitle pill
    slide.addShape(pptx.ShapeType.roundRect, {
      x: x + 0.2, y: 4.0, w: 1.75, h: 0.25,
      fill: { color: "0A1628" },
      rectRadius: 0.04,
    });
    slide.addText(p.subtitle, {
      x: x + 0.2, y: 4.0, w: 1.75, h: 0.25,
      fontSize: 7, bold: true, color: CYAN, align: "center", fontFace: FONT,
    });
  });

  // Tagline
  slide.addText(data.tagline, {
    x: 0.5, y: 4.6, w: 9, h: 0.4,
    fontSize: 11, color: "6B7280", align: "center", fontFace: FONT,
  });

  addSlideNumber(slide, 4, 12);
  return slide;
}

// ─── Shared slide builders (5–12 + appendix) ───
// These extract text from the DOM since shared slides aren't in the variant data.

function getText(selector, fallback) {
  const el = document.querySelector(selector);
  return el ? el.textContent.trim() : (fallback || "");
}

function buildSlide5(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "HOW IT WORKS");

  slide.addText(getText(".slide-5-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  const panels = document.querySelectorAll(".slide-5-panel");
  panels.forEach((panel, i) => {
    const x = 0.3 + i * 3.2;
    const title = panel.querySelector(".slide-5-panel-title");
    const body = panel.querySelector(".slide-5-panel-body");
    const caption = panel.querySelector(".slide-5-panel-caption");

    slide.addShape(pptx.ShapeType.roundRect, {
      x, y: 1.2, w: 2.9, h: 3.6,
      fill: { color: DARK_CARD },
      line: { color: "0D3B4F", width: 1 },
      rectRadius: 0.08,
    });

    // Step number + title
    slide.addText(`${i + 1}  ${title ? title.textContent : ""}`, {
      x: x + 0.15, y: 1.3, w: 2.6, h: 0.3,
      fontSize: 10, bold: true, color: WHITE, fontFace: FONT,
    });

    // Code body
    if (body) {
      slide.addText(body.textContent.trim(), {
        x: x + 0.15, y: 1.7, w: 2.6, h: 2.4,
        fontSize: 7, color: "E6EDF3", fontFace: "Courier New",
        lineSpacingMultiple: 1.35, valign: "top",
      });
    }

    // Caption
    if (caption) {
      slide.addText(caption.textContent.trim(), {
        x: x + 0.15, y: 4.2, w: 2.6, h: 0.5,
        fontSize: 8, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.3,
      });
    }
  });

  addSlideNumber(slide, 5, 12);
  return slide;
}

function buildSlide6(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "MARKET");

  slide.addText(getText(".slide-6-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  // TAM/SAM/SOM circles as text blocks (circles don't translate well to PPTX)
  const markets = [
    { label: "TAM", val: getText(".slide-6-tam-label .slide-6-market-val"), desc: getText(".slide-6-tam-label .slide-6-market-desc") },
    { label: "SAM", val: getText(".slide-6-sam-label .slide-6-market-val"), desc: getText(".slide-6-sam-label .slide-6-market-desc") },
    { label: "SOM", val: getText(".slide-6-ring--som .slide-6-ring-label-val"), desc: "" },
  ];

  markets.forEach((m, i) => {
    const x = 0.5 + i * 2.2;
    slide.addShape(pptx.ShapeType.roundRect, {
      x, y: 1.3, w: 2, h: 1.6,
      fill: { color: DARK_CARD },
      line: { color: "0D3B4F", width: 1 },
      rectRadius: 0.08,
    });
    slide.addText(m.label, {
      x, y: 1.4, w: 2, h: 0.25,
      fontSize: 8, bold: true, color: CYAN, align: "center", fontFace: FONT,
    });
    slide.addText(m.val, {
      x, y: 1.65, w: 2, h: 0.4,
      fontSize: 18, bold: true, color: WHITE, align: "center", fontFace: FONT,
    });
    if (m.desc) {
      slide.addText(m.desc, {
        x: x + 0.1, y: 2.1, w: 1.8, h: 0.7,
        fontSize: 7, color: "6B7280", align: "center", fontFace: FONT, lineSpacingMultiple: 1.3,
      });
    }
  });

  // M&A callout
  slide.addText(getText(".slide-6-callout-title"), {
    x: 7, y: 1.3, w: 2.5, h: 0.3,
    fontSize: 9, bold: true, color: CYAN, fontFace: FONT,
  });

  const rows = document.querySelectorAll(".slide-6-callout-row");
  rows.forEach((row, i) => {
    const name = row.querySelector(".slide-6-callout-name");
    const detail = row.querySelector(".slide-6-callout-detail");
    slide.addText(`${name ? name.textContent : ""}  —  ${detail ? detail.textContent : ""}`, {
      x: 7, y: 1.65 + i * 0.3, w: 2.8, h: 0.28,
      fontSize: 8, color: WHITE, fontFace: FONT,
    });
  });

  addSlideNumber(slide, 6, 12);
  return slide;
}

function buildSlide7(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "BUSINESS MODEL");

  slide.addText(getText(".slide-7-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  // Pricing table
  const tiers = [
    { name: "Community", price: "Free (AGPL)", buyer: "Individual developers", features: "Core firewall, YAML policies, single-agent, CLI, basic audit" },
    { name: "Team", price: "$49/mo", buyer: "Dev teams, startups", features: "Cloud dashboard, shared policies, analytics, multi-agent" },
    { name: "Enterprise", price: "$25K+/yr", buyer: "CISOs, compliance teams", features: "SSO, RBAC, audit trails, compliance reports, SLAs, dual-license option" },
  ];

  // Header
  const headers = ["Tier", "Price", "Target Buyer", "Key Features"];
  headers.forEach((h, i) => {
    const widths = [1.2, 1.4, 2, 4.4];
    const xs = [0.5, 1.7, 3.1, 5.1];
    slide.addText(h, {
      x: xs[i], y: 1.2, w: widths[i], h: 0.35,
      fontSize: 9, bold: true, color: CYAN, fontFace: FONT,
    });
  });

  tiers.forEach((t, i) => {
    const y = 1.6 + i * 0.45;
    const isEnt = t.name === "Enterprise";
    if (isEnt) {
      slide.addShape(pptx.ShapeType.rect, {
        x: 0.4, y, w: 9.2, h: 0.42,
        fill: { color: "0A1628" },
      });
    }
    slide.addText(t.name, { x: 0.5, y, w: 1.2, h: 0.4, fontSize: 9, bold: true, color: WHITE, fontFace: FONT });
    slide.addText(t.price, { x: 1.7, y, w: 1.4, h: 0.4, fontSize: 9, bold: true, color: CYAN, fontFace: FONT });
    slide.addText(t.buyer, { x: 3.1, y, w: 2, h: 0.4, fontSize: 9, color: GRAY, fontFace: FONT });
    slide.addText(t.features, { x: 5.1, y, w: 4.4, h: 0.4, fontSize: 8, color: GRAY, fontFace: FONT });
  });

  // Path to $1M ARR
  slide.addText("Path to $1M ARR", {
    x: 0.5, y: 3.2, w: 4, h: 0.3,
    fontSize: 10, bold: true, color: WHITE, fontFace: FONT,
  });
  slide.addText("40 enterprise x $25K = $1M\nor 1,700 team x $588/yr = $1M\nor blend: 20 enterprise + 850 team = $1M", {
    x: 0.5, y: 3.55, w: 4, h: 0.9,
    fontSize: 9, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.5,
  });

  // AGPL note
  slide.addText("AGPL from day one — prevents cloud free-riding, drives dual-license revenue. Three streams: SaaS subscriptions, commercial dual-license ($10K–$100K/yr), premium policy libraries.", {
    x: 5, y: 3.2, w: 4.5, h: 1.2,
    fontSize: 9, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.4,
  });

  addSlideNumber(slide, 7, 12);
  return slide;
}

function buildSlide8(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "COMPETITIVE LANDSCAPE");

  slide.addText(getText(".slide-8-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  // 2x2 matrix
  // Axes
  slide.addText("Open Source", { x: 1.5, y: 1.1, w: 2, h: 0.25, fontSize: 8, color: GRAY, align: "center", fontFace: FONT });
  slide.addText("Proprietary", { x: 5.5, y: 1.1, w: 2, h: 0.25, fontSize: 8, color: GRAY, align: "center", fontFace: FONT });
  slide.addText("Agent-Agnostic", { x: 0.1, y: 2.2, w: 1.2, h: 0.3, fontSize: 7, color: GRAY, fontFace: FONT, rotate: 270 });
  slide.addText("Agent-Specific", { x: 8.5, y: 2.2, w: 1.2, h: 0.3, fontSize: 7, color: GRAY, fontFace: FONT, rotate: 270 });

  // Quadrants
  const quads = [
    { x: 1.5, y: 1.4, label: "AvaKill", desc: "Alone in this quadrant.\nAgent-agnostic, YAML policies, <1ms", highlight: true },
    { x: 5.5, y: 1.4, label: "Noma ($100M), Zenity ($55M)", desc: "Enterprise SaaS, 6-figure contracts", highlight: false },
    { x: 1.5, y: 3.1, label: "Rampart, agentsh", desc: "OS-level syscall interception, coding agents only", highlight: false },
    { x: 5.5, y: 3.1, label: "CyberArk, Silverfort", desc: "MCP gateways tied to enterprise identity", highlight: false },
  ];

  quads.forEach((q) => {
    const borderColor = q.highlight ? CYAN : "1E293B";
    const fillColor = q.highlight ? "0A1628" : DARK_CARD;
    slide.addShape(pptx.ShapeType.roundRect, {
      x: q.x, y: q.y, w: 3.2, h: 1.5,
      fill: { color: fillColor },
      line: { color: borderColor, width: q.highlight ? 2 : 1 },
      rectRadius: 0.08,
    });
    slide.addText(q.label, {
      x: q.x + 0.15, y: q.y + 0.15, w: 2.9, h: 0.3,
      fontSize: 10, bold: true, color: q.highlight ? CYAN : WHITE, fontFace: FONT,
    });
    slide.addText(q.desc, {
      x: q.x + 0.15, y: q.y + 0.5, w: 2.9, h: 0.8,
      fontSize: 8, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.3,
    });
  });

  // Bottom bar
  slide.addText(getText(".slide-8-message"), {
    x: 0.5, y: 4.85, w: 9, h: 0.35,
    fontSize: 10, color: WHITE, fontFace: FONT, bold: false,
  });

  addSlideNumber(slide, 8, 12);
  return slide;
}

function buildSlide9(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "TRACTION");

  slide.addText(getText(".slide-9-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  // Live Today items
  slide.addText("Live Today (Mar 2026)", {
    x: 0.5, y: 1.2, w: 4, h: 0.3,
    fontSize: 10, bold: true, color: GREEN, fontFace: FONT,
  });

  const liveItems = document.querySelectorAll(".slide-9-col--live .slide-9-item");
  liveItems.forEach((item, i) => {
    slide.addText(item.textContent.trim(), {
      x: 0.7, y: 1.55 + i * 0.35, w: 4.3, h: 0.33,
      fontSize: 8, color: GRAY, fontFace: FONT,
    });
  });

  // Roadmap
  slide.addText("Roadmap", {
    x: 5.5, y: 1.2, w: 4, h: 0.3,
    fontSize: 10, bold: true, color: CYAN, fontFace: FONT,
  });

  const phases = document.querySelectorAll(".slide-9-phase");
  phases.forEach((phase, i) => {
    const date = phase.querySelector(".slide-9-phase-date");
    const text = phase.querySelector(".slide-9-phase-text");
    slide.addText(date ? date.textContent : "", {
      x: 5.5, y: 1.6 + i * 0.65, w: 0.8, h: 0.25,
      fontSize: 8, bold: true, color: CYAN, fontFace: FONT,
    });
    slide.addText(text ? text.textContent.trim() : "", {
      x: 6.4, y: 1.6 + i * 0.65, w: 3.2, h: 0.55,
      fontSize: 8, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.3,
    });
  });

  addSlideNumber(slide, 9, 12);
  return slide;
}

function buildSlide10(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "TEAM");

  slide.addText(getText(".slide-10-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  // Founder info
  slide.addText("Logan Bell", {
    x: 0.5, y: 1.5, w: 3, h: 0.35,
    fontSize: 16, bold: true, color: WHITE, fontFace: FONT,
  });
  slide.addText("Founder & CEO", {
    x: 0.5, y: 1.85, w: 3, h: 0.25,
    fontSize: 10, color: CYAN, fontFace: FONT,
  });
  slide.addText(getText(".slide-10-founder-statement"), {
    x: 0.5, y: 2.2, w: 3.5, h: 0.6,
    fontSize: 10, color: GRAY, fontFace: FONT, italic: true, lineSpacingMultiple: 1.3,
  });

  // Proof stack
  slide.addText("Proof Stack", {
    x: 5, y: 1.3, w: 4.5, h: 0.3,
    fontSize: 11, bold: true, color: WHITE, fontFace: FONT,
  });

  const proofItems = document.querySelectorAll(".slide-10-proof-item");
  proofItems.forEach((item, i) => {
    slide.addText(item.textContent.trim(), {
      x: 5.2, y: 1.7 + i * 0.4, w: 4.3, h: 0.38,
      fontSize: 9, color: GRAY, fontFace: FONT, lineSpacingMultiple: 1.2,
    });
  });

  // Bottom
  slide.addText(getText(".slide-10-bottom"), {
    x: 0.5, y: 4.5, w: 9, h: 0.4,
    fontSize: 11, color: WHITE, align: "center", fontFace: FONT, bold: true,
  });

  addSlideNumber(slide, 10, 12);
  return slide;
}

function buildSlide11(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "THE ASK");

  slide.addText(getText(".slide-11-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });
  slide.addText(getText(".slide-11-terms"), {
    x: 0.5, y: 1.0, w: 9, h: 0.3,
    fontSize: 12, color: CYAN, fontFace: FONT,
  });

  // Use of funds
  slide.addText("Use of Funds", {
    x: 0.5, y: 1.5, w: 4, h: 0.3,
    fontSize: 10, bold: true, color: WHITE, fontFace: FONT,
  });

  const funds = [
    { label: "Engineering", pct: "60%", desc: "Hire 1-2 security engineers (Go + Python), accelerate v1.0 and governance dashboard" },
    { label: "Community & GTM", pct: "25%", desc: "Developer advocacy, ClawHavoc campaign, conference presence, documentation" },
    { label: "Infrastructure", pct: "15%", desc: "CI/CD, cloud hosting for SaaS dashboard, security audits" },
  ];

  funds.forEach((f, i) => {
    const y = 1.9 + i * 0.7;
    slide.addText(`${f.label}  ${f.pct}`, {
      x: 0.5, y, w: 4.5, h: 0.25,
      fontSize: 10, bold: true, color: WHITE, fontFace: FONT,
    });
    slide.addText(f.desc, {
      x: 0.5, y: y + 0.25, w: 4.5, h: 0.35,
      fontSize: 8, color: GRAY, fontFace: FONT,
    });
  });

  // Milestones
  slide.addText("12-Month Milestones", {
    x: 5.5, y: 1.5, w: 4, h: 0.3,
    fontSize: 10, bold: true, color: WHITE, fontFace: FONT,
  });

  const milestones = document.querySelectorAll(".slide-11-milestone");
  milestones.forEach((m, i) => {
    slide.addText(m.textContent.trim(), {
      x: 5.7, y: 1.9 + i * 0.4, w: 3.8, h: 0.35,
      fontSize: 10, color: GRAY, fontFace: FONT,
    });
  });

  addSlideNumber(slide, 11, 12);
  return slide;
}

function buildSlide12(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };

  slide.addText("AvaKill", {
    x: 0, y: 1.2, w: 10, h: 0.6,
    fontSize: 36, bold: true, color: CYAN, align: "center", fontFace: FONT,
  });

  slide.addText("Thank You", {
    x: 0, y: 1.85, w: 10, h: 0.5,
    fontSize: 28, bold: true, color: WHITE, align: "center", fontFace: FONT,
  });

  slide.addText(getText(".slide-12-tagline"), {
    x: 1.5, y: 2.5, w: 7, h: 0.6,
    fontSize: 13, color: GRAY, align: "center", fontFace: FONT, italic: true, lineSpacingMultiple: 1.3,
  });

  // Contact
  const contacts = [
    "logan@avakill.com",
    "310-913-1024",
    "avakill.com",
    "github.com/log-bell/avakill",
  ];
  slide.addText(contacts.join("  |  "), {
    x: 0, y: 3.5, w: 10, h: 0.4,
    fontSize: 10, color: "4B5563", align: "center", fontFace: FONT,
  });

  return slide;
}

function buildAppendix(pptx) {
  const slide = pptx.addSlide();
  slide.background = { color: BG };
  addSectionTitle(slide, "APPENDIX");

  slide.addText(getText(".slide-appendix-headline"), {
    x: 0.5, y: 0.55, w: 9, h: 0.5,
    fontSize: 22, bold: true, color: WHITE, fontFace: FONT,
  });

  // Two columns of compliance mappings
  const cols = document.querySelectorAll(".slide-appendix-col");
  cols.forEach((col, ci) => {
    const x = 0.5 + ci * 4.7;
    const title = col.querySelector(".slide-appendix-col-title");

    slide.addText(title ? title.textContent : "", {
      x, y: 1.2, w: 4.4, h: 0.3,
      fontSize: 10, bold: true, color: CYAN, fontFace: FONT,
    });

    const mappingRows = col.querySelectorAll(".slide-appendix-row");
    mappingRows.forEach((row, ri) => {
      const code = row.querySelector(".slide-appendix-row-code");
      const desc = row.querySelector(".slide-appendix-row-desc");
      slide.addText(`${code ? code.textContent : ""}  →  ${desc ? desc.textContent : ""}`, {
        x, y: 1.6 + ri * 0.35, w: 4.4, h: 0.33,
        fontSize: 8, color: GRAY, fontFace: FONT,
      });
    });
  });

  slide.addText(getText(".slide-appendix-bottom"), {
    x: 0.5, y: 4.6, w: 9, h: 0.4,
    fontSize: 9, color: "6B7280", align: "center", fontFace: FONT,
  });

  return slide;
}

// ─── Main export function ───

async function exportPPTX() {
  const variant = getActiveVariant();
  const pptx = new PptxGenJS();

  pptx.layout = "LAYOUT_WIDE"; // 13.33" x 7.5" — standard 16:9
  pptx.author = "AvaKill";
  pptx.subject = `AvaKill Pitch Deck — ${variant.meta.name} variant`;

  // Variant slides (1–4)
  buildSlide1(pptx, variant.slides[0]);
  buildSlide2(pptx, variant.slides[1]);
  buildSlide3(pptx, variant.slides[2]);
  buildSlide4(pptx, variant.slides[3]);

  // Shared slides (5–12 + appendix)
  buildSlide5(pptx);
  buildSlide6(pptx);
  buildSlide7(pptx);
  buildSlide8(pptx);
  buildSlide9(pptx);
  buildSlide10(pptx);
  buildSlide11(pptx);
  buildSlide12(pptx);
  buildAppendix(pptx);

  const filename = `avakill-deck-${variant.id}.pptx`;
  await pptx.writeFile({ fileName: filename });
  return filename;
}
