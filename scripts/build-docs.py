#!/usr/bin/env python3
"""Build HTML docs from markdown sources.

Reads each .md file from docs/, converts to HTML, generates sidebar and TOC,
injects into the site template, and writes to site/docs/<slug>/index.html.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.fenced_code import FencedCodeExtension
from markdown.extensions.tables import TableExtension
from markdown.extensions.toc import TocExtension

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
SITE_DOCS_DIR = ROOT / "site" / "docs"
TEMPLATE_PATH = SITE_DOCS_DIR / "_template.html"

# SVG icons for doc pages
_ICON_BOOK = (
    '<svg viewBox="0 0 24 24">'
    '<path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/>'
    '<path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>'
    "</svg>"
)
_ICON_FILE = (
    '<svg viewBox="0 0 24 24">'
    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12'
    'a2 2 0 0 0 2-2V8z"/>'
    '<polyline points="14 2 14 8 20 8"/>'
    "</svg>"
)
_ICON_TERMINAL = (
    '<svg viewBox="0 0 24 24">'
    '<polyline points="4 17 10 11 4 5"/>'
    '<line x1="12" y1="19" x2="20" y2="19"/>'
    "</svg>"
)
_ICON_CODE = (
    '<svg viewBox="0 0 24 24">'
    '<polyline points="16 18 22 12 16 6"/>'
    '<polyline points="8 6 2 12 8 18"/>'
    "</svg>"
)
_ICON_SERVER = (
    '<svg viewBox="0 0 24 24">'
    '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>'
    '<rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>'
    '<line x1="6" y1="6" x2="6.01" y2="6"/>'
    '<line x1="6" y1="18" x2="6.01" y2="18"/>'
    "</svg>"
)

# Ordered list of docs: (slug, filename, title, icon_svg, description)
DOCS = [
    (
        "getting-started",
        "getting-started.md",
        "Getting Started",
        _ICON_BOOK,
        "Install AvaKill, create your first policy, and protect your AI agents.",
    ),
    (
        "policy-reference",
        "policy-reference.md",
        "Policy Reference",
        _ICON_FILE,
        "YAML schema, actions, conditions, rate limits, and sandbox configuration.",
    ),
    (
        "cli-reference",
        "cli-reference.md",
        "CLI Reference",
        _ICON_TERMINAL,
        "All avakill commands, avakill-shim flags, and hook binaries.",
    ),
    (
        "api-reference",
        "api-reference.md",
        "API Reference",
        _ICON_CODE,
        "Python SDK: Guard, PolicyEngine, models, and framework wrappers.",
    ),
    (
        "architecture",
        "architecture.md",
        "Architecture",
        _ICON_SERVER,
        "How hooks, MCP proxy, OS sandbox, and daemon fit together.",
    ),
]


def build_subnav(active_slug: str) -> str:
    """Generate the doc-category subnav bar."""
    lines = ['<nav class="doc-subnav">']
    for slug, _, title, icon, _ in DOCS:
        cls = ' class="active"' if slug == active_slug else ""
        lines.append(f'  <a href="/docs/{slug}/"{cls}>')
        lines.append(f"    {icon}")
        lines.append(f"    {title}")
        lines.append("  </a>")
    lines.append("</nav>")
    return "\n".join(lines)


def build_sidebar(active_slug: str, toc_tokens: list[dict]) -> str:
    """Generate the left sidebar from TOC tokens (h2/h3 headings)."""
    lines = []

    # Current doc's heading hierarchy
    lines.append('<div class="sidebar-group">')
    lines.append('  <div class="sidebar-label">On this page</div>')
    lines.append('  <ul class="sidebar-list">')

    for token in toc_tokens:
        level = token["level"]
        text = token["name"]
        anchor = token["id"]
        if level == 2:
            lines.append(f'    <li><a href="#{anchor}" class="sidebar-link">{text}</a></li>')
        elif level == 3:
            lines.append(
                f'    <li><a href="#{anchor}"'
                f' class="sidebar-link sidebar-link--sub">'
                f"{text}</a></li>"
            )

    lines.append("  </ul>")
    lines.append("</div>")

    # Links to other doc pages
    lines.append('<div class="sidebar-group">')
    lines.append('  <div class="sidebar-label">Documentation</div>')
    lines.append('  <ul class="sidebar-list">')
    for slug, _, title, _, _ in DOCS:
        if slug == active_slug:
            lines.append(
                f'    <li><a href="/docs/{slug}/" class="sidebar-link active">{title}</a></li>'
            )
        else:
            lines.append(f'    <li><a href="/docs/{slug}/" class="sidebar-link">{title}</a></li>')
    lines.append("  </ul>")
    lines.append("</div>")

    return "\n".join(lines)


def build_toc(toc_tokens: list[dict]) -> str:
    """Generate the right-side 'On this page' TOC from h2 headings."""
    lines = []
    for token in toc_tokens:
        if token["level"] == 2:
            lines.append(f'<li><a href="#{token["id"]}" class="toc-link">{token["name"]}</a></li>')
    return "\n        ".join(lines)


def build_prev_next(current_slug: str) -> str:
    """Generate prev/next navigation cards."""
    idx = next(i for i, (slug, *_) in enumerate(DOCS) if slug == current_slug)
    lines = ['<div class="docs-nav-bottom">']

    if idx > 0:
        prev_slug, _, prev_title, _, _ = DOCS[idx - 1]
        lines.append(f'  <a href="/docs/{prev_slug}/" class="docs-nav-card">')
        lines.append('    <div class="docs-nav-label">&larr; Previous</div>')
        lines.append(f'    <div class="docs-nav-title">{prev_title}</div>')
        lines.append("  </a>")
    else:
        lines.append('  <a href="/" class="docs-nav-card">')
        lines.append('    <div class="docs-nav-label">&larr; Previous</div>')
        lines.append('    <div class="docs-nav-title">Home</div>')
        lines.append("  </a>")

    if idx < len(DOCS) - 1:
        next_slug, _, next_title, _, _ = DOCS[idx + 1]
        lines.append(f'  <a href="/docs/{next_slug}/" class="docs-nav-card docs-nav-card--next">')
        lines.append('    <div class="docs-nav-label">Next &rarr;</div>')
        lines.append(f'    <div class="docs-nav-title">{next_title}</div>')
        lines.append("  </a>")

    lines.append("</div>")
    return "\n".join(lines)


def extract_toc_tokens(md_instance: markdown.Markdown) -> list[dict]:
    """Extract TOC tokens from a rendered markdown instance."""
    toc_tokens = getattr(md_instance, "toc_tokens", [])
    flat: list[dict] = []

    def _flatten(tokens: list[dict], parent_level: int = 1) -> None:
        for token in tokens:
            flat.append({"level": parent_level, "id": token["id"], "name": token["name"]})
            if token.get("children"):
                _flatten(token["children"], parent_level + 1)

    _flatten(toc_tokens)
    return flat


def rewrite_internal_links(html: str) -> str:
    """Rewrite relative .md links to /docs/<slug>/ links."""

    def _replace(m: re.Match) -> str:
        filename = m.group(1)
        slug = filename.replace(".md", "")
        return f'href="/docs/{slug}/"'

    return re.sub(r'href="([a-z-]+\.md)"', _replace, html)


def build_doc(slug: str, filename: str, title: str, description: str, template: str) -> None:
    """Build a single doc page."""
    md_path = DOCS_DIR / filename
    if not md_path.exists():
        print(f"  SKIP {filename} (not found)")
        return

    md_text = md_path.read_text(encoding="utf-8")

    md_instance = markdown.Markdown(
        extensions=[
            FencedCodeExtension(),
            CodeHiliteExtension(css_class="codehilite", guess_lang=False, use_pygments=True),
            TocExtension(
                permalink=False,
                slugify=lambda value, separator: re.sub(
                    r"[^\w-]",
                    "",
                    re.sub(r"\s+", "-", value.strip().lower()),
                ),
            ),
            TableExtension(),
        ]
    )

    content_html = md_instance.convert(md_text)
    content_html = rewrite_internal_links(content_html)

    toc_tokens = extract_toc_tokens(md_instance)

    subnav = build_subnav(slug)
    sidebar_html = build_sidebar(slug, toc_tokens)
    toc_html = build_toc(toc_tokens)
    prev_next = build_prev_next(slug)

    full_content = content_html + "\n\n" + prev_next

    html = template
    html = html.replace("{{TITLE}}", title)
    html = html.replace("{{DESCRIPTION}}", description)
    html = html.replace("{{SUBNAV}}", subnav)
    html = html.replace("{{SIDEBAR}}", sidebar_html)
    html = html.replace("{{CONTENT}}", full_content)
    html = html.replace("{{TOC}}", toc_html)

    out_dir = SITE_DOCS_DIR / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "index.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"  OK   {slug}/index.html")


def build_index(template: str) -> None:
    """Build site/docs/index.html as a redirect to getting-started."""
    redirect_html = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="refresh" content="0;url=/docs/getting-started/">
  <title>Docs — AvaKill</title>
  <link rel="canonical" href="/docs/getting-started/">
</head>
<body>
  <p>Redirecting to <a href="/docs/getting-started/">Getting Started</a>...</p>
</body>
</html>"""
    out_path = SITE_DOCS_DIR / "index.html"
    out_path.write_text(redirect_html, encoding="utf-8")
    print("  OK   index.html (redirect)")


def main() -> None:
    print("Building docs...")

    if not TEMPLATE_PATH.exists():
        print(f"ERROR: Template not found at {TEMPLATE_PATH}", file=sys.stderr)
        sys.exit(1)

    template = TEMPLATE_PATH.read_text(encoding="utf-8")

    for slug, filename, title, _, description in DOCS:
        build_doc(slug, filename, title, description, template)

    build_index(template)

    print(f"\nDone. {len(DOCS)} docs built to {SITE_DOCS_DIR}/")


if __name__ == "__main__":
    main()
