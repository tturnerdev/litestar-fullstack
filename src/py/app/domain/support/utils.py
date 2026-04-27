"""Support domain utilities.

Provides markdown rendering and ticket number generation.
"""

from __future__ import annotations

import html
import re


def render_markdown(text: str) -> str:
    """Render markdown text to sanitized HTML.

    Supports standard markdown syntax: headings, bold, italic, code blocks,
    inline code, lists, links, blockquotes, and horizontal rules.

    All output is sanitized to prevent XSS.

    Args:
        text: The markdown text to render.

    Returns:
        Sanitized HTML string.
    """
    if not text:
        return ""

    # Escape HTML entities first to prevent XSS
    result = html.escape(text)

    # Fenced code blocks (``` ... ```)
    result = re.sub(
        r"```(\w*)\n(.*?)```",
        lambda m: f'<pre><code class="language-{m.group(1)}">{m.group(2)}</code></pre>'
        if m.group(1)
        else f"<pre><code>{m.group(2)}</code></pre>",
        result,
        flags=re.DOTALL,
    )

    # Inline code
    result = re.sub(r"`([^`]+)`", r"<code>\1</code>", result)

    # Headings (h1-h6)
    result = re.sub(r"^######\s+(.+)$", r"<h6>\1</h6>", result, flags=re.MULTILINE)
    result = re.sub(r"^#####\s+(.+)$", r"<h5>\1</h5>", result, flags=re.MULTILINE)
    result = re.sub(r"^####\s+(.+)$", r"<h4>\1</h4>", result, flags=re.MULTILINE)
    result = re.sub(r"^###\s+(.+)$", r"<h3>\1</h3>", result, flags=re.MULTILINE)
    result = re.sub(r"^##\s+(.+)$", r"<h2>\1</h2>", result, flags=re.MULTILINE)
    result = re.sub(r"^#\s+(.+)$", r"<h1>\1</h1>", result, flags=re.MULTILINE)

    # Bold and italic
    result = re.sub(r"\*\*\*(.+?)\*\*\*", r"<strong><em>\1</em></strong>", result)
    result = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", result)
    result = re.sub(r"\*(.+?)\*", r"<em>\1</em>", result)

    # Images ![alt](url)
    result = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", r'<img src="\2" alt="\1" />', result)

    # Links [text](url)
    result = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2" rel="noopener noreferrer">\1</a>', result)

    # Blockquotes
    result = re.sub(r"^&gt;\s*(.+)$", r"<blockquote>\1</blockquote>", result, flags=re.MULTILINE)

    # Horizontal rules
    result = re.sub(r"^---+$", "<hr />", result, flags=re.MULTILINE)

    # Unordered lists
    result = re.sub(r"^[-*+]\s+(.+)$", r"<li>\1</li>", result, flags=re.MULTILINE)
    result = re.sub(r"(<li>.*</li>\n?)+", r"<ul>\g<0></ul>", result)

    # Ordered lists
    result = re.sub(r"^\d+\.\s+(.+)$", r"<li>\1</li>", result, flags=re.MULTILINE)

    # Line breaks: double newline -> paragraph
    paragraphs = result.split("\n\n")
    processed = []
    for p in paragraphs:
        p = p.strip()
        if not p:
            continue
        # Don't wrap block elements in <p>
        if re.match(r"<(h[1-6]|pre|ul|ol|blockquote|hr|li)", p):
            processed.append(p)
        else:
            processed.append(f"<p>{p}</p>")
    result = "\n".join(processed)

    # Clean up single newlines within paragraphs to <br>
    result = re.sub(r"(?<!</p>)\n(?!<)", "<br />\n", result)

    return result


def generate_ticket_number(sequence: int) -> str:
    """Generate a ticket number from a sequence value.

    Args:
        sequence: The sequential number.

    Returns:
        Formatted ticket number like "SUP-00001".
    """
    return f"SUP-{sequence:05d}"
