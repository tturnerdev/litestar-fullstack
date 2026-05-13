"""Tests for support domain utilities."""

from __future__ import annotations

from app.domain.support.utils import generate_ticket_number, render_markdown


class TestRenderMarkdown:
    def test_empty_string(self) -> None:
        assert render_markdown("") == ""

    def test_plain_text(self) -> None:
        result = render_markdown("Hello world")
        assert "<p>Hello world</p>" in result

    def test_heading(self) -> None:
        assert "<h1>Title</h1>" in render_markdown("# Title")
        assert "<h2>Subtitle</h2>" in render_markdown("## Subtitle")

    def test_bold(self) -> None:
        assert "<strong>bold</strong>" in render_markdown("**bold**")

    def test_italic(self) -> None:
        assert "<em>italic</em>" in render_markdown("*italic*")

    def test_inline_code(self) -> None:
        assert "<code>code</code>" in render_markdown("`code`")

    def test_safe_link(self) -> None:
        result = render_markdown("[Click](https://example.com)")
        assert 'href="https://example.com"' in result
        assert 'rel="noopener noreferrer"' in result

    def test_safe_link_http(self) -> None:
        result = render_markdown("[Click](http://example.com)")
        assert 'href="http://example.com"' in result

    def test_safe_link_mailto(self) -> None:
        result = render_markdown("[Email](mailto:user@example.com)")
        assert 'href="mailto:user@example.com"' in result

    def test_safe_link_relative(self) -> None:
        result = render_markdown("[Page](/some/path)")
        assert 'href="/some/path"' in result

    def test_safe_link_anchor(self) -> None:
        result = render_markdown("[Section](#section)")
        assert 'href="#section"' in result

    def test_blocks_javascript_link(self) -> None:
        result = render_markdown("[XSS](javascript:alert(1))")
        assert "javascript:" not in result
        assert "href" not in result or 'href=""' in result

    def test_blocks_javascript_link_with_entity_encoding(self) -> None:
        result = render_markdown("[XSS](javascript:alert('xss'))")
        assert "javascript:" not in result

    def test_blocks_data_uri_link(self) -> None:
        result = render_markdown("[XSS](data:text/html,<script>alert(1)</script>)")
        assert "data:" not in result or 'href=""' in result

    def test_blocks_vbscript_link(self) -> None:
        result = render_markdown("[XSS](vbscript:MsgBox(1))")
        assert "vbscript:" not in result

    def test_safe_image(self) -> None:
        result = render_markdown("![alt](https://example.com/img.png)")
        assert 'src="https://example.com/img.png"' in result

    def test_blocks_javascript_image(self) -> None:
        result = render_markdown("![xss](javascript:alert(1))")
        assert "javascript:" not in result

    def test_html_entities_escaped(self) -> None:
        result = render_markdown("<script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_blockquote(self) -> None:
        result = render_markdown("> Quote")
        assert "<blockquote>" in result

    def test_unordered_list(self) -> None:
        result = render_markdown("- Item 1\n- Item 2")
        assert "<li>Item 1</li>" in result
        assert "<ul>" in result

    def test_fenced_code_block(self) -> None:
        result = render_markdown("```python\nprint('hi')\n```")
        assert '<code class="language-python">' in result


class TestGenerateTicketNumber:
    def test_basic(self) -> None:
        assert generate_ticket_number(1) == "SUP-00001"

    def test_large_number(self) -> None:
        assert generate_ticket_number(12345) == "SUP-12345"

    def test_zero(self) -> None:
        assert generate_ticket_number(0) == "SUP-00000"
