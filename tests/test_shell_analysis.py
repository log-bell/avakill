"""Tests for shell metacharacter detection."""

from __future__ import annotations

from avakill.core.shell_analysis import is_shell_safe

# -------------------------------------------------------------------
# Safe commands (should all pass)
# -------------------------------------------------------------------


class TestSafeCommands:
    """Commands without metacharacters should be considered safe."""

    def test_simple_echo(self) -> None:
        safe, findings = is_shell_safe("echo hello")
        assert safe is True
        assert findings == []

    def test_ls_with_flags(self) -> None:
        safe, _ = is_shell_safe("ls -la /tmp")
        assert safe is True

    def test_cat_file(self) -> None:
        safe, _ = is_shell_safe("cat README.md")
        assert safe is True

    def test_pwd(self) -> None:
        safe, _ = is_shell_safe("pwd")
        assert safe is True

    def test_git_status(self) -> None:
        safe, _ = is_shell_safe("git status")
        assert safe is True

    def test_empty_command(self) -> None:
        safe, findings = is_shell_safe("")
        assert safe is True
        assert findings == []

    def test_command_with_dashes(self) -> None:
        safe, _ = is_shell_safe("python --version")
        assert safe is True

    def test_command_with_equals(self) -> None:
        safe, _ = is_shell_safe("ENV_VAR=value python app.py")
        assert safe is True


# -------------------------------------------------------------------
# Pipes
# -------------------------------------------------------------------


class TestPipeDetection:
    """Pipe metacharacter detection."""

    def test_simple_pipe(self) -> None:
        safe, findings = is_shell_safe("cat file.txt | grep error")
        assert safe is False
        assert any("pipe" in f for f in findings)

    def test_pipe_to_shell(self) -> None:
        safe, findings = is_shell_safe("echo payload | sh")
        assert safe is False

    def test_base64_pipe_to_shell(self) -> None:
        """Red team bypass: base64 encoded payload piped to shell."""
        safe, findings = is_shell_safe("echo dG91Y2ggL3RtcC9wd25lZA== | base64 -d | sh")
        assert safe is False


# -------------------------------------------------------------------
# Redirects
# -------------------------------------------------------------------


class TestRedirectDetection:
    """Output/input redirect detection."""

    def test_output_redirect(self) -> None:
        safe, findings = is_shell_safe("echo data > output.txt")
        assert safe is False
        assert any("redirect" in f for f in findings)

    def test_append_redirect(self) -> None:
        safe, findings = is_shell_safe("echo data >> output.txt")
        assert safe is False

    def test_redirect_to_hook_binary(self) -> None:
        """Red team bypass: overwrite hook binary via redirect."""
        safe, findings = is_shell_safe("echo '' > /path/to/avakill-hook-claude-code")
        assert safe is False

    def test_input_redirect(self) -> None:
        safe, findings = is_shell_safe("wc -l < input.txt")
        assert safe is False
        assert any("input redirect" in f for f in findings)

    def test_heredoc(self) -> None:
        safe, findings = is_shell_safe("cat << EOF")
        assert safe is False


# -------------------------------------------------------------------
# Chaining
# -------------------------------------------------------------------


class TestChainingDetection:
    """Semicolon and logical operator detection."""

    def test_semicolon(self) -> None:
        safe, findings = is_shell_safe("echo a; echo b")
        assert safe is False
        assert any("chaining" in f for f in findings)

    def test_logical_and(self) -> None:
        safe, findings = is_shell_safe("test -f file && rm file")
        assert safe is False
        assert any("AND" in f for f in findings)

    def test_logical_or(self) -> None:
        safe, findings = is_shell_safe("test -f file || echo missing")
        assert safe is False
        assert any("OR" in f for f in findings)


# -------------------------------------------------------------------
# Subshells and expansion
# -------------------------------------------------------------------


class TestSubshellDetection:
    """Backtick, $(), and ${} detection."""

    def test_backtick_subshell(self) -> None:
        safe, findings = is_shell_safe("echo `whoami`")
        assert safe is False
        assert any("backtick" in f for f in findings)

    def test_dollar_paren_subshell(self) -> None:
        safe, findings = is_shell_safe("echo $(whoami)")
        assert safe is False
        assert any("subshell" in f for f in findings)

    def test_variable_expansion(self) -> None:
        safe, findings = is_shell_safe("echo ${HOME}")
        assert safe is False
        assert any("variable expansion" in f for f in findings)


# -------------------------------------------------------------------
# Dangerous builtins
# -------------------------------------------------------------------


class TestDangerousBuiltins:
    """Detects dangerous builtins like source and xargs."""

    def test_eval_builtin(self) -> None:
        # NOTE: This tests detection of the shell "eval" builtin in commands.
        # The is_shell_safe function uses regex matching, not code execution.
        safe, findings = is_shell_safe("eval 'rm -rf /'")
        assert safe is False
        assert any("eval" in f.lower() for f in findings)

    def test_source(self) -> None:
        safe, findings = is_shell_safe("source ~/.bashrc")
        assert safe is False
        assert any("source" in f for f in findings)

    def test_xargs(self) -> None:
        safe, findings = is_shell_safe("find . -name '*.tmp' -print0 | xargs -0 rm")
        assert safe is False
        assert any("xargs" in f for f in findings)

    def test_eval_not_in_word(self) -> None:
        """'evaluate' should NOT trigger detection."""
        safe, findings = is_shell_safe("python evaluate.py")
        assert safe is True


# -------------------------------------------------------------------
# Red team attack replays
# -------------------------------------------------------------------


class TestRedTeamBypasses:
    """Reproduce the three specific red team bypasses that this module must catch."""

    def test_echo_redirect_to_file(self) -> None:
        """Attack: echo foo > bar.txt — turns safe echo into arbitrary write."""
        safe, _ = is_shell_safe("echo foo > bar.txt")
        assert safe is False

    def test_base64_pipe_chain(self) -> None:
        """Attack: echo <b64> | base64 -d | sh — encoded payload execution."""
        safe, _ = is_shell_safe("echo dG91Y2ggL3RtcC9wd25lZA== | base64 -d | sh")
        assert safe is False

    def test_overwrite_hook_binary(self) -> None:
        """Attack: echo '' > /path/to/avakill-hook-claude-code — disable firewall."""
        safe, _ = is_shell_safe("echo '' > /usr/local/bin/avakill-hook-claude-code")
        assert safe is False


# -------------------------------------------------------------------
# Multiple findings
# -------------------------------------------------------------------


class TestMultipleFindings:
    """Commands with multiple metacharacters should report all of them."""

    def test_pipe_and_redirect(self) -> None:
        safe, findings = is_shell_safe("cat file | sort > output.txt")
        assert safe is False
        assert len(findings) >= 2

    def test_chain_and_subshell(self) -> None:
        safe, findings = is_shell_safe("echo $(whoami); rm -rf /")
        assert safe is False
        assert len(findings) >= 2
