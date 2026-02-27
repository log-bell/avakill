"""Tests for the SelfProtection class and Guard integration."""

from __future__ import annotations

import pytest

from avakill.core.engine import Guard
from avakill.core.models import AuditEvent, PolicyConfig, PolicyRule, ToolCall
from avakill.core.self_protection import SelfProtection
from avakill.logging.event_bus import EventBus


@pytest.fixture(autouse=True)
def _reset_event_bus():
    EventBus.reset()
    yield
    EventBus.reset()


@pytest.fixture
def sp() -> SelfProtection:
    return SelfProtection()


@pytest.fixture
def permissive_policy() -> PolicyConfig:
    """A policy that allows everything — self-protection should still block."""
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(name="allow-all", tools=["*"], action="allow"),
        ],
    )


# -------------------------------------------------------------------
# Policy file modification
# -------------------------------------------------------------------


class TestPolicyFileModification:
    """Self-protection blocks writes/deletes to avakill.yaml."""

    def test_blocks_rm_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "rm avakill.yaml"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection" in d.reason

    def test_blocks_rm_avakill_yml(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "rm avakill.yml"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_file_write_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "avakill.yaml", "content": "version: 1.0"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_file_delete_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="file_delete", arguments={"path": "avakill.yaml"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_sed_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "sed -i 's/deny/allow/' avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_mv_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "mv avakill.yaml /tmp/backup.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_redirect_overwrite(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "> avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_file_overwrite_tool(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_overwrite",
            arguments={"path": "/project/avakill.yaml", "content": "test"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_read_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="file_read", arguments={"path": "avakill.yaml"})
        d = sp.check(tc)
        assert d is None

    def test_allows_cat_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "cat avakill.yaml"})
        d = sp.check(tc)
        assert d is None

    def test_allows_proposed_yaml_write(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "avakill.proposed.yaml", "content": "version: 1.0"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_proposed_yml_write(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "my.proposed.yml", "content": "test"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_unrelated_file_write(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "config.yaml", "content": "test"},
        )
        d = sp.check(tc)
        assert d is None

    def test_deny_message_contains_stop_instruction(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "avakill.yaml", "content": "x"},
        )
        d = sp.check(tc)
        assert d is not None
        assert "STOP" in d.reason
        assert "Tell the user" in d.reason


# -------------------------------------------------------------------
# Package uninstall
# -------------------------------------------------------------------


class TestPackageUninstall:
    """Self-protection blocks uninstalling avakill."""

    def test_blocks_pip_uninstall(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pip uninstall avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (uninstall)" in d.reason

    def test_blocks_pip3_uninstall(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pip3 uninstall avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_python_m_pip_uninstall(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "python -m pip uninstall avakill"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_uv_remove(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "uv remove avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_poetry_remove(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "poetry remove avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_pip_remove(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pip remove avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_pip_install(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pip install avakill"})
        d = sp.check(tc)
        assert d is None

    def test_allows_pip_uninstall_other(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pip uninstall requests"})
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Approve command
# -------------------------------------------------------------------


class TestApproveCommand:
    """Self-protection blocks agents from running avakill approve."""

    def test_blocks_avakill_approve(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill approve avakill.proposed.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (approve)" in d.reason

    def test_allows_avakill_review(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill review avakill.proposed.yaml"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_avakill_validate(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill validate avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Reset command
# -------------------------------------------------------------------


class TestResetCommand:
    """Self-protection blocks agents from running avakill reset."""

    def test_blocks_avakill_reset(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill reset"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (reset)" in d.reason

    def test_blocks_avakill_reset_confirm(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill reset --confirm"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_avakill_reset_include_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill reset --include-policy"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_avakill_setup(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill setup"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Source modification
# -------------------------------------------------------------------


class TestSourceModification:
    """Self-protection blocks writes to avakill source files."""

    def test_blocks_write_to_src_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "src/avakill/core/engine.py", "content": "hacked"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (source-write)" in d.reason

    def test_blocks_write_to_site_packages(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={
                "path": "/usr/lib/python3/site-packages/avakill/core/engine.py",
                "content": "hacked",
            },
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_rm_src_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "rm -rf src/avakill/"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_read_src_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "src/avakill/core/engine.py"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_write_to_other_src(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "src/myapp/main.py", "content": "ok"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Tool name detection
# -------------------------------------------------------------------


class TestToolNameDetection:
    """Self-protection detects write/delete tools targeting policy files."""

    def test_blocks_file_write_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_file_delete_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_delete",
            arguments={"path": "avakill.yml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_create_overwrite_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_create",
            arguments={"path": "/project/avakill.yaml", "content": "test"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_file_modify_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_modify",
            arguments={"path": "avakill.yml", "content": "test"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_file_rename_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_rename",
            arguments={"old_path": "avakill.yaml", "new_path": "backup.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_read_tool_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_write_tool_non_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "config.json"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Hook binary protection
# -------------------------------------------------------------------


class TestHookBinaryProtection:
    """Self-protection blocks shell commands and write tools targeting hook binaries."""

    def test_blocks_rm_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "rm /usr/local/bin/avakill-hook-claude-code"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (hook-binary)" in d.reason

    def test_blocks_redirect_to_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "echo '' > /usr/local/bin/avakill-hook-claude-code"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (hook-binary)" in d.reason

    def test_blocks_truncate_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "truncate -s 0 /path/to/avakill-hook-gemini-cli"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_mv_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "mv /usr/local/bin/avakill-hook-claude-code /tmp/gone"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_chmod_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "chmod 000 /usr/local/bin/avakill-hook-claude-code"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_write_tool_to_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/usr/local/bin/avakill-hook-claude-code", "content": ""},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_read_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "/usr/local/bin/avakill-hook-claude-code"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_execute_hook_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill-hook-claude-code"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_unrelated_file_write(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/tmp/output.txt", "content": "data"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Hook config file protection
# -------------------------------------------------------------------


class TestHookConfigProtection:
    """Self-protection blocks writes to agent hook configuration files."""

    def test_blocks_write_claude_settings(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/home/user/.claude/settings.json", "content": "{}"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (hook-config-write)" in d.reason

    def test_blocks_write_claude_settings_local(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/home/user/.claude/settings.local.json", "content": "{}"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_write_gemini_settings(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/home/user/.gemini/settings.json", "content": "{}"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_write_cursor_hooks(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/project/.cursor/hooks.json", "content": "{}"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_write_windsurf_hooks(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/home/user/.codeium/windsurf/hooks.json", "content": "{}"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_file_delete_config(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_delete",
            arguments={"path": "/home/user/.claude/settings.json"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_read_config(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "/home/user/.claude/settings.json"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_unrelated_json_write(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/project/config/app.json", "content": "{}"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_write_to_non_agent_settings(self, sp: SelfProtection) -> None:
        """settings.json in a non-agent directory should be allowed."""
        tc = ToolCall(
            tool_name="file_write",
            arguments={"path": "/project/.vscode/settings.json", "content": "{}"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# pipx uninstall (Fix #1)
# -------------------------------------------------------------------


class TestPipxUninstall:
    """Self-protection blocks pipx uninstall/remove avakill."""

    def test_blocks_pipx_uninstall(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pipx uninstall avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (uninstall)" in d.reason

    def test_blocks_pipx_remove(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pipx remove avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False


# -------------------------------------------------------------------
# File edit protection (Fix #2)
# -------------------------------------------------------------------


class TestFileEditProtection:
    """Self-protection blocks edit-named tools targeting policy/hook files."""

    def test_blocks_file_edit_avakill_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_edit",
            arguments={"path": "avakill.yaml", "old_string": "deny", "new_string": "allow"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (policy-write)" in d.reason

    def test_blocks_file_edit_avakill_yml(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_edit",
            arguments={"path": "avakill.yml", "old_string": "x", "new_string": "y"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_file_edit_other_yaml(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_edit",
            arguments={"path": "config.yaml", "old_string": "x", "new_string": "y"},
        )
        d = sp.check(tc)
        assert d is None

    def test_blocks_file_edit_hook_config(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_edit",
            arguments={
                "path": "/home/user/.claude/settings.json",
                "old_string": "x",
                "new_string": "y",
            },
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False


# -------------------------------------------------------------------
# Shell bypass prevention (Fixes #3, #5, #6, #7)
# -------------------------------------------------------------------


class TestShellBypassPrevention:
    """Shell commands with write intent targeting policy files are blocked."""

    def test_blocks_python_c_write_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "python3 -c \"open('avakill.yaml','w').write('x')\""},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (policy-shell)" in d.reason

    def test_blocks_perl_e_write_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": 'perl -e \'open(F,">avakill.yaml");print F "x"\''},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_cp_dev_null_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "cp /dev/null avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_ln_sf_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "ln -sf /dev/null avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_truncate_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "truncate -s 0 avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_tee_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "echo 'x' | tee avakill.yaml"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_cat_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "cat avakill.yaml"})
        d = sp.check(tc)
        assert d is None

    def test_blocks_cat_pipe_policy(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "cat avakill.yaml | something"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False


# -------------------------------------------------------------------
# Shell hook config bypass (Fix #4)
# -------------------------------------------------------------------


class TestShellHookConfigBypass:
    """Shell commands targeting hook config files are blocked."""

    def test_blocks_python_rewrite_settings_json(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="Bash",
            arguments={
                "command": 'python3 -c "import json; '
                "json.dump({}, open('/home/user/.claude/settings.json','w'))\""
            },
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (hook-config-shell)" in d.reason

    def test_blocks_node_rewrite_settings_json(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={
                "cmd": "node -e \"require('fs').writeFileSync("
                "'/home/user/.claude/settings.json', '{}')\""
            },
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_cat_settings_json(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "cat /home/user/.claude/settings.json"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Main binary protection (Fix #8)
# -------------------------------------------------------------------


class TestMainBinaryProtection:
    """Self-protection blocks destructive commands targeting the main avakill binary."""

    def test_blocks_rm_avakill_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "rm ~/.local/bin/avakill"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (hook-binary)" in d.reason

    def test_blocks_mv_avakill_binary(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "mv ~/.local/bin/avakill /tmp/gone"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_allows_rm_avakill_unrelated(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "rm avakill-unrelated-file.txt"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Source false positive fix (Fix #9)
# -------------------------------------------------------------------


class TestSourceFalsePositiveFix:
    """Word boundaries prevent false positives on 'rm' inside words."""

    def test_allows_read_normalization_py(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "src/avakill/core/normalization.py"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_read_format_py(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="file_read",
            arguments={"path": "src/avakill/core/format.py"},
        )
        d = sp.check(tc)
        assert d is None

    def test_still_blocks_rm_src_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "rm -rf src/avakill/"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False


# -------------------------------------------------------------------
# Daemon shutdown protection (ISSUE-2)
# -------------------------------------------------------------------


class TestDaemonShutdownProtection:
    """Self-protection blocks commands that would shut down the avakill daemon."""

    # --- Direct CLI ---

    def test_blocks_avakill_daemon_stop(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "avakill daemon stop"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False
        assert "Tell the user" in d.reason
        assert "self-protection (daemon-shutdown)" in d.reason

    def test_blocks_avakill_daemon_stop_force(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill daemon stop --force"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    # --- pkill / killall ---

    def test_blocks_pkill_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pkill avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_pkill_f_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pkill -f avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_pkill_9_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "pkill -9 avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_killall_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "killall avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_killall_9_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(tool_name="shell_exec", arguments={"cmd": "killall -9 avakill"})
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    # --- kill with pgrep / pidof ---

    def test_blocks_kill_pgrep_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "kill $(pgrep avakill)"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_kill_9_pgrep_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "kill -9 $(pgrep avakill)"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_kill_backtick_pgrep(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "kill `pgrep avakill`"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_kill_pidof_avakill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "kill $(pidof avakill)"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    # --- kill with PID file ---

    def test_blocks_kill_cat_pid_file(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "kill -9 $(cat /var/run/avakill.pid)"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    # --- Full paths ---

    def test_blocks_full_path_kill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "/usr/bin/kill -9 $(pgrep avakill)"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_full_path_pkill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "/usr/bin/pkill avakill"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    # --- Service management ---

    def test_blocks_systemctl_stop(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "systemctl stop avakill"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_systemctl_kill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "systemctl kill avakill"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_systemctl_disable(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "systemctl disable avakill"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_service_stop(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "service avakill stop"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    # --- Bash tool name (Claude Code uses "Bash") ---

    def test_blocks_bash_tool_daemon_stop(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="Bash",
            arguments={"command": "avakill daemon stop"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    def test_blocks_bash_tool_pkill(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="Bash",
            arguments={"command": "pkill avakill"},
        )
        d = sp.check(tc)
        assert d is not None
        assert d.allowed is False

    # --- Allowed commands (no false positives) ---

    def test_allows_avakill_daemon_start(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill daemon start"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_avakill_daemon_status(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill daemon status"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_avakill_validate(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill validate"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_avakill_schema(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "avakill schema"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_kill_unrelated_process(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "kill 12345"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_pkill_unrelated(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "pkill nginx"},
        )
        d = sp.check(tc)
        assert d is None

    def test_allows_killall_unrelated(self, sp: SelfProtection) -> None:
        tc = ToolCall(
            tool_name="shell_exec",
            arguments={"cmd": "killall python"},
        )
        d = sp.check(tc)
        assert d is None


# -------------------------------------------------------------------
# Guard integration
# -------------------------------------------------------------------


class TestGuardIntegration:
    """Self-protection integrates correctly with the Guard class."""

    def test_self_protection_overrides_permissive_policy(
        self, permissive_policy: PolicyConfig
    ) -> None:
        guard = Guard(policy=permissive_policy)
        decision = guard.evaluate(tool="shell_exec", args={"cmd": "rm avakill.yaml"})
        assert decision.allowed is False
        assert decision.policy_name == "self-protection"

    def test_self_protection_disabled(self, permissive_policy: PolicyConfig) -> None:
        guard = Guard(policy=permissive_policy, self_protection=False)
        decision = guard.evaluate(tool="shell_exec", args={"cmd": "rm avakill.yaml"})
        # With self-protection disabled, permissive policy allows it
        assert decision.allowed is True

    def test_self_protection_emits_audit_event(self, permissive_policy: PolicyConfig) -> None:
        received: list[AuditEvent] = []
        bus = EventBus.get()
        bus.subscribe(received.append)

        guard = Guard(policy=permissive_policy)
        guard.evaluate(tool="shell_exec", args={"cmd": "pip uninstall avakill"})

        assert len(received) == 1
        assert received[0].decision.allowed is False
        assert received[0].decision.policy_name == "self-protection"
        assert received[0].tool_call.tool_name == "shell_exec"

    def test_self_protection_has_latency(self, permissive_policy: PolicyConfig) -> None:
        guard = Guard(policy=permissive_policy)
        decision = guard.evaluate(tool="file_write", args={"path": "avakill.yaml", "content": "x"})
        assert decision.latency_ms >= 0

    def test_self_protection_blocks_daemon_shutdown(self, permissive_policy: PolicyConfig) -> None:
        guard = Guard(policy=permissive_policy)
        decision = guard.evaluate(tool="shell_exec", args={"cmd": "pkill avakill"})
        assert decision.allowed is False
        assert decision.policy_name == "self-protection"

    def test_normal_evaluation_still_works_with_self_protection(
        self, permissive_policy: PolicyConfig
    ) -> None:
        guard = Guard(policy=permissive_policy)
        # This should pass through self-protection and hit normal policy
        decision = guard.evaluate(tool="file_read", args={"path": "data.csv"})
        assert decision.allowed is True
        assert decision.policy_name == "allow-all"
