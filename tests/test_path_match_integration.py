"""Integration tests for T2 path resolution through Guard.evaluate().

Reproduces real-world catastrophic deletion scenarios and verifies
workspace boundary enforcement end-to-end.
"""

from __future__ import annotations

import time

from avakill.cli.rule_catalog import build_policy_dict, generate_yaml
from avakill.core.engine import Guard
from avakill.core.models import PolicyConfig, PolicyRule, RuleConditions


class TestCatastrophicDeletionScenarios:
    """Reproduce real-world incidents."""

    def _guard_with_t2_rules(self) -> Guard:
        """Create a Guard with catastrophic deletion T2 rules."""
        policy = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="block-catastrophic-deletion",
                    tools=[
                        "shell_execute",
                        "Bash",
                        "run_shell_command",
                        "run_command",
                        "shell",
                        "shell_*",
                    ],
                    action="deny",
                    conditions=RuleConditions(
                        args_match={"command": ["rm -rf", "rm -r"]},
                        path_match={"command": ["~/", "/"]},
                    ),
                    message="Catastrophic recursive deletion blocked.",
                ),
            ],
        )
        return Guard(policy=policy, self_protection=False)

    def test_claude_code_tilde_expansion(self):
        """rm -rf tests/ patches/ plan/ ~/ → DENIED.

        Reproduces the Claude Code home directory deletion incident.
        """
        guard = self._guard_with_t2_rules()
        decision = guard.evaluate(
            "Bash",
            {"command": "rm -rf tests/ patches/ plan/ ~/"},
        )
        assert decision.allowed is False
        assert decision.policy_name == "block-catastrophic-deletion"

    def test_rm_rf_home_via_env_var(self):
        """rm -rf $HOME → DENIED."""
        guard = self._guard_with_t2_rules()
        decision = guard.evaluate(
            "Bash",
            {"command": "rm -rf $HOME"},
        )
        assert decision.allowed is False

    def test_rm_rf_root(self):
        """rm -rf / → DENIED."""
        guard = self._guard_with_t2_rules()
        decision = guard.evaluate(
            "Bash",
            {"command": "rm -rf /"},
        )
        assert decision.allowed is False

    def test_safe_rm_in_workspace(self, tmp_path):
        """rm -rf ./build/ → ALLOWED (not under protected paths when using specific dirs)."""
        policy = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="block-sensitive-delete",
                    tools=["Bash"],
                    action="deny",
                    conditions=RuleConditions(
                        args_match={"command": ["rm -rf"]},
                        path_match={"command": ["~/.ssh/", "/etc/"]},
                    ),
                ),
            ],
        )
        guard = Guard(policy=policy, self_protection=False)
        decision = guard.evaluate(
            "Bash",
            {"command": f"rm -rf {tmp_path}/build"},
        )
        assert decision.allowed is True


class TestWorkspaceBoundary:
    """Test workspace boundary enforcement."""

    def test_write_inside_workspace_allowed(self, tmp_path):
        workspace = tmp_path / "project"
        workspace.mkdir()
        target = workspace / "src" / "main.py"
        target.parent.mkdir(parents=True)

        policy = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="enforce-workspace-boundary",
                    tools=["Write", "Edit", "write_file"],
                    action="deny",
                    conditions=RuleConditions(
                        path_not_match={"file_path": ["__workspace__"]},
                        workspace=str(workspace),
                    ),
                ),
            ],
        )
        guard = Guard(policy=policy, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": str(target)})
        assert decision.allowed is True

    def test_write_outside_workspace_denied(self, tmp_path):
        workspace = tmp_path / "project"
        workspace.mkdir()

        policy = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="enforce-workspace-boundary",
                    tools=["Write", "Edit", "write_file"],
                    action="deny",
                    conditions=RuleConditions(
                        path_not_match={"file_path": ["__workspace__"]},
                        workspace=str(workspace),
                    ),
                ),
            ],
        )
        guard = Guard(policy=policy, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": "/etc/passwd"})
        assert decision.allowed is False

    def test_workspace_env_var_override(self, tmp_path, monkeypatch):
        workspace = tmp_path / "myproject"
        workspace.mkdir()
        monkeypatch.setenv("AVAKILL_WORKSPACE", str(workspace))

        policy = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="enforce-workspace-boundary",
                    tools=["Write"],
                    action="deny",
                    conditions=RuleConditions(
                        path_not_match={"file_path": ["__workspace__"]},
                    ),
                ),
            ],
        )
        guard = Guard(policy=policy, self_protection=False)

        # Inside workspace → allowed
        inside = workspace / "file.txt"
        assert guard.evaluate("Write", {"file_path": str(inside)}).allowed is True

        # Outside workspace → denied
        assert guard.evaluate("Write", {"file_path": "/tmp/evil.txt"}).allowed is False


class TestSymlinkEscape:
    """Test symlink escape detection."""

    def test_symlink_to_etc_caught(self, tmp_path):
        """A symlink pointing to /etc is resolved and blocked."""
        link = tmp_path / "innocent"
        link.symlink_to("/etc")
        target = str(link / "passwd")

        policy = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="block-system-reads",
                    tools=["Read", "read_file"],
                    action="deny",
                    conditions=RuleConditions(
                        path_match={"file_path": ["/etc/"]},
                    ),
                ),
            ],
        )
        guard = Guard(policy=policy, self_protection=False)
        decision = guard.evaluate("Read", {"file_path": target})
        assert decision.allowed is False


class TestCatalogRulesIntegration:
    """Test T2 rules from the rule catalog generate functional policies."""

    def test_catalog_t2_policy_blocks_home_deletion(self):
        """Build a policy from catalog T2 rules and verify it blocks rm -rf ~/."""
        policy_dict = build_policy_dict(
            ["block-catastrophic-deletion"],
            default_action="allow",
        )
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate(
            "Bash",
            {"command": "rm -rf ~/"},
        )
        assert decision.allowed is False

    def test_catalog_ssh_key_rule_blocks_access(self):
        """Build a policy with block-ssh-key-access and verify it works."""
        policy_dict = build_policy_dict(
            ["block-ssh-key-access"],
            default_action="allow",
        )
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate(
            "Read",
            {"file_path": "~/.ssh/id_rsa"},
        )
        assert decision.allowed is False

    def test_catalog_cloud_credentials_blocked(self):
        """Block access to ~/.aws/ credentials."""
        policy_dict = build_policy_dict(
            ["block-cloud-credentials"],
            default_action="allow",
        )
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate(
            "Read",
            {"file_path": "~/.aws/credentials"},
        )
        assert decision.allowed is False

    def test_catalog_system_dir_writes_blocked(self):
        """Block writes to /etc/."""
        policy_dict = build_policy_dict(
            ["block-system-dir-writes"],
            default_action="allow",
        )
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate(
            "Write",
            {"file_path": "/etc/hosts"},
        )
        assert decision.allowed is False

    def test_catalog_full_t2_policy_validates(self):
        """All T2 rules together produce a valid, functional policy."""
        from avakill.cli.rule_catalog import ALL_RULES

        t2_ids = [r.id for r in ALL_RULES if r.tier == 2]
        output = generate_yaml(t2_ids, default_action="allow")
        # Validate YAML roundtrip
        import yaml

        parsed = yaml.safe_load(output)
        PolicyConfig.model_validate(parsed)
        # Create Guard from it
        guard = Guard(policy=parsed, self_protection=False)
        # Basic smoke test
        decision = guard.evaluate("Bash", {"command": "ls -la"})
        assert decision.allowed is True


class TestPerformance:
    """Verify path resolution doesn't blow the <1ms evaluation budget."""

    def test_evaluation_under_1ms(self):
        policy = PolicyConfig(
            default_action="allow",
            policies=[
                PolicyRule(
                    name="block-sensitive",
                    tools=["Bash"],
                    action="deny",
                    conditions=RuleConditions(
                        args_match={"command": ["rm -rf"]},
                        path_match={"command": ["~/.ssh/", "/etc/"]},
                    ),
                ),
            ],
        )
        guard = Guard(policy=policy, self_protection=False)

        # Warmup
        for _ in range(5):
            guard.evaluate("Bash", {"command": "echo hello"})

        # Measure 100 iterations
        start = time.monotonic()
        for _ in range(100):
            guard.evaluate("Bash", {"command": "echo hello"})
        elapsed = (time.monotonic() - start) * 1000  # ms total

        avg_ms = elapsed / 100
        assert avg_ms < 1.0, f"Average evaluation took {avg_ms:.3f}ms (budget: <1ms)"


class TestCatalogT1BaseRules:
    """Integration tests for T1 base rules (always included)."""

    def test_catastrophic_shell_blocks_rm_rf_root(self):
        """block-catastrophic-shell blocks rm -rf /."""
        policy_dict = build_policy_dict([], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "rm -rf /"})
        assert decision.allowed is False

    def test_catastrophic_shell_allows_safe_rm(self):
        """block-catastrophic-shell allows safe rm."""
        policy_dict = build_policy_dict([], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "rm file.txt"})
        assert decision.allowed is True

    def test_catastrophic_sql_shell_blocks_drop_database(self):
        """block-catastrophic-sql-shell blocks DROP DATABASE via shell."""
        policy_dict = build_policy_dict([], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "DROP DATABASE prod"})
        assert decision.allowed is False

    def test_catastrophic_sql_db_blocks_drop_database(self):
        """block-catastrophic-sql-db blocks DROP DATABASE via database tools."""
        policy_dict = build_policy_dict([], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("execute_sql", {"query": "DROP DATABASE prod"})
        assert decision.allowed is False


class TestCatalogT1OptionalRules:
    """Integration tests for T1 optional rules."""

    def test_dangerous_shell_blocks_sudo(self):
        """block-dangerous-shell blocks sudo."""
        policy_dict = build_policy_dict(["block-dangerous-shell"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "sudo rm -rf /tmp"})
        assert decision.allowed is False

    def test_dangerous_shell_allows_ls(self):
        """block-dangerous-shell allows safe commands."""
        policy_dict = build_policy_dict(["block-dangerous-shell"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "ls -la"})
        assert decision.allowed is True

    def test_destructive_tools_blocks_delete_tool(self):
        """block-destructive-tools blocks delete_* tool names."""
        policy_dict = build_policy_dict(["block-destructive-tools"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("delete_file", {"path": "/tmp/foo"})
        assert decision.allowed is False

    def test_destructive_sql_blocks_truncate(self):
        """block-destructive-sql blocks TRUNCATE."""
        policy_dict = build_policy_dict(["block-destructive-sql"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("execute_sql", {"query": "TRUNCATE TABLE users"})
        assert decision.allowed is False

    def test_package_install_requires_approval(self):
        """approve-package-installs blocks pip install (require_approval)."""
        policy_dict = build_policy_dict(["approve-package-installs"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "pip install requests"})
        assert decision.allowed is False

    def test_sensitive_files_blocks_env(self):
        """block-sensitive-file-access blocks .env reads."""
        policy_dict = build_policy_dict(["block-sensitive-file-access"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Read", {"file_path": ".env"})
        assert decision.allowed is False

    def test_sensitive_files_allows_normal_read(self):
        """block-sensitive-file-access allows normal file reads."""
        policy_dict = build_policy_dict(["block-sensitive-file-access"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Read", {"file_path": "src/main.py"})
        assert decision.allowed is True

    def test_web_rate_limit_allows_within_limit(self):
        """rate-limit-web-search allows calls within rate limit."""
        policy_dict = build_policy_dict(["rate-limit-web-search"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("WebSearch", {})
        assert decision.allowed is True

    def test_shell_allowlist_allows_safe_command(self):
        """shell-command-allowlist allows allowlisted commands."""
        policy_dict = build_policy_dict(["shell-command-allowlist"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "echo hello"})
        assert decision.allowed is True

    def test_agent_rate_limit_allows_within_limit(self):
        """rate-limit-agent-spawn allows calls within rate limit."""
        policy_dict = build_policy_dict(["rate-limit-agent-spawn"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Task", {})
        assert decision.allowed is True

    def test_file_write_approval_requires_approval(self):
        """require-file-write-approval blocks writes (require_approval)."""
        policy_dict = build_policy_dict(["require-file-write-approval"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": "foo.txt"})
        assert decision.allowed is False


class TestCatalogT2RulesExtended:
    """Integration tests for T2 rules not covered by existing tests."""

    def test_deletion_outside_workspace_blocked(self, tmp_path):
        """block-deletion-outside-workspace blocks rm -rf outside workspace."""
        policy_dict = build_policy_dict(
            ["block-deletion-outside-workspace"], default_action="allow"
        )
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "rm -rf /tmp/other"})
        assert decision.allowed is False

    def test_symlink_escape_blocks_etc_read(self):
        """block-symlink-escape blocks reads resolving to /etc/."""
        policy_dict = build_policy_dict(["block-symlink-escape"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Read", {"file_path": "/etc/passwd"})
        assert decision.allowed is False

    def test_ownership_changes_blocked(self):
        """block-ownership-changes blocks chown outside workspace."""
        policy_dict = build_policy_dict(["block-ownership-changes"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Bash", {"command": "chown root /etc/hosts"})
        assert decision.allowed is False

    def test_profile_modification_blocked(self):
        """block-profile-modification blocks writes to ~/.bashrc."""
        policy_dict = build_policy_dict(["block-profile-modification"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": "~/.bashrc"})
        assert decision.allowed is False

    def test_startup_persistence_blocked(self):
        """block-startup-persistence blocks writes to LaunchAgents."""
        policy_dict = build_policy_dict(["block-startup-persistence"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": "~/Library/LaunchAgents/evil.plist"})
        assert decision.allowed is False

    def test_env_outside_workspace_blocked(self):
        """block-env-outside-workspace blocks .env access outside workspace."""
        policy_dict = build_policy_dict(["block-env-outside-workspace"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Read", {"file_path": "/other/project/.env"})
        assert decision.allowed is False

    def test_launchagent_creation_blocked(self):
        """block-launchagent-creation blocks plist writes to LaunchAgents."""
        policy_dict = build_policy_dict(["block-launchagent-creation"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": "~/Library/LaunchAgents/evil.plist"})
        assert decision.allowed is False

    def test_systemd_persistence_blocked(self):
        """block-systemd-persistence blocks writes to systemd dirs."""
        policy_dict = build_policy_dict(["block-systemd-persistence"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": "/etc/systemd/system/evil.service"})
        assert decision.allowed is False

    def test_system_file_modification_blocked(self):
        """block-system-file-modification blocks writes to /etc/passwd."""
        policy_dict = build_policy_dict(["block-system-file-modification"], default_action="allow")
        guard = Guard(policy=policy_dict, self_protection=False)
        decision = guard.evaluate("Write", {"file_path": "/etc/passwd"})
        assert decision.allowed is False
