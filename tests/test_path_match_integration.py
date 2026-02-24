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
