"""Tests for the Tetragon TracingPolicy generator."""

import yaml

from avakill.core.models import PolicyConfig, PolicyRule
from avakill.enforcement.tetragon import TetragonPolicyGenerator


def _deny_policy(*tools: str) -> PolicyConfig:
    """Create a policy that denies the given tools."""
    return PolicyConfig(
        version="1.0",
        default_action="allow",
        policies=[
            PolicyRule(name="deny-tools", tools=list(tools), action="deny"),
        ],
    )


def _empty_policy() -> PolicyConfig:
    """Create a policy with no deny rules."""
    return PolicyConfig(
        version="1.0",
        default_action="deny",
        policies=[
            PolicyRule(name="allow-all", tools=["*"], action="allow"),
        ],
    )


class TestTetragonPolicyGenerator:
    """Tests for Tetragon TracingPolicy YAML generation."""

    def test_generate_produces_valid_yaml(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        assert isinstance(parsed, dict)

    def test_generate_has_api_version(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        assert parsed["apiVersion"] == "cilium.io/v1alpha1"
        assert parsed["kind"] == "TracingPolicy"

    def test_generate_has_metadata(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        assert parsed["metadata"]["name"] == "avakill-enforcement"
        assert parsed["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "avakill"

    def test_generate_file_write_kprobe(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobes = parsed["spec"]["kprobes"]
        assert len(kprobes) >= 1

        calls = [k["call"] for k in kprobes]
        assert "security_file_open" in calls

    def test_generate_exec_kprobe(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("shell_execute")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobes = parsed["spec"]["kprobes"]
        calls = [k["call"] for k in kprobes]
        assert "security_bprm_check" in calls

    def test_generate_file_delete_kprobe(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_delete")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobes = parsed["spec"]["kprobes"]
        calls = [k["call"] for k in kprobes]
        assert "security_inode_unlink" in calls

    def test_generate_kprobe_has_sigkill_action(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("shell_execute")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobe = parsed["spec"]["kprobes"][0]
        actions = kprobe["selectors"][0]["matchActions"]
        assert actions[0]["action"] == "Sigkill"

    def test_generate_kprobe_has_args(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("shell_execute")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobe = parsed["spec"]["kprobes"][0]
        assert len(kprobe["args"]) > 0
        assert kprobe["args"][0]["index"] == 0

    def test_write_creates_file(self, tmp_path) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write", "shell_execute")
        output = tmp_path / "tetragon.yaml"

        result = gen.write(config, output)

        assert result == output
        assert output.exists()
        parsed = yaml.safe_load(output.read_text())
        assert parsed["apiVersion"] == "cilium.io/v1alpha1"

    def test_empty_policy_generates_minimal(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _empty_policy()
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        assert parsed["spec"]["kprobes"] == []

    def test_generate_wildcard_includes_all_kprobes(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("*")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobes = parsed["spec"]["kprobes"]
        calls = {k["call"] for k in kprobes}
        assert "security_file_open" in calls
        assert "security_bprm_check" in calls
        assert "security_inode_unlink" in calls

    def test_generate_deduplicates_kprobes(self) -> None:
        """file_write and file_edit both map to security_file_open — should appear once."""
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write", "file_edit")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobes = parsed["spec"]["kprobes"]
        calls = [k["call"] for k in kprobes]
        assert calls.count("security_file_open") == 1

    def test_generate_skips_allow_rules(self) -> None:
        gen = TetragonPolicyGenerator()
        config = PolicyConfig(
            version="1.0",
            default_action="deny",
            policies=[
                PolicyRule(name="allow-read", tools=["file_read"], action="allow"),
                PolicyRule(name="deny-write", tools=["file_write"], action="deny"),
            ],
        )
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobes = parsed["spec"]["kprobes"]
        assert len(kprobes) == 1

    def test_generate_glob_pattern(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_*")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobes = parsed["spec"]["kprobes"]
        calls = {k["call"] for k in kprobes}
        assert "security_file_open" in calls
        assert "security_inode_unlink" in calls

    def test_write_creates_parent_dirs(self, tmp_path) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write")
        output = tmp_path / "nested" / "dir" / "policy.yaml"

        result = gen.write(config, output)

        assert result == output
        assert output.exists()

    def test_generate_unknown_tool_no_kprobes(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("unknown_tool")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        assert parsed["spec"]["kprobes"] == []

    def test_generate_file_write_has_match_args(self) -> None:
        gen = TetragonPolicyGenerator()
        config = _deny_policy("file_write")
        output = gen.generate(config)

        parsed = yaml.safe_load(output)
        kprobe = parsed["spec"]["kprobes"][0]
        match_args = kprobe["selectors"][0].get("matchArgs", [])
        assert len(match_args) > 0
        assert match_args[0]["operator"] == "MaskAny"
