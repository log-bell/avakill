"""Cilium Tetragon TracingPolicy YAML generator.

Generates TracingPolicy resources that can be deployed to Kubernetes
clusters running Cilium Tetragon for kernel-level enforcement of
AvaKill policies.

Output only — policies are not applied directly. They are meant for
infrastructure teams to review and deploy via kubectl.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from avakill.core.models import PolicyConfig

# Map canonical tool names to kprobe specifications
TOOL_TO_KPROBES: dict[str, dict] = {
    "file_write": {
        "call": "security_file_open",
        "args": ["file", "int"],
        "selectors_matchArgs": [
            {"index": 1, "operator": "MaskAny", "values": ["O_WRONLY", "O_RDWR"]},
        ],
    },
    "file_delete": {
        "call": "security_inode_unlink",
        "args": ["inode", "dentry"],
    },
    "file_edit": {
        "call": "security_file_open",
        "args": ["file", "int"],
        "selectors_matchArgs": [
            {"index": 1, "operator": "MaskAny", "values": ["O_WRONLY", "O_RDWR"]},
        ],
    },
    "shell_execute": {
        "call": "security_bprm_check",
        "args": ["linux_binprm"],
    },
}


class TetragonPolicyGenerator:
    """Cilium Tetragon TracingPolicy YAML generator.

    Output only — not applied directly. For infra teams to deploy.
    """

    def generate(self, config: PolicyConfig) -> str:
        """Generate a TracingPolicy YAML from AvaKill deny rules.

        Args:
            config: The policy configuration to translate.

        Returns:
            A YAML string containing a Tetragon TracingPolicy resource.
        """
        kprobes = self._collect_kprobes(config)

        policy: dict = {
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicy",
            "metadata": {
                "name": "avakill-enforcement",
                "labels": {
                    "app.kubernetes.io/managed-by": "avakill",
                },
            },
            "spec": {
                "kprobes": kprobes if kprobes else [],
            },
        }

        return yaml.dump(
            policy,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

    def write(self, config: PolicyConfig, output: Path) -> Path:
        """Generate and write a TracingPolicy YAML to a file.

        Args:
            config: The policy configuration to translate.
            output: Path where the YAML should be written.

        Returns:
            The path where the YAML was written.
        """
        content = self.generate(config)
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        return output

    def _collect_kprobes(self, config: PolicyConfig) -> list[dict]:
        """Collect kprobe specs from deny rules."""
        seen_calls: set[str] = set()
        kprobes: list[dict] = []

        for rule in config.policies:
            if rule.action != "deny":
                continue
            for tool_pattern in rule.tools:
                specs = self._tool_pattern_to_kprobes(tool_pattern)
                for spec in specs:
                    call = spec["call"]
                    if call in seen_calls:
                        continue
                    seen_calls.add(call)

                    kprobe: dict = {
                        "call": call,
                        "syscall": False,
                        "args": [
                            {"index": i, "type": arg_type}
                            for i, arg_type in enumerate(spec.get("args", []))
                        ],
                        "selectors": [
                            {
                                "matchActions": [
                                    {
                                        "action": "Sigkill",
                                    }
                                ],
                            }
                        ],
                    }

                    # Add matchArgs to selectors if specified
                    if "selectors_matchArgs" in spec:
                        kprobe["selectors"][0]["matchArgs"] = spec[
                            "selectors_matchArgs"
                        ]

                    kprobes.append(kprobe)

        return kprobes

    def _tool_pattern_to_kprobes(self, tool_pattern: str) -> list[dict]:
        """Convert a tool name pattern to kprobe specs."""
        # Exact match
        if tool_pattern in TOOL_TO_KPROBES:
            return [TOOL_TO_KPROBES[tool_pattern]]

        # Wildcard
        if tool_pattern in ("*", "all"):
            return list(TOOL_TO_KPROBES.values())

        # Glob patterns
        from fnmatch import fnmatch

        specs = []
        for tool_name, spec in TOOL_TO_KPROBES.items():
            if fnmatch(tool_name, tool_pattern):
                specs.append(spec)
        return specs
