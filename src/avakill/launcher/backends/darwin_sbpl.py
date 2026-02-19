"""Allow-based SBPL profile generator for macOS sandbox_init.

Generates Sandbox Profile Language profiles from SandboxConfig allow
rules. Unlike SandboxExecEnforcer (deny-based from PolicyConfig), this
produces deny-default profiles with explicit allows - the correct
pattern for child process sandboxing.
"""

from __future__ import annotations

from pathlib import Path

from avakill.core.models import SandboxConfig


def generate_sbpl_profile(config: SandboxConfig) -> str:
    """Generate an allow-based SBPL profile from SandboxConfig.

    The profile denies everything by default, then explicitly allows:
    - Baseline operations (sysctl, mach, signal, process-fork)
    - File reads for specified paths
    - File writes for specified paths
    - Process execution for specified binaries
    - Network outbound for specified hosts/ports
    """
    lines: list[str] = [
        "(version 1)",
        "",
        ";; AvaKill-generated sandbox profile (allow-based)",
        ";; Deny everything by default, then allow specific operations",
        "(deny default)",
        "",
        ";; Baseline: operations required for any process to function",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow mach-register)",
        "(allow signal (target self))",
        "(allow process-fork)",
        "(allow process-info*)",
        "(allow file-read-metadata)",
        "(allow file-read-xattr)",
        "(allow file-write-xattr)",
        "",
    ]

    paths = config.allow_paths
    network = config.allow_network

    # File reads
    read_paths = [str(Path(p).expanduser().resolve()) for p in paths.read]
    if read_paths:
        lines.append(";; Allowed read paths")
        for p in read_paths:
            lines.append(f'(allow file-read* (subpath "{p}"))')
        lines.append("")

    # File writes
    write_paths = [str(Path(p).expanduser().resolve()) for p in paths.write]
    if write_paths:
        lines.append(";; Allowed write paths")
        for p in write_paths:
            lines.append(f'(allow file-write* (subpath "{p}"))')
        lines.append("")

    # Executable paths - use literal for files, subpath for directories
    exec_paths = [str(Path(p).expanduser().resolve()) for p in paths.execute]
    if exec_paths:
        lines.append(";; Allowed executables")
        for p in exec_paths:
            resolved = Path(p)
            if resolved.is_dir():
                lines.append(f'(allow process-exec (subpath "{p}"))')
            else:
                lines.append(f'(allow process-exec (literal "{p}"))')
        for p in exec_paths:
            resolved = Path(p)
            if resolved.is_dir():
                lines.append(f'(allow file-read* (subpath "{p}"))')
            else:
                lines.append(f'(allow file-read* (literal "{p}"))')
        lines.append("")

    # Network outbound
    if network.connect:
        lines.append(";; Allowed outbound network connections")
        for entry in network.connect:
            if ":" in entry:
                host, port = entry.rsplit(":", 1)
                lines.append(f'(allow network-outbound (remote tcp "{host}" (to port {port})))')
            else:
                lines.append(f'(allow network-outbound (remote tcp "{entry}"))')
        lines.append("")

    # Network bind (for servers)
    if network.bind:
        lines.append(";; Allowed bind ports")
        for entry in network.bind:
            port = entry.rsplit(":", 1)[-1] if ":" in entry else entry
            lines.append(f"(allow network-bind (local tcp (to port {port})))")
        lines.append("")

    return "\n".join(lines) + "\n"
