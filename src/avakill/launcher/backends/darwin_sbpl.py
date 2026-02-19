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
    # Platform baseline derived from OpenAI Codex's seatbelt policies.
    # Without these, even basic commands fail because dyld can't load libraries.
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
        "(allow ipc-posix-sem)",
        "(allow pseudo-tty)",
        "",
        ";; dyld: allow loading system frameworks and shared libraries",
        '(allow file-map-executable (subpath "/usr/lib"))',
        '(allow file-map-executable (subpath "/System/Library"))',
        '(allow file-map-executable (subpath "/Library/Apple/System/Library"))',
        '(allow file-map-executable (subpath "/Library/Apple/usr/lib"))',
        "",
        ";; System paths required for basic process operation",
        '(allow file-read* (subpath "/usr/lib"))',
        '(allow file-read* (subpath "/usr/share"))',
        '(allow file-read* (subpath "/private/etc"))',
        '(allow file-read* (subpath "/private/var/db/timezone"))',
        '(allow file-read* (literal "/dev/null"))',
        '(allow file-read* (literal "/dev/urandom"))',
        '(allow file-read* (literal "/dev/random"))',
        '(allow file-read* (literal "/"))',
        '(allow file-write-data (literal "/dev/null"))',
        "",
        ";; PTY support for interactive processes",
        '(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))',
        '(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+"))',
        '(allow file-ioctl (regex #"^/dev/ttys[0-9]+"))',
        "",
        ";; Network: Unix domain sockets for system services",
        '(allow network-outbound (literal "/private/var/run/syslog"))',
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

    # File writes — also grant read access (you need to list a dir to write into it)
    write_paths = [str(Path(p).expanduser().resolve()) for p in paths.write]
    if write_paths:
        lines.append(";; Allowed write paths (read + write)")
        for p in write_paths:
            lines.append(f'(allow file-read* (subpath "{p}"))')
            lines.append(f'(allow file-write* (subpath "{p}"))')
        lines.append("")

    # Executables: allow process-exec for read paths (directories) and explicit binaries
    # Codex uses a broad (allow process-exec) — we scope it to allowed paths.
    if read_paths:
        lines.append(";; Allow execution of binaries in readable paths")
        for p in read_paths:
            lines.append(f'(allow process-exec (subpath "{p}"))')

    exec_paths = [str(Path(p).expanduser().resolve()) for p in paths.execute]
    if exec_paths:
        lines.append(";; Explicitly allowed executables")
        for p in exec_paths:
            resolved = Path(p)
            if resolved.is_dir():
                lines.append(f'(allow process-exec (subpath "{p}"))')
            else:
                lines.append(f'(allow process-exec (literal "{p}"))')
                lines.append(f'(allow file-read* (literal "{p}"))')
        lines.append("")

    # Network outbound — SBPL inline mode doesn't support host/port filters,
    # so we allow TCP outbound broadly. Fine-grained host filtering is handled
    # by the cooperative policy engine (hooks/MCP proxy), not the kernel sandbox.
    if network.connect:
        lines.append(";; Allowed outbound network connections (TCP)")
        lines.append("(allow network-outbound (remote tcp))")
        lines.append("")

    # Network bind
    if network.bind:
        lines.append(";; Allowed network bind")
        lines.append("(allow network-bind (local tcp))")
        lines.append("")

    return "\n".join(lines) + "\n"
