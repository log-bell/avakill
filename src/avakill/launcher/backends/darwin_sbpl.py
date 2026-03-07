"""Deny-default SBPL profile generator for macOS sandbox-exec.

Generates Sandbox Profile Language profiles using broad reads + scoped
writes + sensitive path denials. Works out of the box for all AI agents.

Also provides ``default_sandbox_config()`` for generating sensible
sandbox defaults during ``avakill setup``.
"""

from __future__ import annotations

from pathlib import Path

from avakill.core.models import (
    SandboxConfig,
    SandboxDenyPaths,
    SandboxNetworkRules,
    SandboxPathRules,
)


def generate_sbpl_profile(config: SandboxConfig) -> str:
    """Generate a deny-default SBPL profile from SandboxConfig.

    Uses broad reads (system paths + $HOME) with sensitive path denials,
    scoped writes via parameters, and enumerated Mach services. Based on
    research baseline from production sandbox profiles (Codex, ai-jail,
    Nix, Chromium, Homebrew).
    """
    lines: list[str] = [
        "(version 1)",
        "(deny default)",
        "",
        ";; Process operations",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        "(allow signal (target same-sandbox))",
        "(allow sysctl-read)",
        "(allow mach-host*)",
        "",
        ";; Mach IPC — enumerated service lookups",
        "(allow mach-lookup",
        '  (global-name "com.apple.system.opendirectoryd.libinfo")',
        '  (global-name "com.apple.system.logger")',
        '  (global-name "com.apple.system.notification_center")',
        '  (global-name "com.apple.cfprefsd.daemon")',
        '  (global-name "com.apple.cfprefsd.agent")',
        '  (global-name "com.apple.trustd")',
        '  (global-name "com.apple.trustd.agent")',
        '  (global-name "com.apple.ocspd")',
        '  (global-name "com.apple.SecurityServer")',
        '  (global-name "com.apple.securityd")',
        '  (global-name "com.apple.coreservices.launchservicesd")',
        '  (global-name "com.apple.lsd.mapdb")',
        '  (global-name-regex #"^com\\.apple\\.distributed_notifications")',
        ")",
        "(allow mach-register)",
        "",
        ";; IPC — shared memory and semaphores",
        "(allow ipc-posix-shm-read-data)",
        "(allow ipc-posix-shm-write-data)",
        "(allow ipc-posix-shm-write-create)",
        "(allow ipc-posix-sem)",
        "",
        ";; Terminal / PTY — file-ioctl is critical for interactive tools",
        "(allow pseudo-tty)",
        "(allow file-ioctl)",
        "",
        "(allow file-read* file-write*",
        '  (literal "/dev/ptmx")',
        '  (regex #"/dev/ttys[0-9]+")',
        '  (literal "/dev/tty")',
        '  (literal "/dev/null")',
        '  (literal "/dev/zero"))',
        "",
        "(allow file-read*",
        '  (literal "/dev/random")',
        '  (literal "/dev/urandom")',
        '  (subpath "/dev/fd"))',
        "",
        ";; IOKit — hardware queries",
        "(allow iokit-open)",
        "",
        ";; File reads — system paths",
        ";; literal '/' is required on macOS 26+ for dyld path resolution",
        '(allow file-read* (literal "/"))',
        "(allow file-read*",
        '  (subpath "/usr/lib")',
        '  (subpath "/usr/share")',
        '  (subpath "/System")',
        '  (subpath "/private/var/db/dyld")',
        '  (subpath "/System/Volumes/Preboot/Cryptexes/OS")',
        '  (subpath "/private/etc")',
        '  (subpath "/Library/Preferences")',
        '  (subpath "/Library/Managed Preferences")',
        '  (subpath "/System/Library/Keychains")',
        '  (subpath "/Library/Keychains")',
        '  (subpath "/private/var/db/mds")',
        '  (subpath "/Library/Apple")',
        '  (subpath "/opt/homebrew")',
        '  (subpath "/usr/local")',
        '  (subpath "/Library/Frameworks/Python.framework")',
        '  (subpath "/Library/Developer/CommandLineTools")',
        '  (subpath "/Library/Java/JavaVirtualMachines")',
        '  (subpath "/bin")',
        '  (subpath "/usr/bin")',
        '  (subpath "/usr/sbin")',
        '  (subpath "/sbin")',
        '  (subpath "/tmp")',
        '  (subpath "/private/tmp")',
        '  (subpath "/private/var/folders")',
        '  (subpath "/private/var/tmp"))',
        "",
        ";; File reads — user home (parameterized)",
        '(allow file-read* (subpath (param "HOME")))',
        "",
    ]

    # Sensitive path denials — override broad HOME read
    deny_paths = config.deny_paths.read
    if deny_paths:
        lines.append(";; Sensitive path denials")
        for i in range(len(deny_paths)):
            lines.append(f'(deny file-read* (subpath (param "DENY_PATH_{i}")))')
        lines.append("")

    # Scoped writes
    write_paths = config.allow_paths.write
    lines.append(";; File writes — scoped")
    lines.append("(allow file-write*")
    lines.append('  (subpath "/tmp")')
    lines.append('  (subpath "/private/tmp")')
    lines.append('  (subpath "/private/var/tmp")')
    lines.append('  (subpath "/private/var/folders")')
    for i in range(len(write_paths)):
        lines.append(f'  (subpath (param "WRITE_PATH_{i}"))')
    lines.append(")")
    lines.append("")

    # Network
    network = config.allow_network
    if network.connect or network.bind:
        lines.append(";; Network")
        if network.connect:
            lines.append("(allow network-outbound")
            lines.append('  (remote tcp "*:443")')
            lines.append('  (remote tcp "*:80")')
            lines.append('  (remote udp "*:53")')
            lines.append('  (remote tcp "localhost:*"))')
        lines.append('(allow network-bind (local tcp "localhost:*"))')
        lines.append('(allow network-inbound (local tcp "localhost:*"))')
        lines.append("(allow system-socket)")
        lines.append("")

    # User preferences
    lines.append(";; User preferences")
    lines.append("(allow user-preference-read")
    lines.append('  (preference-domain "kCFPreferencesAnyApplication")')
    lines.append('  (preference-domain "com.apple.security"))')
    lines.append("")

    return "\n".join(lines) + "\n"


def generate_sbpl_params(config: SandboxConfig) -> dict[str, str]:
    """Return the -D parameters for sandbox-exec invocation."""
    home = str(Path.home())
    params = {"HOME": home}

    write_paths = [str(Path(p).expanduser().resolve()) for p in config.allow_paths.write]
    for i, p in enumerate(write_paths):
        params[f"WRITE_PATH_{i}"] = p

    deny_paths = [str(Path(p).expanduser().resolve()) for p in config.deny_paths.read]
    for i, p in enumerate(deny_paths):
        params[f"DENY_PATH_{i}"] = p

    return params


# Common AI API endpoints for network allows
_DEFAULT_NETWORK_CONNECTS = [
    "api.anthropic.com:443",
    "api.openai.com:443",
    "generativelanguage.googleapis.com:443",
    "api.github.com:443",
]

_DEFAULT_DENY_PATHS = [
    "~/.ssh",
    "~/.gnupg",
    "~/.aws",
    "~/.kube",
    "~/.gcloud",
    "~/.azure",
    "~/Library/Keychains",
    "~/Library/Mail",
    "~/Library/Messages",
    "~/Library/Safari",
    "~/Library/Cookies",
]

_AGENT_CONFIG_DIRS = [
    "~/.gemini",
    "~/.claude",
    "~/.config/claude",
    "~/.cursor",
    "~/.windsurf",
    "~/.codex",
]


def default_sandbox_config(workspace: Path | None = None) -> SandboxConfig:
    """Build a sensible default SandboxConfig for the current environment.

    Uses broad reads (handled by the SBPL profile itself) with scoped
    writes and sensitive path denials. No binary resolution needed since
    the profile allows process-exec globally.

    This is called by ``avakill setup``, NOT by the SBPL generator.
    """
    ws = (workspace or Path.cwd()).resolve()
    home = Path.home()

    write_paths = [str(ws), "/tmp"]
    for agent_dir in _AGENT_CONFIG_DIRS:
        p = home / agent_dir.lstrip("~/")
        if p.is_dir():
            write_paths.append(str(p))

    return SandboxConfig(
        allow_paths=SandboxPathRules(write=write_paths),
        deny_paths=SandboxDenyPaths(read=list(_DEFAULT_DENY_PATHS)),
        allow_network=SandboxNetworkRules(connect=list(_DEFAULT_NETWORK_CONNECTS)),
    )
