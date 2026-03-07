"""Allow-based SBPL profile generator for macOS sandbox_init.

Generates Sandbox Profile Language profiles from SandboxConfig allow
rules. Unlike SandboxExecEnforcer (deny-based from PolicyConfig), this
produces deny-default profiles with explicit allows - the correct
pattern for child process sandboxing.

Also provides ``default_sandbox_config()`` for generating sensible
sandbox defaults during ``avakill setup``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from avakill.core.models import (
    SandboxConfig,
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
        '  (global-name-regex #"^com\\\\.apple\\\\.distributed_notifications")',
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

# System paths that should be readable on macOS
_DEFAULT_READ_PATHS = [
    "/usr",
    "/bin",
    "/sbin",
    "/private/etc/ssl",
    "/private/etc/resolv.conf",
    "/Library/Apple",
    "/System",
]

# Common runtime binaries to resolve
_RUNTIME_BINARIES = [
    "python3",
    "python",
    "node",
    "git",
    "npm",
    "pip",
    "uv",
    "pipx",
    # AI CLI tools — common avakill launch targets
    "gemini",
    "claude",
]

# Version manager markers — when found in a path, truncate to this segment
# so the allowed path covers all sessions/versions, not just one.
_VERSION_MANAGER_MARKERS = [
    "fnm_multishells",  # fnm per-session shim dirs
    "fnm/node-versions",  # fnm real node installations
    ".nvm/versions",  # nvm installations
    ".volta",  # volta shims + tools
]


def _stable_parent(dir_path: str) -> str:
    """If *dir_path* contains a version-manager marker, truncate there.

    For example::

        ~/.local/state/fnm_multishells/65523_xxx/bin  →  ~/.local/state/fnm_multishells
        ~/.local/share/fnm/node-versions/v22/…/bin    →  ~/.local/share/fnm/node-versions
    """
    for marker in _VERSION_MANAGER_MARKERS:
        idx = dir_path.find(marker)
        if idx != -1:
            return dir_path[: idx + len(marker)]
    return dir_path


def _resolve_binary_paths(binary: str) -> tuple[list[str], list[str]]:
    """Resolve a binary to exec dirs and extra read dirs.

    Follows symlinks to real paths and stabilises version-manager
    directories so the sandbox config survives across terminal sessions.

    Returns:
        (exec_dirs, read_dirs) — both lists may be empty.
    """
    resolved = shutil.which(binary)
    if not resolved:
        return [], []

    exec_dirs: list[str] = []
    read_dirs: list[str] = []
    resolved_path = Path(resolved)

    # The shim/wrapper directory (stabilised)
    shim_dir = _stable_parent(str(resolved_path.parent))
    exec_dirs.append(shim_dir)

    # Follow symlinks to real path
    try:
        real_path = resolved_path.resolve()
        if real_path != resolved_path:
            real_dir = _stable_parent(str(real_path.parent))
            if real_dir != shim_dir:
                exec_dirs.append(real_dir)
                # Node needs to read JS files at the real location
                read_dirs.append(real_dir)
    except (OSError, ValueError):
        pass

    return exec_dirs, read_dirs


def default_sandbox_config(workspace: Path | None = None) -> SandboxConfig:
    """Build a sensible default SandboxConfig for the current environment.

    Detects the workspace (defaults to cwd), resolves runtime binary
    locations (following symlinks through version managers like fnm, nvm,
    and volta), and includes standard system read paths plus Homebrew
    paths if present.

    This is called by ``avakill setup``, NOT by the SBPL generator.

    Args:
        workspace: Project root directory. Defaults to cwd.

    Returns:
        A SandboxConfig ready for YAML serialization.
    """
    ws = (workspace or Path.cwd()).resolve()

    # Resolve read paths: system paths + Homebrew if present
    read_paths = list(_DEFAULT_READ_PATHS)
    for brew_prefix in ("/opt/homebrew", "/usr/local/Cellar", "/usr/local/opt"):
        if Path(brew_prefix).is_dir():
            read_paths.append(brew_prefix)

    # Agent config directories (read-only — policy rules block writes)
    home = Path.home()
    for agent_dir in (".gemini", ".claude", ".cursor", ".windsurf", ".codex"):
        p = home / agent_dir
        if p.is_dir():
            read_paths.append(str(p))

    # Resolve execute paths from runtime binaries on PATH,
    # following symlinks and stabilising version-manager paths
    exec_paths: list[str] = []
    seen: set[str] = set()
    for binary in _RUNTIME_BINARIES:
        bin_exec, bin_read = _resolve_binary_paths(binary)
        for d in bin_exec:
            if d not in seen:
                seen.add(d)
                exec_paths.append(d)
        for d in bin_read:
            if d not in read_paths:
                read_paths.append(d)

    # Write paths: workspace + /tmp
    write_paths = [str(ws), "/tmp"]

    return SandboxConfig(
        allow_paths=SandboxPathRules(
            read=read_paths,
            write=write_paths,
            execute=exec_paths,
        ),
        allow_network=SandboxNetworkRules(
            connect=list(_DEFAULT_NETWORK_CONNECTS),
        ),
    )
