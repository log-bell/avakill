"""MCP config wrapping and unwrapping for AvaKill proxy interception.

Rewrites agent MCP config files so all server traffic routes through
the AvaKill proxy, and can reverse the process to restore originals.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path

from avakill.mcp.config import MCPConfig, MCPServerEntry, is_already_wrapped

logger = logging.getLogger("avakill.mcp.wrapper")


def _resolve_shim_binary() -> str:
    """Find the avakill-shim binary, preferring /usr/local/bin.

    Returns the path to use as the wrapper command.  Falls back to
    ``avakill`` (Python CLI) if the Go shim is not installed.
    """
    # 1. Preferred location
    preferred = Path("/usr/local/bin/avakill-shim")
    if preferred.is_file() and os.access(preferred, os.X_OK):
        return str(preferred)

    # 2. Anywhere on PATH
    shim = shutil.which("avakill-shim")
    if shim:
        return shim

    # 3. Fallback: Python CLI
    return "avakill"


def _resolve_upstream_binary(command: str) -> str:
    """Resolve a bare command name to an absolute path at wrap time.

    This avoids PATH-order issues when the MCP client spawns the shim
    with a restricted PATH (e.g., launchd on macOS).

    Returns *command* unchanged if resolution fails (the shim will
    resolve it at runtime via shell env recovery).
    """
    resolved = shutil.which(command)
    return resolved if resolved else command


def wrap_mcp_config(
    config: MCPConfig,
    policy: str | Path,
    *,
    daemon: bool = False,
    log_db: str | Path | None = None,
) -> MCPConfig:
    """Wrap all MCP server entries to route through AvaKill proxy.

    For each stdio server::

        command: "npx" args: ["-y", "@anthropic/mcp-fs", "/path"]

    Becomes (Go shim)::

        command: "avakill-shim"
        args: ["--policy", "...", "--", "npx", "-y", ...]

    Or (Python fallback)::

        command: "avakill" args: ["mcp-proxy", "--policy", "...",
                 "--upstream-cmd", "npx", "--upstream-args", "-y @anthropic/mcp-fs /path"]

    This is idempotent — already-wrapped entries are skipped.
    """
    shim_binary = _resolve_shim_binary()
    use_shim = "avakill-shim" in shim_binary
    policy_abs = str(Path(policy).resolve())

    wrapped_servers: list[MCPServerEntry] = []

    for server in config.servers:
        if is_already_wrapped(server):
            wrapped_servers.append(server)
            continue

        if server.transport != "stdio":
            # Non-stdio servers pass through unchanged for now
            wrapped_servers.append(server)
            continue

        if use_shim:
            # Go shim uses -- separator: avakill-shim [flags] -- <cmd> [args...]
            # Args stay as discrete array elements — no joining, no splitting.
            shim_flags: list[str] = []

            if daemon:
                shim_flags.extend(["--socket", "~/.avakill/avakill.sock"])
            else:
                shim_flags.extend(["--policy", policy_abs])

            # Build: [shim_flags..., "--", upstream_cmd, upstream_args...]
            args = shim_flags + ["--", server.command] + (server.args or [])

            wrapped = MCPServerEntry(
                name=server.name,
                command=shim_binary,
                args=args,
                env=server.env,
                transport=server.transport,
            )
        else:
            # Fallback: Python avakill CLI — resolve upstream to absolute
            # path since Python proxy doesn't have shell env recovery.
            resolved_upstream = _resolve_upstream_binary(server.command)
            args = ["mcp-proxy"]

            if daemon:
                args.extend(["--daemon", "~/.avakill/avakill.sock"])
            else:
                args.extend(["--policy", policy_abs])

            if log_db:
                args.extend(["--log-db", str(log_db)])

            args.extend(["--upstream-cmd", resolved_upstream])
            if server.args:
                args.extend(["--upstream-args", " ".join(server.args)])

            wrapped = MCPServerEntry(
                name=server.name,
                command="avakill",
                args=args,
                env=server.env,
                transport=server.transport,
            )

        wrapped_servers.append(wrapped)

    return MCPConfig(
        agent=config.agent,
        config_path=config.config_path,
        servers=wrapped_servers,
    )


def unwrap_mcp_config(config: MCPConfig) -> MCPConfig:
    """Reverse wrap_mcp_config: restore original server commands.

    Supports two formats:
    - Go shim (--): args contain "--", everything after is command + args
    - Python fallback: args contain "--upstream-cmd" and "--upstream-args"
    """
    unwrapped_servers: list[MCPServerEntry] = []

    for server in config.servers:
        if not is_already_wrapped(server):
            unwrapped_servers.append(server)
            continue

        upstream_cmd = ""
        upstream_args: list[str] = []

        if "--" in server.args:
            # Go shim format: [shim_flags..., "--", cmd, arg1, arg2, ...]
            sep_idx = server.args.index("--")
            remaining = server.args[sep_idx + 1 :]
            if remaining:
                upstream_cmd = remaining[0]
                upstream_args = remaining[1:]
        else:
            # Python fallback format: --upstream-cmd <cmd> --upstream-args <space-joined>
            args_iter = iter(server.args)
            for arg in args_iter:
                if arg == "--upstream-cmd":
                    upstream_cmd = next(args_iter, "")
                elif arg == "--upstream-args":
                    raw = next(args_iter, "")
                    upstream_args = raw.split() if raw else []

        if not upstream_cmd:
            unwrapped_servers.append(server)
            continue

        restored = MCPServerEntry(
            name=server.name,
            command=upstream_cmd,
            args=upstream_args,
            env=server.env,
            transport=server.transport,
        )
        unwrapped_servers.append(restored)

    return MCPConfig(
        agent=config.agent,
        config_path=config.config_path,
        servers=unwrapped_servers,
    )


def write_mcp_config(config: MCPConfig) -> None:
    """Write the modified config back to disk.

    Creates a ``.bak`` backup of the original file before overwriting.
    Preserves non-MCP keys in the original config.
    """
    config_path = config.config_path
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # Read original to preserve non-MCP keys
    raw = json.loads(config_path.read_text())

    # Create backup
    backup_path = config_path.with_suffix(config_path.suffix + ".bak")
    shutil.copy2(config_path, backup_path)
    logger.info("Backup created: %s", backup_path)

    # Rebuild mcpServers dict
    servers_dict: dict[str, dict] = {}
    for server in config.servers:
        entry: dict = {"command": server.command}
        if server.args:
            entry["args"] = server.args
        if server.env:
            entry["env"] = server.env
        if server.url:
            entry["url"] = server.url
        if server.transport != "stdio":
            entry["transport"] = server.transport
        servers_dict[server.name] = entry

    # Write back — detect which key the original used
    if "mcpServers" in raw:
        raw["mcpServers"] = servers_dict
    elif "servers" in raw:
        raw["servers"] = servers_dict
    else:
        raw["mcpServers"] = servers_dict

    config_path.write_text(json.dumps(raw, indent=2) + "\n")
    logger.info("Config written: %s", config_path)
