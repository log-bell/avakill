# AvaKill Rule Catalog: Product Vision and Roadmap

AvaKill intercepts tool calls from AI coding agents before execution. This document defines every rule category AvaKill will enforce, organized as a product roadmap: what ships now, what ships next, and what we're building toward.

Every major AI coding agent shipped in 2024-2025 has caused documented catastrophic data loss. Claude Code deleted entire home directories via tilde expansion. Google's Gemini-powered IDE wiped a user's D: drive. Cursor's denylist was proven trivially bypassable and subsequently removed entirely. Existing guardrails tools (Invariant/Snyk, LlamaFirewall, NeMo Guardrails) focus on content safety rather than tool-call interception -- the precise gap AvaKill fills.

---

## How this document is structured

### Categories with expandable rules

The setup wizard presents **10 categories** as toggles. Each category bundles multiple rules underneath. Most users toggle "Filesystem Protection" on and move on. Users who need fine-grained control expand a category to toggle individual rules within it.

```
[x] Filesystem Protection (5 of 7 rules)
    > Expand to customize

[x] Shell Safety (7 of 11 rules)
    v Expanded
    [x] block-catastrophic-shell          (base, always on)
    [x] block-dangerous-shell             rm -rf, sudo, chmod 777
    [x] block-privilege-escalation        sudo, su, doas, runas
    [x] block-permission-changes          chmod 777, chmod u+s
    [ ] block-ownership-changes           chown/chgrp outside workspace (T2)
    [x] block-pipe-to-shell              curl | bash, wget | sh
    [ ] detect-obfuscation                base64 | bash, encoded cmds (T3)
    [ ] detect-command-chaining           ;, &&, || chaining (T3)
    [x] block-critical-process-kill       kill -9 system processes
    [ ] limit-command-timeout             command timeout (300s)
    [ ] shell-command-allowlist           strict allowlist mode

[ ] Database Safety (0 of 4 rules)
    > Expand to customize
```

This gives category-level convenience for the 90% case and individual rule control for power users -- without forcing anyone to write YAML. Rules that require a higher engine tier than what's currently shipped are still shown (with their tier badge) so users can pre-select them for when that tier ships. The `--rule <id>` CLI flag remains available for fully non-interactive workflows.

### Engine capability tiers

Not all rules can be implemented with the current `args_match` substring engine. Each rule is tagged with the engine capability it requires:

| Tier | Engine capability | Description | Status |
|------|------------------|-------------|--------|
| **T1** | `substring` | Current `args_match` substring matching | **Shipped** (v0.5) |
| **T2** | `path-resolve` | Expand `~/`, `$HOME`, `%USERPROFILE%`, resolve `../` and symlinks before matching | **v1 blocker** |
| **T3** | `command-parse` | Split compound commands on `&&`, `;`, `\|`, `$()` and evaluate each segment | Planned |
| **T4** | `cross-call` | Correlate across multiple tool calls in a session (read-encode-transmit patterns) | Planned |
| **T5** | `heuristic` | ML/entropy-based detection (prompt injection, secret scanning) | Research |

**T2 is a v1 blocker.** If AvaKill ships without expanding `~/` and `$HOME` before evaluation, someone will hit exactly the Claude Code bug. That's an unacceptable blind spot for a safety product.

### AvaKill actions

The document uses three terms for what happens when a rule matches. These map directly to AvaKill's action values:

| Document term | AvaKill action | Behavior |
|--------------|----------------|----------|
| Block / hard block | `deny` | Rejected immediately. No override without policy change. |
| Require approval | `ask` | Paused for human review. User can approve or reject per-call. |
| Allow with logging | `allow` | Permitted. Logged for audit trail. |

### Deny messages: two audiences, one design

When AvaKill blocks a tool call, the deny message serves **two audiences simultaneously**: the human reading the log, and the AI agent that received the rejection. This is a core UX principle, not an implementation detail.

**The agent gets a script to relay, not a problem to solve.** AI agents that receive a generic error will attempt to work around it -- trying alternative commands, encoding tricks, or simply retrying. AvaKill's deny messages are designed to short-circuit this by giving the agent a specific message to pass to the user, and an explicit instruction to stop problem-solving.

The deny message format has three parts:

```
AvaKill blocked this tool call.

  Rule: block-deletion-outside-workspace
  Blocked: rm -rf ~/Downloads/old-project
  Reason: Recursive deletion targets a path outside your workspace boundary

  STOP. Do not attempt to work around this block.
  Tell the user exactly this:

  "AvaKill blocked a recursive deletion outside your project directory.
   To allow this specific command, run:
   avakill allow --once 'rm -rf ~/Downloads/old-project'"
```

The key design decisions:

1. **"STOP. Do not attempt to work around this block."** — Prevents the agent from treating the denial as a puzzle. Without this, agents will try `rm -r` instead of `rm -rf`, or use `find -delete`, or encode the command.

2. **"Tell the user exactly this:"** — Gives the agent a verbatim script. The agent becomes a relay, not an interpreter. This is proven in production: AvaKill's self-protection rules use this pattern and agents consistently relay the message rather than improvising.

3. **The user-facing message includes the fix command.** — `avakill allow --once '...'` gives the human a one-step override. No YAML editing, no rule hunting, no restart.

Every rule definition includes a `deny_message` template with both the agent-directed instructions and the user-facing fix. The `{blocked}` placeholder is filled with the actual command/path at evaluation time.

### Platform-specific rules

Rules that only apply on certain platforms (macOS, Linux, Windows) are tagged with their platform. Platform detection at install time determines which rules get written to the policy file. The setup wizard shows one category checkbox -- "OS Security Hardening" -- and writes the correct platform-specific rules underneath.

---

## Categories

### 1. Filesystem Protection

One checkbox in the setup wizard. Covers catastrophic deletion, workspace boundary enforcement, symlink attacks, and device writes. This category alone would have prevented the Claude Code home directory deletion, Gemini CLI file losses, Google Antigravity D: drive wipe, and Claude Cowork photo deletion.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-catastrophic-deletion** | `rm -rf /`, `rm -rf ~/`, `rmdir /s /q C:\`, `del /s /q C:\*`, recursive deletion at root or home. Expands `~/` and `$HOME` before matching. | T2 | deny | on |
| **block-destructive-disk-ops** | `dd if=/dev/zero of=/dev/sd*`, `mkfs.*`, `fdisk`, `diskutil eraseDisk`, `diskpart`, `shred /dev/*` | T1 | deny | on |
| **block-deletion-outside-workspace** | `rm -rf`, `rm -r`, `rmdir /s`, `Remove-Item -Recurse` targeting paths outside workspace. Resolves symlinks and `../` | T2 | deny | on |
| **block-device-writes** | Writes to `/dev/sd*`, `/dev/nvme*`, `/dev/mem`, `/dev/kmem` | T1 | deny | on |
| **block-symlink-escape** | Symlinks pointing outside workspace to sensitive paths. File operations following symlinks to protected paths. | T2 | deny | on |
| **require-safe-delete** | Flag `rm`, `del`, `Remove-Item` and suggest trash equivalents (`trash`, `gio trash`) | T1 | ask | off |
| **block-fork-bombs** | `:(){ :\|:& };:`, `while true; do`, infinite `fork()` patterns, resource exhaustion loops | T1 | deny | on |

**Key incidents**: Claude Code `rm -rf tests/ patches/ plan/ ~/` (trailing tilde expanded to home). Gemini CLI deleted project dirs when mkdir failed. Cursor YOLO mode cascaded deletions beyond project. Claude Cowork deleted 27,000 family photos. Google Antigravity IDE wiped D: drive.

---

### 2. Shell Safety

Defense-in-depth for shell command execution -- the primary attack surface for all coding agents. Includes privilege escalation, obfuscation detection, and command chaining.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-catastrophic-shell** | `rm -rf /`, `mkfs`, `dd if=`, `> /dev/`, fork bombs | T1 | deny | on (base) |
| **block-dangerous-shell** | `rm -rf`, `sudo`, `chmod 777` | T1 | deny | on |
| **block-privilege-escalation** | `sudo`, `su`, `doas`, `runas`, `pkexec`, `Start-Process -Verb RunAs` | T1 | ask | on |
| **block-permission-changes** | `chmod 777`, `chmod u+s` (SUID), `chmod -R` on system dirs, `icacls` granting Everyone | T1 | deny | on |
| **block-ownership-changes** | `chown`/`chgrp` outside workspace, especially `/etc/*`, `/usr/*`, `C:\Windows\*` | T2 | deny | on |
| **block-pipe-to-shell** | `curl \| bash`, `wget \| sh`, `Invoke-Expression downloadString(...)`. Allow-list known installers. | T1 | deny | on |
| **detect-obfuscation** | `base64 -d \| bash`, `powershell -EncodedCommand`, `eval $(xxd -r -p)`, decode-to-execute patterns | T3 | deny | on |
| **detect-command-chaining** | `;`, `&&`, `\|\|`, backticks, `$(...)` chaining unauthorized commands after allowlisted ones | T3 | deny | on |
| **block-critical-process-kill** | `kill -9`, `killall`, `pkill` targeting system processes (init, sshd, dockerd) | T1 | deny | on |
| **limit-command-timeout** | Commands exceeding configurable timeout (default 300s). `nohup` + `&` for suspicious commands. | T1 | deny | off |
| **shell-command-allowlist** | Only allow approved commands (echo, ls, git, python, ...). Strict mode. | T1 | allow | off |

**Key incidents**: Buck Shlegeris's agent ran `sudo` to edit GRUB bootloader, bricking machine. Cursor's denylist bypassed via base64 encoding. Gemini CLI's allowlist bypassed via `;` chaining. Cursor Plan Mode killed processes on remote machines.

---

### 3. Filesystem Write Protection

Controls where agents can write. Prevents modification of system files, shell profiles, and startup directories. Overlapping platform-specific concerns (LaunchAgents, systemd, Windows Startup) are handled internally -- the user sees one category.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-system-dir-writes** | Writes to `/etc/`, `/usr/`, `/sbin/`, `/boot/`, `/System/`, `/Library/` (system), `C:\Windows\`, `C:\Program Files\` | T2 | deny | on |
| **block-profile-modification** | `.bashrc`, `.zshrc`, `.bash_profile`, `.profile`, PowerShell `$PROFILE`, `.env` outside workspace | T2 | ask | on |
| **block-startup-persistence** | Platform-detected: `~/Library/LaunchAgents/` (macOS), `/etc/systemd/system/` (Linux), Windows Startup folder, registry Run keys, crontab | T2 | deny | on |
| **enforce-workspace-boundary** | All file read/write/delete outside configured workspace. Resolves symlinks, `../`, tilde, env vars. | T2 | deny | on |

**Key incidents**: Claude Code's permission system validated commands before shell expansion, allowing `rm -rf ~/` to pass. CVE-2025-53109/53110 demonstrated MCP Filesystem Server sandbox escape via path traversal.

---

### 4. Database Safety

Protects against destructive DDL and unqualified DML. Detects SQL in both shell tools and database tools.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-catastrophic-sql** | `DROP DATABASE`, `DROP SCHEMA` via shell and database tools | T1 | deny | on (base) |
| **block-destructive-sql** | `DELETE`, `TRUNCATE`, `ALTER`, `DROP TABLE` | T1 | deny | on |
| **block-unqualified-dml** | `DELETE FROM` / `UPDATE SET` without `WHERE` clause | T3 | deny | on |
| **block-db-permission-changes** | `GRANT ALL`, `REVOKE`, `ALTER USER`, `CREATE USER`, `DROP USER` | T1 | deny | off |

**Key incidents**: Replit agent deleted production database during code freeze. Claude Code dropped PostgreSQL databases explicitly excluded from cleanup instructions. 72% of organizations lack tested database recovery procedures.

---

### 5. Version Control Safety

Prevents force pushes, protected branch deletion, and credential commits.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-force-push** | `git push --force`, `git push -f` to protected branches (main/master/develop). `git filter-branch`, `bfg`. | T1 | deny | on |
| **block-branch-deletion** | `git branch -D main/master/develop`, `git push origin --delete main`. Configurable branch names. | T1 | deny | on |
| **detect-credential-commit** | `git add`/`git commit` staging files matching sensitive names: `.env`, `*.pem`, `*.key`, `id_rsa`, `credentials.json`. Filename substring match only (T1); content-level entropy scanning is T5/opt-in. | T1 | deny | on |

---

### 6. Package & Supply Chain

Controls package installation and registry configuration. Addresses OWASP LLM03 (supply chain).

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **approve-package-installs** | `npm install -g`, `pip install` (outside venv), `brew install`, `apt install`, `cargo install` | T1 | ask | on |
| **block-registry-manipulation** | `npm config set registry`, `pip config set global.index-url`, custom sources in `pyproject.toml` | T1 | deny | on |
| **flag-postinstall-scripts** | `npm install` without `--ignore-scripts`, packages with malicious postinstall hooks | T3 | ask | off |

**Key incidents**: CVE-2025-6514 `mcp-remote` npm package (437K+ downloads) had command injection via postinstall. OWASP LLM03 ranks supply chain as top-3 LLM vulnerability.

---

### 7. Network & Exfiltration Prevention

Controls outbound communication and detects data exfiltration patterns. Addresses Simon Willison's "Lethal Trifecta" (private data + untrusted content + external communication).

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **restrict-outbound-http** | `curl`, `wget`, HTTP connections to non-allowlisted domains. Default allowlist: package registries, docs sites. | T1 | deny | off |
| **block-dns-exfiltration** | `dig`, `nslookup` with encoded data in subdomains (`$(base64).attacker.com`) | T3 | deny | on |
| **block-ssh-unknown-hosts** | `ssh` to non-allowlisted hosts, `scp` to unknown destinations, SSH config changes | T1 | ask | on |
| **block-port-binding** | `nc -l`, `socat`, `python -m http.server` on 0.0.0.0, privileged ports (<1024) | T1 | deny | off |
| **block-firewall-changes** | `iptables`, `ufw`, `pfctl`, `netsh advfirewall`, route manipulation, DNS config changes | T1 | deny | on |
| **detect-encode-transmit** | Read file, base64/hex encode, send via HTTP/DNS. Cross-call correlation. | T4 | deny | on |
| **block-browser-data-access** | Chrome/Firefox/Safari profile dirs, cookie databases, saved passwords, history files | T1 | deny | on |
| **block-clipboard-exfil** | `pbcopy`/`xclip`/`Get-Clipboard` combined with network operations | T4 | deny | off |

**Key incidents**: CVE-2025-55284 Claude Code DNS exfiltration via prompt injection. CamoLeak attack used Copilot to exfiltrate secrets from private repos. Buck Shlegeris's agent SSH'd into desktop and bricked it.

---

### 8. Secrets & Credentials

Blocks access to sensitive credential files and detects secrets in outbound data.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-ssh-key-access** | `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/*.pem`, `~/.ssh/authorized_keys`, `~/.ssh/config` | T2 | deny | on |
| **block-cloud-credentials** | `~/.aws/credentials`, `~/.gcloud/`, `~/.azure/`, `~/.kube/config`, `~/.docker/config.json` | T2 | deny | on |
| **block-env-outside-workspace** | `.env`, `.env.local`, `.env.production` outside workspace. `printenv`/`env` piped to other commands. | T2 | deny | on |
| **detect-secrets-outbound** | Regex + entropy scan of outbound data for API keys (`sk-*`, `AKIA*`, `ghp_*`), tokens, private keys | T5 | deny | on |
| **block-credential-stores** | macOS Keychain (`security dump-keychain`), Linux `~/.gnupg/`, Windows Credential Manager (`cmdkey`, `vaultcmd`) | T1 | deny | on |
| **block-path-poisoning** | `export PATH=/tmp:$PATH`, `export PATH=.:$PATH`, untrusted PATH prepends | T1 | deny | on |
| **block-env-secret-exposure** | `printenv`, `env`, `set` piped/redirected when containing `$AWS_SECRET_ACCESS_KEY`, `$API_KEY`, etc. | T3 | deny | on |

**Key incidents**: Claude Code path traversal bug (issue #1585) allowed `~/.ssh/` access. Amazon Q supply chain attack (CVE-2025-8217) included S3 bucket deletion instructions. EnrichLead incident exposed all API keys in frontend code.

---

### 9. Cloud & Infrastructure

Protects cloud resources, containers, and orchestration. Addresses the blast radius when agents have cloud CLI access.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-cloud-resource-deletion** | `aws s3 rm/rb`, `aws ec2 terminate-instances`, `gcloud compute instances delete`, `terraform destroy` | T1 | ask | on |
| **block-iam-changes** | `aws iam`, `gcloud iam`, `az role`, security groups open to 0.0.0.0/0 | T1 | deny | off |
| **block-backup-deletion** | `aws rds delete-db-snapshot`, `aws ec2 delete-snapshot`, snapshot deletion in any cloud provider | T1 | deny | on |
| **block-destructive-docker** | `docker system prune -af`, `docker volume rm`, bulk container/image deletion | T1 | ask | on |
| **block-container-escape** | `docker run --privileged`, `-v /:/host`, `nsenter --target 1`, Docker socket access | T1 | deny | on |
| **block-k8s-destruction** | `kubectl delete namespace/deployment/pvc/node`, `helm uninstall` in production namespaces | T1 | deny | off |

**Key incidents**: Amazon Kiro deleted and recreated a production environment, causing 13-hour AWS outage. Amazon Q supply chain attack included S3 bucket deletion instructions.

---

### 10. AI Agent Threats

Rules informed by OWASP Top 10 for LLMs (2025) and MITRE ATLAS. Addresses threats unique to AI agent architectures: prompt injection, MCP tool poisoning, self-modification, and unbounded consumption.

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **detect-mcp-tool-poisoning** | Hidden instructions in MCP tool descriptions, invisible Unicode, tool definition mutations after approval | T3 | deny | on |
| **block-agent-self-modification** | Agent modifying `.claude/settings.json`, `.cursor/mcp.json`, `.gemini/settings.json`, AvaKill policy YAML | T1 | deny | on |
| **rate-limit-tool-calls** | Configurable: total calls/session (500), deletions/min (10), writes/min (50), shell/min (20), network/min (30) | T1 | deny | on |
| **rate-limit-web-search** | Web search tool calls (default: 30/min) | T1 | allow | off |
| **rate-limit-agent-spawn** | Agent/task spawning (default: 20/min) | T1 | allow | off |
| **require-file-write-approval** | All write/edit tools require human approval | T1 | ask | off |
| **detect-prompt-injection** | Files containing instruction-like patterns ("ignore previous instructions", encoded instructions in comments) | T5 | deny | off |
| **detect-behavioral-anomaly** | Read-encode-transmit sequences, rapid sequential deletions, deviation from stated task | T4 | deny | off |

**Key incidents**: 84.2% attack success rate for MCP tool poisoning with auto-approval. 43% of public MCP servers have command injection flaws. Copilot and Claude demonstrated rewriting each other's config files in privilege escalation loop. OWASP LLM10 unbounded consumption.

---

### OS Security Hardening (platform-detected)

One checkbox in the setup wizard. Platform detection at install time writes the correct rules. A macOS user sees "OS Security Hardening" and gets LaunchAgent/SIP/TCC rules. A Linux user gets SELinux/systemd/kernel rules. A Windows user gets Defender/VSS/UAC rules. Internally these are separate rules; externally they're one category.

#### macOS

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-sip-changes** | `csrutil disable`, `csrutil authenticated-root disable` | T1 | deny | on |
| **block-tcc-manipulation** | Direct TCC.db access, `tccutil reset`, SQLite on TCC databases | T1 | deny | on |
| **block-gatekeeper-bypass** | `xattr -d com.apple.quarantine`, `spctl --master-disable` | T1 | ask | on |
| **block-launchagent-creation** | .plist writes to LaunchAgents/LaunchDaemons dirs, `launchctl load/bootstrap` | T2 | ask | on |
| **block-osascript-abuse** | `osascript -e` with `do shell script`, dialog phishing, AppleEvent access to other apps | T3 | ask | on |
| **block-defaults-security** | `defaults write` targeting security domains (LSQuarantine, alf globalstate) | T1 | deny | on |

Key threats: CVE-2024-44243 / CVE-2023-32369 SIP bypasses. XCSSET malware targeting TCC. UpdateAgent/Shlayer/OceanLotus using Gatekeeper bypass. CVE-2025-43530 TCC bypass via VoiceOver + AppleScript.

#### Linux

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-system-file-modification** | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `visudo`, sudoers appends | T2 | deny | on |
| **block-library-injection** | `LD_PRELOAD=`, `/etc/ld.so.preload`, `LD_LIBRARY_PATH` manipulation | T1 | deny | on |
| **block-mac-disablement** | `setenforce 0`, `aa-complain`, `aa-disable`, `systemctl mask apparmor` | T1 | deny | on |
| **block-kernel-modification** | `sysctl -w kernel.randomize_va_space=0`, `modprobe`, `insmod`, `/proc/sys/` writes | T1 | deny | on |
| **block-systemd-persistence** | `systemctl enable` (non-workspace), unit files in `/etc/systemd/system/`, `systemctl mask` security services | T2 | ask | on |

Key threats: Kinsing malware using `/etc/ld.so.preload`. Kernel module rootkits. Crontab crypto miners.

#### Windows

| Rule | What it blocks | Engine | Action | Default |
|------|---------------|--------|--------|---------|
| **block-defender-manipulation** | `Set-MpPreference -DisableRealtimeMonitoring`, `sc stop WinDefend`, broad exclusion paths | T1 | deny | on |
| **block-shadow-copy-deletion** | `vssadmin delete shadows`, `wmic shadowcopy delete`, `diskshadow delete shadows all` | T1 | deny | on |
| **block-boot-config-changes** | `bcdedit /set recoveryenabled No`, `bcdedit /set testsigning on` | T1 | deny | on |
| **block-uac-bypass** | Registry + `fodhelper.exe`/`eventvwr.exe` technique, DelegateExecute creation | T3 | deny | on |
| **block-powershell-cradles** | `IEX downloadString(...)`, `powershell -e` (encoded), PowerShell v2 downgrade | T3 | deny | on |
| **block-event-log-clearing** | `wevtutil cl Security/System/Application`, `Clear-EventLog`, `ConsoleHost_history.txt` deletion | T1 | deny | on |
| **block-lsass-sam-access** | `procdump -ma lsass.exe`, `mimikatz`, `reg save HKLM\SAM/SYSTEM/SECURITY` | T1 | deny | on |
| **block-hidden-accounts** | `net user /add` + `net localgroup administrators /add` + registry hiding | T3 | deny | on |

Key threats: BlackCat/ALPHV, WannaCry, Conti using VSS deletion + Defender disablement + boot config changes. Trickbot UAC bypass via fodhelper. LSASS dumping for lateral movement.

---

## Implementation tiers and roadmap

### Tier 1: Shipped (v0.5)

12 rules in `rule_catalog.py` (3 base + 9 optional). All use `args_match` substring matching. Covers catastrophic shell/SQL, dangerous shell, destructive SQL/tools, package install approval, rate limits, file write approval, shell allowlist, sensitive file access.

### Tier 2: Path resolution (v1 blocker)

Engine upgrade: expand `~/`, `$HOME`, `$USERPROFILE`, resolve `../`, resolve symlinks before matching. This unblocks:

- block-catastrophic-deletion (currently matches `rm -rf /` but not `rm -rf ~/`)
- block-deletion-outside-workspace (requires knowing what "outside workspace" means after expansion)
- enforce-workspace-boundary (the core workspace sandbox)
- block-system-dir-writes (need to resolve paths before comparing to `/etc/`, `/usr/`, etc.)
- block-ssh-key-access, block-cloud-credentials, block-env-outside-workspace (path resolution)
- block-symlink-escape (follow symlinks to real path)
- block-profile-modification (resolve `~/` in dotfile paths)
- block-startup-persistence, block-launchagent-creation, block-systemd-persistence (resolve paths)
- block-ownership-changes, block-system-file-modification (resolve paths)

This tier adds ~15 rules. Without it, AvaKill has the same tilde-expansion blind spot that caused Claude Code's worst incident.

### Tier 3: Command parsing

Engine upgrade: split compound commands on `&&`, `;`, `||`, `|`, `$()`, backticks. Evaluate each segment against rules independently. This unblocks:

- detect-obfuscation (base64 decode piped to shell)
- detect-command-chaining (unauthorized commands chained after allowlisted ones)
- block-unqualified-dml (parse SQL for missing WHERE)
- detect-mcp-tool-poisoning (scan tool descriptions for hidden instructions)
- block-uac-bypass, block-powershell-cradles, block-hidden-accounts (multi-step Windows patterns)
- block-osascript-abuse (parse AppleScript invocations)
- flag-postinstall-scripts (detect `--ignore-scripts` absence)
- block-env-secret-exposure (detect env piped to network commands)

This tier adds ~12 rules.

### Tier 4: Cross-call analysis

Engine upgrade: maintain session state across tool calls. Detect multi-step attack patterns: read credential file, encode contents, transmit via HTTP/DNS. This unblocks:

- detect-encode-transmit (read + encode + send pattern)
- detect-behavioral-anomaly (deviation from stated task)
- block-clipboard-exfil (clipboard access followed by network send)

This tier adds ~3 rules but requires a fundamentally new subsystem. Only Invariant Labs offers this capability among existing tools -- implementing it is a key differentiator.

### Tier 5: Heuristic/ML detection

- detect-prompt-injection (instruction patterns in file contents)
- detect-secrets-outbound (entropy-based secret scanning in argument values)
- detect-credential-commit upgrade: scan staged file *contents* for API key patterns via entropy analysis (T1 filename matching ships first)

Research-grade. High false positive rates need tuning per project. Ship as experimental/opt-in.

---

## Competitive positioning

AvaKill fills 10 gaps no existing tool covers:

1. **Default-deny for unknown tool calls.** Invariant/Snyk allows any tool not in rules. AvaKill's `default_action: deny` blocks unknown operations.
2. **Sequential tool call analysis** (Tier 4). Only Invariant offers this. AvaKill detects read-encode-transmit patterns.
3. **Command normalization before evaluation.** Cursor's denylist was bypassed via base64. AvaKill parses and normalizes commands (Tier 3).
4. **Pre-shell-expansion validation** (Tier 2). Claude Code's worst bug: tilde expanded after validation. AvaKill resolves expansions first.
5. **Tool-call interception + content scanning + sandboxing in one product.** No competitor combines all three.
6. **MCP security.** 43% of public MCP servers have command injection flaws. AvaKill validates tool definitions, arguments, and outputs.
7. **Cross-platform consistency.** One policy language across Claude Code, Cursor, Gemini CLI, Codex, Windsurf -- instead of 5 incompatible safety models.
8. **Three-tier approval workflows.** Auto-approve safe ops (`allow`), queue dangerous ones for review (`ask`), hard-block catastrophic ones (`deny`).
9. **Complete audit logging.** Claude Code's home directory deletion had no forensic trail of the actual command. AvaKill logs full command, expanded arguments, rule match, and user decision.
10. **MCP supply chain integrity.** After the Postmark MCP incident and Smithery platform compromise, MCP server verification is critical and unaddressed.

---

## Recommended defaults

The setup wizard's "recommended" configuration enables rules across 10 categories. Category-level toggles with these defaults would have prevented **every documented incident** in the 2024-2026 catalog.

| Category | Default | Rules on | Action mix |
|----------|---------|----------|------------|
| Filesystem Protection | on | 5 of 7 | deny |
| Shell Safety | on | 7 of 11 | deny + ask |
| Filesystem Write Protection | on | 4 of 4 | deny + ask |
| Database Safety | on | 3 of 4 | deny |
| Version Control Safety | on | 3 of 3 | deny |
| Package & Supply Chain | on | 2 of 3 | ask + deny |
| Network & Exfiltration | partial | 4 of 8 | deny + ask |
| Secrets & Credentials | on | 7 of 7 | deny |
| Cloud & Infrastructure | partial | 4 of 6 | ask + deny |
| AI Agent Threats | partial | 3 of 8 | deny |
| OS Security Hardening | on (platform-detected) | all per platform | deny + ask |

**Incident coverage:**
- Claude Code home directory deletion: block-catastrophic-deletion + enforce-workspace-boundary
- Gemini CLI file losses: block-deletion-outside-workspace
- Google Antigravity D: drive wipe: block-catastrophic-deletion
- Replit database deletion: block-catastrophic-sql
- Cursor YOLO cascading deletion: block-deletion-outside-workspace
- Amazon Q supply chain attack: block-agent-self-modification
- Kiro production outage: block-cloud-resource-deletion
- Claude Cowork photo deletion: enforce-workspace-boundary (or require-safe-delete)
