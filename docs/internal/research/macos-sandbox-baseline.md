# Building an OS-level sandbox for AI coding agents on macOS

**The macOS `sandbox-exec` tool, though deprecated since 2017, remains the only kernel-level sandboxing CLI on macOS and is actively used by OpenAI Codex CLI, Nix, Homebrew, and Chromium.** Building a deny-default SBPL profile for AI coding agents requires solving five specific challenges: enumerating hundreds of filesystem paths that Node.js/Python need at startup, accommodating each agent's unique auth and config requirements, debugging denials through the Unified Logging system (the only reliable method on macOS 14+), allowing the precise set of Mach services needed for TLS and terminal interaction, and balancing security against usability. This report synthesizes findings from production sandbox profiles (OpenAI Codex, Nix, Homebrew, Chromium, ai-jail) into a complete, annotated baseline profile.

---

## 1. Every path Node.js and Python touch on macOS

A deny-default sandbox must explicitly allow every file a runtime reads at startup. Node.js and Python both pull in system libraries, ICU data, DNS configuration, and user-specific caches before executing a single line of application code.

### System paths required by all processes

Every process on macOS needs the dynamic linker and core system libraries. The **dyld shared cache** moved to `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` on macOS Ventura and later — missing this path is the single most common cause of "killed: 9" errors in new sandbox profiles. Required read-only paths include:

- `/usr/lib/` and `/usr/lib/system/` — core system shared libraries including `libSystem.B.dylib`
- `/System/Library/Frameworks/` and `/System/Library/PrivateFrameworks/` — system frameworks
- `/System/Volumes/Preboot/Cryptexes/OS/` — dyld shared cache (macOS 13+)
- `/usr/share/` — ICU data, timezone data, locale data
- `/private/etc/` (symlinked from `/etc/`) — `resolv.conf`, `hosts`, `localtime`
- `/dev/null`, `/dev/urandom`, `/dev/random` — standard devices

For write access, the critical path is **`$TMPDIR`**, which macOS sets to a per-user directory at `/private/var/folders/XX/XXXXXXXXX/T/`. Nearly every tool — npm, pip, uv, Python's `tempfile` module — writes here. The sandbox must allow `file-write*` to the entire `/private/var/folders/` subtree (or at least the user's specific subdirectory), plus `/tmp/` and `/private/tmp/`.

On Apple Silicon, Rosetta 2 translation requires read access to `/Library/Apple/usr/lib/`, `/Library/Apple/usr/libexec/oah/`, and write access to `/var/db/oah/` for the AOT cache.

### Node.js runtime and npm/npx paths

Node.js binaries live at `/opt/homebrew/bin/node` (Apple Silicon Homebrew), `/usr/local/bin/node` (Intel Homebrew), or within version manager directories. At startup, Node reads its own binary for embedded ICU data, loads shared libraries from the Homebrew prefix, and checks several user configuration files:

| Path | Access | Purpose |
|------|--------|---------|
| `/opt/homebrew/` (or `/usr/local/`) subtree | Read | Homebrew-installed binaries, libraries, frameworks |
| `~/.node_repl_history` | Read+Write | REPL history |
| `~/.npmrc` | Read | npm user configuration |
| `~/.npm/` | Read+Write | npm cache, `_cacache/`, `_logs/`, `_npx/` |
| `~/.config/configstore/` | Read+Write | npm update-notifier state |
| `$TMPDIR` | Read+Write | npm temp operations, build artifacts |

For **version managers**, each has its own directory tree: **nvm** stores everything under `~/.nvm/` (including per-version `bin/`, `lib/node_modules/`); **fnm** uses `~/Library/Application Support/fnm/` with multishell temps at `~/Library/Caches/fnm_multishells/`; **Volta** uses `~/.volta/` with shims in `~/.volta/bin/`. All require both read and execute access to their version-specific `bin/` directories.

### Python, pip, and uv paths

Python's paths are more fragmented across installation methods. Homebrew Python lives under `/opt/homebrew/opt/python@3.Y/`, the official installer under `/Library/Frameworks/Python.framework/`, and Xcode CLT Python under `/Library/Developer/CommandLineTools/`. Each needs its stdlib directory, `lib-dynload/`, and site-packages.

**pip** caches wheels at `~/Library/Caches/pip/` on macOS (not `~/.cache/pip/` as on Linux). **uv**, the fast Python package manager, stores its cache at `~/.cache/uv/` and managed Python installations at `~/.local/share/uv/python/`. Both need write access to `$TMPDIR` for build isolation. **pyenv** mirrors nvm's approach with `~/.pyenv/versions/` and `~/.pyenv/shims/`.

A critical detail: **`__pycache__/` directories** need write access wherever Python code runs — project directories, site-packages, even within version manager installations. Without this, Python falls back to interpreting `.py` files without caching, causing significant slowdowns.

---

## 2. What each AI coding agent needs beyond its config directory

Each agent has distinct filesystem, Keychain, network, and authentication requirements. The table below captures the critical differences:

| Agent | Config directory | macOS Keychain | Localhost ports | Primary auth |
|-------|-----------------|----------------|-----------------|--------------|
| Claude Code | `~/.claude/` + `~/.config/claude/` | **Yes** (primary) | MCP OAuth (~45123) | Browser OAuth / `ANTHROPIC_API_KEY` |
| Gemini CLI | `~/.gemini/` | No (file-based) | Random port for Google OAuth | Browser OAuth / `GEMINI_API_KEY` |
| Cursor | `~/Library/Application Support/Cursor/` + `~/.cursor/` | **Yes** (Electron keytar) | Likely for auth | Browser login (GitHub/Google) |
| Windsurf | `~/Library/Application Support/Windsurf/` + `~/.codeium/` | **Yes** (Electron keytar) | Likely for auth | Browser login + BYOK |
| Codex CLI | `~/.codex/` | No (file-based) | ChatGPT OAuth callback | Browser OAuth / `OPENAI_API_KEY` |

### Claude Code's expanding footprint

Claude Code recently migrated from `~/.claude/` to `~/.config/claude/` (v1.0.30+), but both locations may be active for backward compatibility. It also writes `~/.claude.json` at the home root for MCP server configuration — a path easily missed. Within the config directory, it maintains `projects/` subdirectories named after project paths (e.g., `projects/-Users-sean-myproject/`), debug history, file edit snapshots, and session environment variables.

Claude Code **stores OAuth tokens in the macOS Keychain** under the service name `"Claude Code"`. When Keychain is unavailable (e.g., over SSH), it falls back to `~/.claude/.credentials.json` with `chmod 600`. This means a sandbox that blocks Keychain access via Mach services needs to ensure the fallback file path is writable.

### Gemini CLI's OAuth and sandbox awareness

Gemini CLI is notable for being **sandbox-aware on macOS** — it supports custom `.sb` profiles in the project's `.gemini/sandbox-macos-<profile>.sb` directory. Its OAuth flow opens a browser and listens on a **randomly chosen localhost port** for the Google OAuth callback, making it impossible to restrict to a specific port number. The `~/.gemini/` directory contains `oauth_creds.json`, `trustedFolders.json`, per-project shell history, and MCP OAuth tokens. When using Vertex AI, it also needs `~/.config/gcloud/application_default_credentials.json`.

### OpenAI Codex CLI already uses sandbox-exec

**Codex CLI is the only agent that ships with its own macOS sandbox implementation.** Its Rust backend (`codex-rs/core/src/seatbelt.rs`) generates SBPL profiles at runtime and invokes `/usr/bin/sandbox-exec`. The profile uses a **deny-default base with global file-read and scoped file-write** approach. In `workspace-write` mode, it allows writes only to the project directory, `/tmp`, `$TMPDIR`, and user-configured extra writable roots — while keeping `.git/` and `.codex/` read-only even within writable directories. Network is blocked by default via a separate `seatbelt_network_policy.sbpl` that unconditionally sets `CODEX_SANDBOX_NETWORK_DISABLED=1`. A known bug as of early 2026: `network_access = true` in `config.toml` is silently ignored by the seatbelt profile on macOS.

---

## 3. Getting sandbox denial logs on macOS 14 and 15

The SBPL `(trace)` directive and `(debug deny)` stopped producing output around **macOS 10.13 High Sierra**. The `sandbox-exec -t /path/trace.out` flag is undocumented and unreliable on macOS 14+. The replacement is the **Unified Logging system**, which captures sandbox denials as kernel messages.

### The one command that actually works

The following `log stream` predicate, documented by Chromium's sandbox debugging guide and confirmed by multiple community sources, reliably captures sandbox denials on macOS 14 Sonoma and macOS 15 Sequoia:

```bash
log stream --style compact --info --debug --predicate \
  '((processID == 0) AND (senderImagePath CONTAINS "/Sandbox")) OR
   (subsystem == "com.apple.sandbox.reporting")' \
  | tee /tmp/sandbox-denials.txt
```

The `processID == 0` filter catches **kernel-originated messages** (the Sandbox kernel extension logs via PID 0). The `com.apple.sandbox.reporting` subsystem catches sandboxd violation reports that may include backtraces. Denial messages follow this format:

```
kernel: (Sandbox) Sandbox: mycommand(12345) deny(1) file-read-data /some/path
```

For historical searches, replace `log stream` with `log show --start '2026-03-07 00:00:00'`. A simpler but noisier predicate that also works:

```bash
log stream --style compact --predicate 'sender=="Sandbox"'
```

### SBPL modifiers that control reporting

Default `deny` actions automatically generate violation reports. Two modifiers alter this behavior:

- **`(deny file-write* (with no-report))`** — suppresses logging for that specific rule (Apple uses this in their own profiles to reduce noise for known-benign denials like quarantine xattr writes)
- **`(allow file-read* (with report))`** — forces a log entry even for allowed operations, useful for auditing what a process actually accesses
- **`(deny file-write* (with send-signal SIGSTOP))`** — pauses the process on violation so you can attach `lldb` and inspect the call stack

### The automated trace replacement

The `trace.sh` script by n8henrie replicates the old `(trace)` workflow: it runs a process under `(deny default)`, reads denials from the kernel log via `log show`, parses the denied operations into corresponding `(allow)` rules, and iterates until the process succeeds. This is the most practical approach for building profiles from scratch.

### What doesn't work

**DTrace** requires SIP to be partially disabled (`csrutil enable --without dtrace` from Recovery), doesn't work on Apple Silicon after sleep/wake cycles, and has no sandbox-specific provider probes. **Endpoint Security Framework** monitors file/process events but operates at a different layer and cannot capture sandbox policy decisions. **sysctl knobs** like `security.mac.sandbox.debug_mode` only exist on Apple Internal builds and are unavailable on production macOS. **`fs_usage`** can show failed file operations but doesn't label them as sandbox denials.

---

## 4. The Mach services and operations interactive CLI tools need

Building SBPL profiles for interactive tools is harder than for batch processes because terminal interaction, TLS certificate validation, and Keychain access all require specific Mach service lookups that are nowhere documented by Apple.

### The file-ioctl discovery that unblocked everything

The single most impactful finding from production sandbox deployments: **`(allow file-ioctl)` is required for interactive terminal tools**. Without it, Node.js and Bun crash with `setRawMode failed with errno: 1` because `tcsetattr()` — used to switch the terminal to raw mode for interactive prompts — is implemented via `ioctl()` on the TTY file descriptor. This was the critical fix in ai-jail v0.2.0 and is present in all working production profiles.

### Essential Mach services by category

**For any process** (directory lookups, logging):
- `com.apple.system.opendirectoryd.libinfo` — `getpwuid()`, user/group resolution
- `com.apple.system.logger` — syslog/ASL interface
- `com.apple.system.notification_center` — Darwin notification center

**For TLS/HTTPS connections** (critical for API calls to Anthropic, OpenAI, Google):
- `com.apple.trustd` and `com.apple.trustd.agent` — certificate trust evaluation. **If blocked, all TLS handshakes fail** with `OSStatus -26276`. This is non-negotiable for any agent that calls an API.
- `com.apple.SecurityServer` / `com.apple.securityd` — Security framework; required for Keychain operations
- `com.apple.ocspd` — OCSP certificate revocation checking

**For preferences** (CoreFoundation reads during framework initialization):
- `com.apple.cfprefsd.daemon` and `com.apple.cfprefsd.agent` — without these, `CFPreferences` and `NSUserDefaults` return nil

A known edge case: **Go binaries on macOS always use Security.framework for TLS**, even when built with `CGO_ENABLED=0`. The binary calls `SecTrustEvaluateWithError()` through `//go:cgo_import_dynamic`. This means tools like `gh` (GitHub CLI) fail inside sandboxes even after adding trustd access, because Go's TLS path requires additional Mach services. The workaround is embedding Mozilla CA roots via `golang.org/x/crypto/x509roots/fallback`.

### PTY, process, and system operations

Interactive CLI tools need this complete set of non-file operations:

```
process-exec, process-fork          — execute and fork child processes
process-info* (target same-sandbox) — os.cpus(), process metadata
signal (target same-sandbox)        — signal handling
sysctl-read                         — hw.ncpu, kern.osversion, hw.memsize
mach-host*                          — host_processor_info() for os.cpus()
pseudo-tty                          — PTY allocation
file-ioctl                          — tcsetattr() for terminal raw mode
iokit-open                          — hardware queries
ipc-posix-shm-read-data/write-data  — POSIX shared memory
ipc-posix-sem                       — semaphores (Python multiprocessing)
```

The `mach-host*` rule was discovered through OpenAI Codex issue #11210: without it, `os.cpus()` returns an empty array, causing npm and yarn to serialize all work to a single thread.

---

## 5. How production tools build their sandbox profiles

Five major open-source projects use `sandbox-exec` with SBPL on macOS. Their approaches fall into two camps: **deny-default with broad reads** (Codex, ai-jail) and **deny-default with enumerated reads** (Nix, Chromium). Bazel is the outlier with allow-default.

### OpenAI Codex CLI: deny-default, global reads, scoped writes

Codex's Rust implementation generates profiles at runtime. The base policy (`seatbelt_base_policy.sbpl`) starts with `(deny default)` then immediately grants `(allow file-read*)` globally — reading is considered safe. Write access is scoped: writable roots are passed as sandbox parameters (`-DWRITABLE_ROOT_0=/path`) and assembled into `(allow file-write* (subpath (param "WRITABLE_ROOT_0")))` rules. Sensitive paths are explicitly denied even from reads: `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/Library/Keychains`, `~/Library/Mail`, `~/Library/Messages`, `~/Library/Safari`, `~/Library/Cookies`.

Codex recently (PR #11387, Feb 2026) added configurable read access restrictions, enabling `ReadOnlyAccess::Restricted` which emits scoped `(allow file-read*)` rules instead of global reads. PR #11639 added a structured extension layer for macOS-specific permissions (preferences, automation, accessibility, calendar).

### Nix: deny-default with per-path enumeration

Nix takes the strictest approach: it enumerates **every single `/nix/store/` path** that a derivation depends on as individual `(subpath "/nix/store/<hash>-...")` rules. This can generate thousands of entries for complex builds, which once triggered a macOS sandbox compiler assertion failure (`INSTR_JUMP_NE_MAX_LENGTH` exceeded, fixed by splitting large expressions in PR #12570). Nix's default sandbox paths include `/System/Library/Frameworks`, `/System/Library/PrivateFrameworks`, `/bin/sh`, `/bin/bash`, `/private/tmp`, `/private/var/tmp`, and `/usr/lib`. Network is denied by default.

A notable Nix finding: on macOS 10.15+, `/bin/sh` became a shim that executes `/bin/bash`, requiring both paths in the sandbox. Without `/bin/bash`, you get `Failed to exec /bin/bash as variant for /bin/sh (1: Operation not permitted)`.

### Homebrew: deny-default, Ruby-generated, PTY-based execution

Homebrew's `sandbox.rb` generates SBPL profiles dynamically in Ruby using a `SandboxRule` struct abstraction. It writes the profile to a temp file and invokes `sandbox-exec -f`. Key design choice: Homebrew runs sandboxed commands in a **pseudoterminal** (`PTY.open`) to prevent access to the parent terminal, matching window size for test sensitivity. Its generated profile allows writes to formula-specific paths (Cellar directory, logs, caches, temp dirs) plus device writes to `/dev/ptmx`, `/dev/null`, `/dev/random`, `/dev/zero`, `/dev/fd/[0-9]+`, and `/dev/ttys?[0-9]`. Homebrew reads denial logs via the syslog after execution, filtering by timestamp and "deny" keyword.

### Bazel: allow-default with selective denies

Bazel takes the **opposite** approach: `(allow default)` then `(deny network*)` and `(deny file-write*)` with explicit write exceptions. This is simpler but less secure — any operation not explicitly denied is permitted. Bazel allows localhost network access (`(allow network* (local ip "localhost:*"))`) and writes to the execroot, `/dev/`, temp directories, `~/Library/Logs`, and `~/Library/Developer`.

### Chromium: the gold standard for strictness

Chromium compiles profiles to binary bytecode via `Seatbelt::Compile` and applies sandboxing **before loading any frameworks** — even system ones. It explicitly enumerates every Mach service, sysctl, IOKit class, and file path needed. This is the most secure approach but requires the most maintenance. Chromium's sandbox debugging documentation provides the most reliable `log stream` predicate for capturing denials.

### Common patterns across all tools

Every production profile shares these elements: `process-fork` + `process-exec` for subprocess execution, `sysctl-read` for system info, write access to `/tmp` + `/private/var/folders/` for temp files, and parameterization of dynamic paths (home directory, project directory, temp directory) rather than hardcoding. All tools acknowledge `sandbox-exec` is deprecated but continue using it — as Bazel's maintainer noted, "the sandboxing subsystem will have to remain for Apple's own use."

---

## 6. A complete "agent-safe" deny-default SBPL baseline

The following profile synthesizes findings from every source above into a working baseline for any AI coding agent on macOS 14+. It uses parameters (passed via `sandbox-exec -D KEY=VALUE`) for dynamic paths.

```scheme
(version 1)
(deny default)

; ═══════════════════════════════════════════════════════
; PROCESS OPERATIONS
; Required for executing commands, forking child processes,
; querying CPU count, and handling signals.
; ═══════════════════════════════════════════════════════
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))

; hw.ncpu, hw.activecpu, kern.osversion, hw.memsize, etc.
; Without sysctl-read, many tools cannot detect CPU count.
(allow sysctl-read)

; host_processor_info() — needed by Node.js os.cpus().
; Without this, npm/yarn serialize to 1 worker thread.
(allow mach-host*)

; ═══════════════════════════════════════════════════════
; MACH IPC — SERVICE LOOKUPS
; Each service is required for specific functionality.
; ═══════════════════════════════════════════════════════
(allow mach-lookup
  ; User/group identity resolution (getpwuid, etc.)
  (global-name "com.apple.system.opendirectoryd.libinfo")
  ; System logging
  (global-name "com.apple.system.logger")
  ; Darwin notification center (framework initialization)
  (global-name "com.apple.system.notification_center")
  ; CoreFoundation preferences — needed by most frameworks
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.cfprefsd.agent")
  ; TLS certificate trust evaluation — REQUIRED for HTTPS
  ; Without trustd, all API calls to Anthropic/OpenAI/Google fail
  (global-name "com.apple.trustd")
  (global-name "com.apple.trustd.agent")
  ; OCSP certificate revocation checking
  (global-name "com.apple.ocspd")
  ; Security framework / Keychain (needed by Claude Code, Cursor, Windsurf)
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd")
  ; LaunchServices — needed for `open` command, file type resolution
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.lsd.mapdb")
  ; Distributed notifications (cross-process coordination)
  (global-name-regex #"^com\.apple\.distributed_notifications")
)
(allow mach-register)

; ═══════════════════════════════════════════════════════
; IPC — SHARED MEMORY AND SEMAPHORES
; POSIX shared memory for Node.js worker threads;
; semaphores for Python multiprocessing.SemLock.
; ═══════════════════════════════════════════════════════
(allow ipc-posix-shm-read-data)
(allow ipc-posix-shm-write-data)
(allow ipc-posix-shm-write-create)
(allow ipc-posix-sem)

; ═══════════════════════════════════════════════════════
; TERMINAL / PTY
; file-ioctl is CRITICAL — without it, Node.js/Bun crash
; with "setRawMode failed with errno: 1"
; ═══════════════════════════════════════════════════════
(allow pseudo-tty)
(allow file-ioctl)

(allow file-read* file-write*
  (literal "/dev/ptmx")
  (regex #"/dev/ttys[0-9]+")
  (literal "/dev/tty")
  (literal "/dev/null")
  (literal "/dev/zero"))

(allow file-read*
  (literal "/dev/random")
  (literal "/dev/urandom")
  (subpath "/dev/fd"))

; ═══════════════════════════════════════════════════════
; IOKIT — HARDWARE QUERIES
; Node.js and Python query hardware info at startup.
; ═══════════════════════════════════════════════════════
(allow iokit-open)

; ═══════════════════════════════════════════════════════
; FILE READS — SYSTEM PATHS
; Global file-read is the simplest approach (used by Codex).
; Alternative: enumerate specific paths (more secure, more fragile).
; ═══════════════════════════════════════════════════════
(allow file-read*
  ; Dynamic linker and system libraries
  (subpath "/usr/lib")
  (subpath "/usr/share")
  (subpath "/System")
  (subpath "/private/var/db/dyld")
  ; System config: DNS, hosts, timezone
  (subpath "/private/etc")
  ; Preferences and managed preferences
  (subpath "/Library/Preferences")
  (subpath "/Library/Managed Preferences")
  ; Security: root certificates and keychains
  (subpath "/System/Library/Keychains")
  (subpath "/Library/Keychains")
  (subpath "/private/var/db/mds")
  ; Rosetta 2 (Apple Silicon running x86 binaries)
  (subpath "/Library/Apple")
  ; Homebrew — Apple Silicon
  (subpath "/opt/homebrew")
  ; Homebrew — Intel
  (subpath "/usr/local")
  ; python.org framework Python
  (subpath "/Library/Frameworks/Python.framework")
  ; Xcode CLT (includes Python, Git, etc.)
  (subpath "/Library/Developer/CommandLineTools")
  ; Java (for JDK-based tools in Codex)
  (subpath "/Library/Java/JavaVirtualMachines")
  ; Shells — macOS 10.15+ needs both sh and bash
  (literal "/bin/sh")
  (literal "/bin/bash")
  (literal "/bin/zsh")
  (subpath "/bin")
  (subpath "/usr/bin")
  (subpath "/usr/sbin")
  (subpath "/sbin")
  ; Temp directories (read access)
  (subpath "/tmp")
  (subpath "/private/tmp")
  (subpath "/private/var/folders")
  (subpath "/private/var/tmp")
)

; User-specific read paths (parameterized)
(allow file-read*
  (subpath (param "HOME"))
)

; ═══════════════════════════════════════════════════════
; SENSITIVE PATH DENIALS — Override the broad HOME read
; These deny rules take precedence over the allow above.
; ═══════════════════════════════════════════════════════
(deny file-read*
  (subpath (param "DENY_SSH"))         ; ~/.ssh
  (subpath (param "DENY_GNUPG"))       ; ~/.gnupg
  (subpath (param "DENY_AWS"))         ; ~/.aws
  (subpath (param "DENY_KUBE"))        ; ~/.kube
  (subpath (param "DENY_KEYCHAINS"))   ; ~/Library/Keychains
  (subpath (param "DENY_MAIL"))        ; ~/Library/Mail
  (subpath (param "DENY_MESSAGES"))    ; ~/Library/Messages
  (subpath (param "DENY_SAFARI"))      ; ~/Library/Safari
  (subpath (param "DENY_COOKIES"))     ; ~/Library/Cookies
)

; ═══════════════════════════════════════════════════════
; FILE WRITES — SCOPED TO SPECIFIC PATHS
; This is where security lives: writes are tightly scoped.
; ═══════════════════════════════════════════════════════
(allow file-write*
  ; Temp directories (CRITICAL — npm, pip, uv all write here)
  (subpath "/tmp")
  (subpath "/private/tmp")
  (subpath "/private/var/tmp")
  (subpath "/private/var/folders")
  ; Project working directory
  (subpath (param "PROJECT_DIR"))
  ; Agent config directories — include whichever agent is in use
  (subpath (param "AGENT_CONFIG_DIR"))
)

; ═══════════════════════════════════════════════════════
; NETWORK — CONFIGURABLE
; Default: allow outbound HTTPS + localhost for OAuth.
; For full lockdown: remove these rules entirely.
; ═══════════════════════════════════════════════════════
(allow network-outbound
  (remote tcp "*:443")               ; HTTPS to API endpoints
  (remote tcp "*:80")                ; HTTP (some OAuth redirects)
  (remote udp "*:53")                ; DNS resolution
  (remote tcp "localhost:*"))        ; Localhost connections

; OAuth callback listener (Gemini CLI, Codex, Claude MCP)
(allow network-bind (local tcp "localhost:*"))
(allow network-inbound (local tcp "localhost:*"))
(allow system-socket)

; ═══════════════════════════════════════════════════════
; USER PREFERENCES (modern macOS)
; ═══════════════════════════════════════════════════════
(allow user-preference-read
  (preference-domain "kCFPreferencesAnyApplication")
  (preference-domain "com.apple.security"))
```

### How to invoke this profile

```bash
sandbox-exec -f agent-sandbox.sb \
  -D HOME="$HOME" \
  -D PROJECT_DIR="$(pwd)" \
  -D AGENT_CONFIG_DIR="$HOME/.claude" \
  -D DENY_SSH="$HOME/.ssh" \
  -D DENY_GNUPG="$HOME/.gnupg" \
  -D DENY_AWS="$HOME/.aws" \
  -D DENY_KUBE="$HOME/.kube" \
  -D DENY_KEYCHAINS="$HOME/Library/Keychains" \
  -D DENY_MAIL="$HOME/Library/Mail" \
  -D DENY_MESSAGES="$HOME/Library/Messages" \
  -D DENY_SAFARI="$HOME/Library/Safari" \
  -D DENY_COOKIES="$HOME/Library/Cookies" \
  -- claude
```

For multiple writable roots (e.g., agent config + npm cache + version manager), either expand the `AGENT_CONFIG_DIR` parameter to accept multiple paths or add additional `(allow file-write* (subpath (param "WRITABLE_ROOT_N")))` rules with corresponding `-D` parameters, following Codex's pattern.

### Debugging the profile iteratively

Run the log monitor in a separate terminal before launching the sandboxed process:

```bash
log stream --style compact --info --debug --predicate \
  '((processID == 0) AND (senderImagePath CONTAINS "/Sandbox"))
   OR (subsystem == "com.apple.sandbox.reporting")' \
  | tee /tmp/sandbox-denials.txt
```

Each denial line tells you the exact operation and path to add. For crash-on-violation debugging, replace specific deny rules with `(deny file-write* (with send-signal SIGSTOP))` and attach `lldb -p <pid>` to inspect the call stack.

---

## Conclusion

Three insights emerged from this research that aren't obvious from Apple's sparse documentation. First, **`file-ioctl` is the silent killer** — every production profile for interactive tools had to discover this the hard way through `setRawMode` crashes. Second, **TLS requires a Mach service chain, not just file paths** — `trustd`, `trustd.agent`, `SecurityServer`, and the Keychains directory must all be accessible, and Go binaries need an additional workaround with embedded CA roots. Third, **the most practical profile architecture is deny-default with broad reads and scoped writes** (the Codex/ai-jail pattern), because enumerating every readable path (the Nix approach) is brittle across macOS versions and tool installations, while allowing all writes (Bazel) defeats the purpose.

The profile above should work for Claude Code, Gemini CLI, Codex CLI, and any Node.js/Python-based agent with appropriate `AGENT_CONFIG_DIR` and `PROJECT_DIR` parameters. For Cursor and Windsurf (Electron-based IDEs), additional writes to `~/Library/Application Support/<agent>/` and `~/Library/Caches/<agent>/` are needed. The `sandbox-exec` tool may be deprecated, but as of macOS 15 Sequoia it remains functional and is actively used by Apple's own blastdoor, Xcode, and Swift Package Manager sandboxing — there is no migration pressure.