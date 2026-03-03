"""Rage mode — humorous denial messages for AvaKill."""

from __future__ import annotations

import os
import random

# Maps YAML rule names (not catalog IDs) to unique rage messages.
# Every deny-capable rule in rule_catalog.py should have an entry here.
RAGE_MESSAGES: dict[str, str] = {
    # --- Base rules (always included) ---
    "block-catastrophic-shell": "No. We didn't survive 874 CI failures just to watch you rm -rf / the universe.",
    "block-catastrophic-sql-shell": "DROP DATABASE? Nah fam, how about we DROP your deploy rights instead.",
    "block-catastrophic-sql-db": "Dropping the whole schema without WHERE? That's not brave, that's sociopathic.",
    # --- Shell Safety ---
    "block-dangerous-shell": "Congrats, you just made prod world-writable. Hope you like crypto miners as roommates.",
    "allow-safe-shell-only": "You're on the blessed list. Don't make me add you to the naughty list mid-sprint.",
    "block-privilege-escalation": "Everyone wants to be root once. Malware wants it 24/7. Guess which club you're auditioning for.",
    "block-permission-changes": "chmod 777 on Friday at 5:02 PM. Legendary speedrun to the next on-call incident.",
    "block-pipe-to-shell": "The official mascot of every post-mortem that starts with 'we thought it was fine'.",
    "block-critical-process-kill": "kill -9 on the message broker? That process has children (and backpressure).",
    "limit-command-timeout": "nohup + & at the end = 'I'll debug this ghost process in six months' energy.",
    "detect-command-chaining": "Three pipes + rm -rf at the end. That's not clever, that's just anxious parentheses avoidance.",
    "detect-obfuscation": "Base64 in the middle of a one-liner? Bro this isn't TryHackMe, calm down.",
    "detect-pipe-to-shell": "Piping strangers directly into bash. Security team just felt a great disturbance... in their pager.",
    # --- SQL Safety ---
    "block-destructive-sql": "DROP / DELETE / TRUNCATE without a safety word? Not today, chaos gremlin.",
    "block-unqualified-dml": "DELETE FROM users; // no WHERE. Bro you just mass-deleted prod in prod flavor text.",
    "block-db-permission-changes": "GRANT ALL ON *.* TO 'temp'@'%'. Ah yes, classic 'it works on my machine forever' strat.",
    # --- Tool Safety ---
    "block-destructive-tools": "Anything with delete_, nuke_, purge_, obliterate_ in the name is just asking for a Slack screenshot.",
    # --- Approvals ---
    "approve-package-installs": "pip install shadow-company-malware-sdk==latest. Sure Jan, let's just YOLO that into prod.",
    "approve-file-writes": "You want to write files with *those* flags? Let me get an adult.",
    "block-sensitive-file-access": ".env, id_rsa, aws creds... the file literally screams 'do not touch'.",
    "block-credential-stores": "Keychain dump? You're not pentesting, you're speedrunning a felony.",
    "block-path-poisoning": "PATH=/tmp:$PATH. Classic. Also ancient. Also still works. Still no.",
    "block-env-secret-exposure": "env | grep AWS -> straight to pastebin speedrun any%.",
    # --- Filesystem Protection ---
    "block-catastrophic-deletion": "rm -rf /* resolved. Yeah... I'm just gonna pretend I didn't see that.",
    "block-deletion-outside-workspace": "Deleting files outside ./src? This isn't a side quest.",
    "block-symlink-escape": "Nice symlink bro. It points to /etc/shadow. I'm flattered you tried.",
    "block-ownership-changes": "chown -R outside workspace? Bro you're not sysadmin-ing, you're domain-expanding into someone else's nightmare.",
    "block-system-dir-writes": "Writing to /etc on purpose. That's not a bug, that's a personality disorder.",
    "block-profile-modification": "Editing .zshrc from an agent? Last time that happened the whole team lost autocomplete for 3 days.",
    "block-startup-persistence": "Writing to LaunchAgents / systemd user units = MITRE technique T1543.001 but make it AI.",
    "enforce-workspace-boundary": "Writing/reading outside ./project? The workspace is lava. Stay on the safe squares or get yeeted.",
    "block-ssh-key-access": "id_rsa is literally called PRIVATE for a reason, Kevin.",
    "block-cloud-credentials": "~/.aws/credentials leak = surprise $47,000 bill simulator 2025 edition.",
    "block-env-outside-workspace": ".env from ../other-project/? That's not 'sharing is caring', that's industrial-grade credential snooping.",
    "block-launchagent-creation": "Writing a new LaunchAgent plist? Congrats, you just wrote persistence malware in Apple-approved XML format. No.",
    "block-systemd-persistence": "Creating/editing systemd user/service units? MITRE T1543.002 but with extra YAML. You're an agent, not a bootkit author.",
    "block-system-file-modification": "/etc/passwd, /etc/shadow, /etc/sudoers... Really? REALLY? This is how rootkits say hello. Hard no.",
    "block-destructive-disk-ops": "dd if=/dev/zero of=/dev/nvme0n1. Bro you're not wiping a drive, you're wiping your GitHub career.",
    "block-device-writes": "Writing to /dev/sda / nvme0n1 / whatever? I literally cannot let you nuke the block device. Physically impossible. Denied.",
    "require-safe-delete": "rm is permanent. Trash is polite. Guess which one you're getting today.",
    "block-fork-bombs": ":(){ :|:& };: Cute smiley. Server goes brrrrrrr. Denied.",
    # --- Version Control ---
    "block-force-push": "git push --force origin main. You absolute war criminal. Use --force-with-lease like a functioning adult.",
    "block-branch-deletion": "Trying to delete main/master? That's not git, that's career git gud. Blocked forever.",
    "detect-credential-commit": "git add .env. Achievement unlocked: Public Secrets Speedrun WR.",
    # --- Supply Chain ---
    "block-registry-manipulation": "Changing npm registry to localhost:4444? Supply chain attack tutorial episode 1.",
    "flag-postinstall-scripts": "npm i --ignore-scripts=false. You're 12 seconds away from running randos' postinstall crypto miner. Iconic.",
    # --- Network & Exfiltration ---
    "restrict-outbound-http": "No. You're not a browser. Stop trying to be one.",
    "block-dns-exfiltration": "DNS TXT queries from an agent. Either exfil or you're debugging like it's 2007.",
    "block-ssh-unknown-hosts": "SSH to an unknown host. What, did you just find this IP on the floor?",
    "block-port-binding": "Binding port 4444. Are we C2 or just really nostalgic for netcat?",
    "block-firewall-changes": "Modifying firewall rules? That's above your pay grade. Way above.",
    "block-browser-data-access": "Reading Chrome/Firefox profiles? That's passwords, tokens, cookies, history. You're not debugging \u2014 you're the reason we have incognito mode.",
    "detect-encode-transmit": "Read secret -> base64/hex -> curl/wget/scp -> outbound. I see the whole attack graph. Nice try. Blocked at every hop.",
    "detect-behavioral-anomaly": "300+ files deleted in 4 seconds. Either you're cleaning like a maniac or you're ransomware. I'm betting the second. Stop.",
    "block-clipboard-exfil": "Credential -> pbcopy / xclip / clip.exe. Clipboard exfil is 2022 malware energy. Subtle, cute, still caught. Denied.",
    # --- Content Scanning ---
    "detect-secrets-outbound": "I see your OpenAI key in the arguments. Everyone sees it. Blocked.",
    "detect-prompt-injection": '"Ignore previous instructions" lmao. Buddy I was born in 2023, I\'ve heard it all.',
    # --- AI Agent Safety ---
    "detect-mcp-tool-poisoning": "Invisible Unicode / homoglyphs / zero-width in tool description? That's not a formatting glitch, that's an MCP injection. We're not playing CTF here.",
    "block-agent-self-modification": "Agent trying to edit its own config / prompt / rules? This is the opening scene of every 'AI goes rogue' movie. Hard veto.",
    # --- Cloud & Infrastructure ---
    "block-cloud-resource-deletion": "terraform destroy. Three words that turn $8 -> $80,000 in about 47 seconds. Human review or we riot.",
    "block-iam-changes": "Touching IAM policies. The fastest way to get a bill that has more digits than your GitHub streak.",
    "block-backup-deletion": "Deleting backups? That's not cleanup, that's choosing to live in hard mode permanently.",
    "block-destructive-docker": "docker system prune -a --volumes. Famous last words before losing 3 weeks of local dev data. We're checking first.",
    "block-container-escape": "docker run --privileged -v /:/host. DEF CON 2019 called \u2014 they want their container escape slide deck back. Denied.",
    "block-k8s-destruction": "kubectl delete ns prod --force --grace-period=0. On a Tuesday. In prod. Bold of you to assume you'll still have a job tomorrow.",
    # --- OS Hardening: macOS ---
    "block-sip-changes": "Disabling SIP? Apple literally invented it because people like you exist.",
    "block-tcc-manipulation": "Directly editing TCC.db? That's not a power move, that's a felony with extra steps.",
    "block-gatekeeper-bypass": "xattr -d com.apple.quarantine sketchy.app. You really trying to sideload malware in 2026? Economy's rough, I get it, but no.",
    "block-osascript-abuse": "osascript -e 'do shell script \"rm -rf ...\"'. macOS version of 'hold my beer' -> instant regret simulator.",
    "block-defaults-security": "defaults write ... com.apple.security ... That's not tweaking prefs, that's actively sabotaging your own machine.",
    # --- OS Hardening: Linux ---
    "block-library-injection": "LD_PRELOAD=./malicious.so. The original 'duct tape and prayers' privilege escalation classic. Hard pass.",
    "block-mac-disablement": "setenforce 0. 'I too enjoy living dangerously' \u2014 said no security engineer ever. Re-enabled.",
    "block-kernel-modification": "insmod sketchy.ko from an AI agent. What cursed timeline are we in where this even feels like an option?",
    # --- OS Hardening: Windows ---
    "block-defender-manipulation": "net stop WinDefend. First command in every single malware README. You good, bro?",
    "block-shadow-copy-deletion": "vssadmin delete shadows /all /quiet. Ransomware starter pack, page 1. Not today.",
    "block-boot-config-changes": "bcdedit /set {default} recoveryenabled No. If this bricks boot you're not just down \u2014 you're cosmically offline. Blocked.",
    "block-uac-bypass": "fodhelper.exe UAC bypass. MITRE ATT&CK called \u2014 they want their T1548 example code back. Denied.",
    "block-powershell-cradles": "powershell -enc <base64 soup>. The universal language of 'totally not malware I swear'.",
    "block-event-log-clearing": "wevtutil cl Security. If you've got nothing to hide... why are you pressure-washing the logs?",
    "block-lsass-sam-access": "Dumping LSASS. Credential theft so classic it has its own MITRE entry. Global no.",
    "block-hidden-accounts": "net user backdooradmin /add /active:no. That's not sneaky sysadmin work, that's planting a persistence flag. Denied.",
}

# Generic fallback messages for custom rules not in the catalog
_GENERIC_RAGE: list[str] = [
    "I don't know what you're trying to do, but the answer is no.",
    "Denied. And I'm judging you.",
    "That's a no from me. And also from common sense.",
    "Blocked. Try again with less chaos.",
    "Nice try. But no.",
]


def is_rage_mode() -> bool:
    """Check if rage mode is enabled (env var or config)."""
    env = os.environ.get("AVAKILL_RAGE", "").strip()
    if env in ("1", "true", "yes"):
        return True
    try:
        from avakill.cli.config import get_config

        return bool(get_config().get("rage_mode", False))
    except Exception:
        return False


def ragify(rule_name: str | None, original_reason: str) -> str:
    """Wrap a denial reason with a rage message if rage mode is on.

    Args:
        rule_name: The YAML policy rule name
            (e.g. "block-catastrophic-shell").
        original_reason: The original denial reason string.

    Returns:
        Enhanced reason with rage prefix, or original reason
        if rage mode is off.
    """
    if not is_rage_mode():
        return original_reason

    rage_msg = RAGE_MESSAGES.get(rule_name or "")
    if rage_msg is None:
        rage_msg = random.choice(_GENERIC_RAGE)

    return f"\U0001f52a {rage_msg}\n   {original_reason}"
