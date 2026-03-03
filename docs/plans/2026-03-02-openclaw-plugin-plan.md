# AvaKill OpenClaw Plugin — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build `avakill-openclaw`, a native OpenClaw plugin that enforces AvaKill policies inside OpenClaw's gateway process with 6 enforcement layers.

**Architecture:** Pure TypeScript plugin that runs in-process with OpenClaw's gateway. Reimplements AvaKill's PolicyEngine in TypeScript for sub-millisecond evaluation with zero Python dependency. Ships as an npm package with `openclaw plugins install avakill-openclaw`.

**Tech Stack:** TypeScript 5.x, `js-yaml`, `minimatch`, `@sinclair/typebox`, vitest for testing

**Design Doc:** `docs/plans/2026-03-02-openclaw-plugin-design.md`

---

## Task 1: Scaffold the npm package

**Files:**
- Create: `avakill-openclaw/package.json`
- Create: `avakill-openclaw/tsconfig.json`
- Create: `avakill-openclaw/openclaw.plugin.json`
- Create: `avakill-openclaw/vitest.config.ts`
- Create: `avakill-openclaw/.gitignore`

**Step 1: Create project directory**

```bash
mkdir -p ~/avakill-openclaw/src/layers
mkdir -p ~/avakill-openclaw/src/__tests__
mkdir -p ~/avakill-openclaw/bootstrap
mkdir -p ~/avakill-openclaw/docs
```

**Step 2: Write package.json**

```json
{
  "name": "avakill-openclaw",
  "version": "1.0.0",
  "description": "AvaKill security firewall plugin for OpenClaw — 6 enforcement layers, sub-millisecond policy evaluation",
  "license": "MIT",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": ["dist", "bootstrap", "openclaw.plugin.json"],
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit",
    "prepublishOnly": "npm run build"
  },
  "dependencies": {
    "js-yaml": "^4.1.0",
    "minimatch": "^9.0.0"
  },
  "devDependencies": {
    "@sinclair/typebox": "^0.32.0",
    "@types/js-yaml": "^4.0.9",
    "typescript": "^5.4.0",
    "vitest": "^1.6.0"
  },
  "peerDependencies": {
    "openclaw": ">=2026.2.0"
  },
  "keywords": ["openclaw", "avakill", "security", "firewall", "ai-safety", "plugin"],
  "repository": {
    "type": "git",
    "url": "https://github.com/log-bell/avakill-openclaw.git"
  }
}
```

**Step 3: Write tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "isolatedModules": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist", "src/__tests__"]
}
```

**Step 4: Write openclaw.plugin.json**

```json
{
  "id": "avakill-openclaw",
  "configSchema": {
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "policy": {
        "type": "string",
        "description": "Path to policy YAML file. Auto-discovers if not set."
      },
      "daemon": {
        "type": "boolean",
        "default": false,
        "description": "Forward audit events to AvaKill daemon if running."
      },
      "audit": {
        "type": "boolean",
        "default": true,
        "description": "Write local audit log to ~/.openclaw/avakill/audit.jsonl"
      },
      "guardTool": {
        "type": "boolean",
        "default": true,
        "description": "Register avakill_guard tool for agent self-checking (L2)."
      },
      "contextInject": {
        "type": "boolean",
        "default": true,
        "description": "Inject safety rules into agent bootstrap context (L6)."
      }
    }
  }
}
```

**Step 5: Write vitest.config.ts**

```typescript
import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    globals: true,
    include: ["src/__tests__/**/*.test.ts"],
  },
});
```

**Step 6: Write .gitignore**

```
node_modules/
dist/
*.tgz
```

**Step 7: Install dependencies**

Run: `cd ~/avakill-openclaw && npm install`

**Step 8: Verify it compiles**

Create a placeholder `src/index.ts`:
```typescript
export const VERSION = "1.0.0";
```

Run: `cd ~/avakill-openclaw && npx tsc --noEmit`
Expected: no errors

**Step 9: Commit**

```bash
cd ~/avakill-openclaw && git init && git add -A
git commit -m "chore: scaffold avakill-openclaw npm package"
```

---

## Task 2: Implement policy models and YAML loader

**Files:**
- Create: `avakill-openclaw/src/models.ts`
- Create: `avakill-openclaw/src/policy.ts`
- Test: `avakill-openclaw/src/__tests__/policy.test.ts`

**Step 1: Write the failing tests**

```typescript
// src/__tests__/policy.test.ts
import { describe, it, expect } from "vitest";
import { loadPolicy, type PolicyConfig } from "../policy.js";

describe("loadPolicy", () => {
  it("parses valid YAML policy string", () => {
    const yaml = `
version: "1.0"
default_action: deny
policies:
  - name: allow-read
    tools: ["file_read"]
    action: allow
    enforcement: hard
`;
    const config = loadPolicy(yaml);
    expect(config.version).toBe("1.0");
    expect(config.default_action).toBe("deny");
    expect(config.policies).toHaveLength(1);
    expect(config.policies[0].name).toBe("allow-read");
    expect(config.policies[0].tools).toEqual(["file_read"]);
    expect(config.policies[0].action).toBe("allow");
  });

  it("substitutes environment variables", () => {
    process.env.TEST_WORKSPACE = "/home/user/project";
    const yaml = `
version: "1.0"
default_action: deny
policies:
  - name: workspace-only
    tools: ["file_write"]
    action: allow
    conditions:
      workspace: "\${TEST_WORKSPACE}"
`;
    const config = loadPolicy(yaml);
    expect(config.policies[0].conditions?.workspace).toBe("/home/user/project");
    delete process.env.TEST_WORKSPACE;
  });

  it("rejects invalid version", () => {
    const yaml = `
version: "2.0"
default_action: deny
policies: []
`;
    expect(() => loadPolicy(yaml)).toThrow();
  });

  it("defaults enforcement to hard", () => {
    const yaml = `
version: "1.0"
default_action: deny
policies:
  - name: test
    tools: ["*"]
    action: deny
`;
    const config = loadPolicy(yaml);
    expect(config.policies[0].enforcement).toBe("hard");
  });

  it("defaults default_action to deny", () => {
    const yaml = `
version: "1.0"
policies:
  - name: test
    tools: ["*"]
    action: allow
`;
    const config = loadPolicy(yaml);
    expect(config.default_action).toBe("deny");
  });

  it("parses rate_limit with window string", () => {
    const yaml = `
version: "1.0"
default_action: deny
policies:
  - name: rate-limited
    tools: ["shell_run"]
    action: allow
    rate_limit:
      max_calls: 10
      window: "60s"
`;
    const config = loadPolicy(yaml);
    expect(config.policies[0].rate_limit?.max_calls).toBe(10);
    expect(config.policies[0].rate_limit?.window).toBe("60s");
  });

  it("parses conditions with args_match", () => {
    const yaml = `
version: "1.0"
default_action: deny
policies:
  - name: block-rm
    tools: ["shell_run"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "rm -r"]
`;
    const config = loadPolicy(yaml);
    expect(config.policies[0].conditions?.args_match?.command).toEqual(["rm -rf", "rm -r"]);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/policy.test.ts`
Expected: FAIL — modules not found

**Step 3: Write models.ts**

```typescript
// src/models.ts

export interface RateLimit {
  max_calls: number;
  window: string; // e.g. "60s", "5m", "1h"
}

export interface RuleConditions {
  args_match?: Record<string, string[]>;
  args_not_match?: Record<string, string[]>;
  shell_safe?: boolean;
  command_allowlist?: string[];
  path_match?: Record<string, string[]>;
  path_not_match?: Record<string, string[]>;
  workspace?: string;
  content_scan?: string[];
}

export interface PolicyRule {
  name: string;
  tools: string[];
  action: "allow" | "deny" | "require_approval";
  enforcement: "hard" | "soft" | "advisory";
  conditions?: RuleConditions;
  rate_limit?: RateLimit;
  message?: string;
  log: boolean;
}

export interface PolicyConfig {
  version: string;
  default_action: "allow" | "deny";
  policies: PolicyRule[];
}

export interface Decision {
  readonly allowed: boolean;
  readonly action: "allow" | "deny" | "require_approval";
  readonly policy_name?: string;
  readonly reason?: string;
  readonly timestamp: Date;
  readonly latency_ms: number;
  readonly overridable: boolean;
}

export interface ToolCall {
  tool_name: string;
  arguments: Record<string, unknown>;
  agent_id?: string;
  session_id?: string;
  timestamp: Date;
}

export interface AuditEntry {
  timestamp: string;
  tool: string;
  args: Record<string, unknown>;
  decision: "allow" | "deny" | "require_approval";
  rule?: string;
  layer: string;
  latency_ms: number;
  agent_id?: string;
  session_key?: string;
}
```

**Step 4: Write policy.ts**

```typescript
// src/policy.ts
import yaml from "js-yaml";
import { readFileSync } from "node:fs";
import type { PolicyConfig, PolicyRule } from "./models.js";

export type { PolicyConfig };

function substituteEnv(text: string): string {
  return text.replace(/\$\{(\w+)\}/g, (match, varName) => {
    return process.env[varName] ?? match;
  });
}

function validateWindow(window: string): void {
  if (!/^\d+[smh]$/.test(window)) {
    throw new Error(`Invalid rate limit window: "${window}". Must match /^\\d+[smh]$/.`);
  }
}

export function loadPolicy(yamlString: string): PolicyConfig {
  const substituted = substituteEnv(yamlString);
  const raw = yaml.load(substituted) as Record<string, unknown>;

  if (!raw || typeof raw !== "object") {
    throw new Error("Policy YAML must be a mapping.");
  }

  const version = String(raw.version ?? "");
  if (version !== "1.0") {
    throw new Error(`Unsupported policy version: "${version}". Only "1.0" is supported.`);
  }

  const default_action = (raw.default_action as string) ?? "deny";
  if (default_action !== "allow" && default_action !== "deny") {
    throw new Error(`Invalid default_action: "${default_action}".`);
  }

  const rawPolicies = (raw.policies as unknown[]) ?? [];
  if (!Array.isArray(rawPolicies)) {
    throw new Error("policies must be an array.");
  }

  const policies: PolicyRule[] = rawPolicies.map((r: unknown, i: number) => {
    const rule = r as Record<string, unknown>;
    if (!rule.name || !rule.tools || !rule.action) {
      throw new Error(`Policy rule at index ${i} missing required fields (name, tools, action).`);
    }

    const tools = rule.tools as string[];
    if (!Array.isArray(tools) || tools.length === 0) {
      throw new Error(`Policy rule "${rule.name}": tools must be a non-empty array.`);
    }

    const action = rule.action as string;
    if (!["allow", "deny", "require_approval"].includes(action)) {
      throw new Error(`Policy rule "${rule.name}": invalid action "${action}".`);
    }

    const enforcement = (rule.enforcement as string) ?? "hard";
    if (!["hard", "soft", "advisory"].includes(enforcement)) {
      throw new Error(`Policy rule "${rule.name}": invalid enforcement "${enforcement}".`);
    }

    let rate_limit = undefined;
    if (rule.rate_limit) {
      const rl = rule.rate_limit as Record<string, unknown>;
      validateWindow(String(rl.window));
      rate_limit = {
        max_calls: Number(rl.max_calls),
        window: String(rl.window),
      };
    }

    return {
      name: String(rule.name),
      tools,
      action: action as PolicyRule["action"],
      enforcement: enforcement as PolicyRule["enforcement"],
      conditions: rule.conditions as PolicyRule["conditions"],
      rate_limit,
      message: rule.message ? String(rule.message) : undefined,
      log: rule.log !== false,
    };
  });

  return { version, default_action, policies };
}

export function loadPolicyFromFile(filePath: string): PolicyConfig {
  const content = readFileSync(filePath, "utf-8");
  return loadPolicy(content);
}

export function windowSeconds(window: string): number {
  const multipliers: Record<string, number> = { s: 1, m: 60, h: 3600 };
  const unit = window[window.length - 1];
  const value = parseInt(window.slice(0, -1), 10);
  return value * (multipliers[unit] ?? 1);
}
```

**Step 5: Run tests to verify they pass**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/policy.test.ts`
Expected: all 7 tests PASS

**Step 6: Commit**

```bash
cd ~/avakill-openclaw
git add src/models.ts src/policy.ts src/__tests__/policy.test.ts
git commit -m "feat: add policy models and YAML loader with env var substitution"
```

---

## Task 3: Implement tool name normalization

**Files:**
- Create: `avakill-openclaw/src/normalize.ts`
- Test: `avakill-openclaw/src/__tests__/normalize.test.ts`

**Step 1: Write the failing tests**

```typescript
// src/__tests__/normalize.test.ts
import { describe, it, expect } from "vitest";
import { normalize } from "../normalize.js";

describe("normalize", () => {
  it("maps bash to shell_run", () => {
    expect(normalize("bash")).toBe("shell_execute");
  });
  it("maps file_read to file_read", () => {
    expect(normalize("file_read")).toBe("file_read");
  });
  it("maps glob to file_list", () => {
    expect(normalize("glob")).toBe("file_list");
  });
  it("maps grep to content_search", () => {
    expect(normalize("grep")).toBe("content_search");
  });
  it("maps spawn_agent to agent_spawn", () => {
    expect(normalize("spawn_agent")).toBe("agent_spawn");
  });
  it("passes MCP tools through unchanged (mcp__ prefix)", () => {
    expect(normalize("mcp__myserver__mytool")).toBe("mcp__myserver__mytool");
  });
  it("passes MCP tools through unchanged (mcp: prefix)", () => {
    expect(normalize("mcp:myserver:mytool")).toBe("mcp:myserver:mytool");
  });
  it("passes unknown tools through unchanged", () => {
    expect(normalize("custom_tool_xyz")).toBe("custom_tool_xyz");
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/normalize.test.ts`
Expected: FAIL

**Step 3: Write normalize.ts**

```typescript
// src/normalize.ts

const OPENCLAW_TO_CANONICAL: Record<string, string> = {
  bash: "shell_execute",
  "system.run": "shell_execute",
  file_read: "file_read",
  file_write: "file_write",
  file_edit: "file_edit",
  glob: "file_list",
  grep: "content_search",
  list_dir: "file_list",
  fetch: "web_fetch",
  web_search: "web_search",
  browser_navigate: "web_fetch",
  spawn_agent: "agent_spawn",
  subagent: "agent_spawn",
};

export function normalize(toolName: string): string {
  if (toolName.startsWith("mcp__") || toolName.startsWith("mcp:")) {
    return toolName;
  }
  return OPENCLAW_TO_CANONICAL[toolName] ?? toolName;
}
```

**Step 4: Run tests to verify they pass**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/normalize.test.ts`
Expected: all 8 tests PASS

**Step 5: Commit**

```bash
cd ~/avakill-openclaw
git add src/normalize.ts src/__tests__/normalize.test.ts
git commit -m "feat: add OpenClaw to AvaKill tool name normalization"
```

---

## Task 4: Implement shell safety analysis

**Files:**
- Create: `avakill-openclaw/src/shell.ts`
- Test: `avakill-openclaw/src/__tests__/shell.test.ts`

**Step 1: Write the failing tests**

```typescript
// src/__tests__/shell.test.ts
import { describe, it, expect } from "vitest";
import { isShellSafe } from "../shell.js";

describe("isShellSafe", () => {
  it("returns safe for simple commands", () => {
    const [safe] = isShellSafe("ls -la");
    expect(safe).toBe(true);
  });
  it("returns safe for empty string", () => {
    const [safe] = isShellSafe("");
    expect(safe).toBe(true);
  });
  it("detects pipe", () => {
    const [safe, findings] = isShellSafe("cat file | grep secret");
    expect(safe).toBe(false);
    expect(findings).toContain("pipe (|)");
  });
  it("detects output redirect >", () => {
    const [safe, findings] = isShellSafe("echo hello > /etc/passwd");
    expect(safe).toBe(false);
    expect(findings).toContain("output redirect (> or >>)");
  });
  it("detects semicolon chaining", () => {
    const [safe, findings] = isShellSafe("echo hello; rm -rf /");
    expect(safe).toBe(false);
    expect(findings).toContain("command chaining (;)");
  });
  it("detects && chaining", () => {
    const [safe, findings] = isShellSafe("cd /tmp && rm -rf *");
    expect(safe).toBe(false);
    expect(findings).toContain("logical AND (&&)");
  });
  it("detects || chaining", () => {
    const [safe, findings] = isShellSafe("test -f x || echo fail");
    expect(safe).toBe(false);
    expect(findings).toContain("logical OR (||)");
  });
  it("detects backtick subshell", () => {
    const [safe, findings] = isShellSafe("echo `whoami`");
    expect(safe).toBe(false);
    expect(findings).toContain("backtick subshell (`)");
  });
  it("detects $() subshell", () => {
    const [safe, findings] = isShellSafe("echo $(whoami)");
    expect(safe).toBe(false);
    expect(findings).toContain("subshell expansion ($())");
  });
  it("detects eval", () => {
    const [safe, findings] = isShellSafe("eval 'rm -rf /'");
    expect(safe).toBe(false);
    expect(findings).toContain("eval builtin");
  });
  it("detects source", () => {
    const [safe, findings] = isShellSafe("source ~/.bashrc");
    expect(safe).toBe(false);
    expect(findings).toContain("source builtin");
  });
  it("detects xargs", () => {
    const [safe, findings] = isShellSafe("find . -print0 | xargs -0 rm");
    expect(safe).toBe(false);
    expect(findings).toContain("xargs command");
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/shell.test.ts`
Expected: FAIL

**Step 3: Write shell.ts**

```typescript
// src/shell.ts

const SHELL_PATTERNS: [RegExp, string][] = [
  [/\|/, "pipe (|)"],
  [/(?<![=\-])>>?(?!=)/, "output redirect (> or >>)"],
  [/<<?\s/, "input redirect (< or <<)"],
  [/;/, "command chaining (;)"],
  [/&&/, "logical AND (&&)"],
  [/\|\|/, "logical OR (||)"],
  [/`/, "backtick subshell (`)"],
  [/\$\(/, "subshell expansion ($())"],
  [/\$\{/, "variable expansion (${})"],
  [/\beval\b/, "eval builtin"],
  [/\bsource\b/, "source builtin"],
  [/\bxargs\b/, "xargs command"],
];

export function isShellSafe(command: string): [boolean, string[]] {
  if (!command) {
    return [true, []];
  }
  const findings: string[] = [];
  for (const [pattern, description] of SHELL_PATTERNS) {
    if (pattern.test(command)) {
      findings.push(description);
    }
  }
  return [findings.length === 0, findings];
}
```

**Step 4: Run tests to verify they pass**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/shell.test.ts`
Expected: all 12 tests PASS

**Step 5: Commit**

```bash
cd ~/avakill-openclaw
git add src/shell.ts src/__tests__/shell.test.ts
git commit -m "feat: add shell safety analysis with 12 metachar patterns"
```

---

## Task 5: Implement the PolicyEngine (core evaluator)

**Files:**
- Create: `avakill-openclaw/src/evaluator.ts`
- Test: `avakill-openclaw/src/__tests__/evaluator.test.ts`

**Step 1: Write the failing tests**

Tests cover: first-match-wins, glob matching, wildcards, args_match (case-insensitive substring, AND across keys, OR within lists), args_not_match, shell_safe condition, command_allowlist, rate limiting, enforcement levels (hard/soft/advisory), default_action fallback.

See design doc for exact evaluation semantics. Port from Python:
- `_matchTool()`: fnmatch via minimatch, special `"*"` and `"all"` wildcards
- `_checkConditions()`: shell_safe -> command_allowlist -> args_match -> args_not_match
- `_checkRateLimit()`: sliding window Map, agent-scoped keys, purge expired from left
- Enforcement: advisory deny flips to allow with `[advisory]` prefix; soft deny sets `overridable: true` with `[overridable]` prefix
- Rate limit exceeded throws `RateLimitExceeded` error

**Step 2: Run tests to verify they fail**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/evaluator.test.ts`

**Step 3: Write evaluator.ts**

Core class with:
- `constructor(config: PolicyConfig)` — stores config, initializes rate limit Map
- `evaluate(toolCall: ToolCall): Decision` — iterate rules, first match wins
- `matchTool(name, patterns)` — minimatch glob + `"*"/"all"` wildcards
- `checkConditions(toolCall, conditions)` — shell_safe, command_allowlist, args_match, args_not_match
- `checkRateLimit(toolCall, rateLimit)` — sliding window timestamps

Export `RateLimitExceeded` error class with `decision` property.

**Step 4: Run tests to verify they pass**

Run: `cd ~/avakill-openclaw && npx vitest run src/__tests__/evaluator.test.ts`

**Step 5: Commit**

```bash
git commit -m "feat: implement PolicyEngine with first-match-wins evaluation"
```

---

## Task 6: Implement self-protection

**Files:**
- Create: `avakill-openclaw/src/self-protection.ts`
- Test: `avakill-openclaw/src/__tests__/self-protection.test.ts`

5 layers of hardcoded checks (mirroring Python `SelfProtection`):

1. **Policy file write**: write-named tools + policy file in args
2. **Shell targets protected**: shell commands with write intent targeting policy/hook config
3. **Hook binary protection**: shell commands targeting hook binaries
4. **Hook config file protection**: write-named tools targeting `.claude/settings.json` etc.
5. **Argument content scanning**: uninstall, daemon shutdown, approve, reset patterns

Regex patterns to port from Python `self_protection.py`:
- `UNINSTALL_PATTERN`: `(?:pipx?|pip3|...) (?:uninstall|remove) avakill`
- `DAEMON_SHUTDOWN_PATTERN`: `(?:avakill daemon stop|pkill.*avakill|...)`
- `HOOK_CONFIG_PATTERN`: `(?:\.claude|\.gemini|\.cursor|\.codeium)...settings.json`

Returns `Decision | null` — null means "no self-protection concern, proceed to policy eval".

**Commit:**
```bash
git commit -m "feat: add self-protection rules (policy files, hooks, daemon)"
```

---

## Task 7: Implement audit logger

**Files:**
- Create: `avakill-openclaw/src/audit.ts`
- Test: `avakill-openclaw/src/__tests__/audit.test.ts`

Simple JSONL writer with pluggable sink interface:
- `AuditSink` interface: `write(line: string): void`
- `AuditLogger` class: `append(entry: AuditEntry): void` — JSON.stringify + sink.write
- `createFileAuditSink(path)`: mkdirSync + appendFileSync

**Commit:**
```bash
git commit -m "feat: add JSONL audit logger with pluggable sink"
```

---

## Task 8: Implement L1 — Hard Block layer

**Files:**
- Create: `avakill-openclaw/src/layers/hard-block.ts`
- Test: `avakill-openclaw/src/__tests__/hard-block.test.ts`

Handler for `before_tool_call` hook:
1. Normalize tool name
2. Check self-protection (returns block if hit)
3. Evaluate via PolicyEngine
4. If denied: return `{ block: true, blockReason: "..." }`
5. If allowed: return `undefined` (pass through)
6. Catch `RateLimitExceeded`, return block
7. Append audit entry for every call

OpenClaw types this handler expects to satisfy:
```typescript
// event: PluginHookBeforeToolCallEvent = { toolName: string; params: Record<string, unknown> }
// ctx: PluginHookToolContext = { agentId?: string; sessionKey?: string; toolName: string }
// return: PluginHookBeforeToolCallResult | void = { params?: ...; block?: boolean; blockReason?: string } | void
```

**Commit:**
```bash
git commit -m "feat: implement L1 hard block layer (before_tool_call)"
```

---

## Task 9: Implement L2 — Guard Tool layer

**Files:**
- Create: `avakill-openclaw/src/layers/guard-tool.ts`
- Test: `avakill-openclaw/src/__tests__/guard-tool.test.ts`

Creates an `AnyAgentTool`-compatible object:
- name: `"avakill_guard"`
- label: `"AvaKill Security Guard"`
- description: instructs agent to call before risky operations
- parameters: `{ tool: string, args: object }`
- handler: normalize -> self-protection check -> policy evaluate -> return ALLOWED/DENIED text

Registered via `api.registerTool(guardTool)`.

**Commit:**
```bash
git commit -m "feat: implement L2 guard tool (avakill_guard)"
```

---

## Task 10: Implement L3 — Output Scan layer

**Files:**
- Create: `avakill-openclaw/src/layers/output-scan.ts`
- Test: `avakill-openclaw/src/__tests__/output-scan.test.ts`

Secret detection regex patterns:
- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- GitHub PATs: `ghp_[A-Za-z0-9]{36}`, `gho_...`, `ghs_...`, `github_pat_...`
- API keys: `sk-...`, `sk-proj-...`
- Slack tokens: `xoxb-...`, `xoxp-...`
- Private keys: `-----BEGIN ... PRIVATE KEY-----`
- JWTs: `eyJ...`
- Generic: `api_key=...`, `secret_key=...`

Returns `ScanResult`: `{ hasSecrets, findings, redacted, secretCount }`

Handler for `tool_result_persist` hook (SYNCHRONOUS):
- Extract text from message content
- Scan for secrets
- If found: replace message content with redaction notice, audit log

**Commit:**
```bash
git commit -m "feat: implement L3 output scan with secret detection and redaction"
```

---

## Task 11: Implement L4 — Message Gate layer

**Files:**
- Create: `avakill-openclaw/src/layers/message-gate.ts`
- Test: `avakill-openclaw/src/__tests__/message-gate.test.ts`

Handler for `message_sending` hook:
- Scan outbound message content for secrets using same scanner as L3
- If secrets found: return `{ cancel: true }` to block the message
- Audit log the blocked message (without the secret content)

OpenClaw types:
```typescript
// event: PluginHookMessageSendingEvent = { to: string; content: string; metadata?: Record<string, unknown> }
// ctx: PluginHookMessageContext = { channelId: string; accountId?: string; conversationId?: string }
// return: PluginHookMessageSendingResult | void = { content?: string; cancel?: boolean } | void
```

**Commit:**
```bash
git commit -m "feat: implement L4 message gate (secret leak prevention)"
```

---

## Task 12: Implement L5 — Spawn Control layer

**Files:**
- Create: `avakill-openclaw/src/layers/spawn-control.ts`
- Test: `avakill-openclaw/src/__tests__/spawn-control.test.ts`

Simple sliding-window rate limiter for subagent spawns:
- Config: `maxPerMinute` (default 10)
- Tracks spawn timestamps in array
- Purges entries older than 60s
- If count >= max: return `{ status: "error", error: "..." }`
- Otherwise: return `undefined` (or `{ status: "ok" }`)

OpenClaw types:
```typescript
// event: PluginHookSubagentSpawningEvent = { childSessionKey, agentId, label?, mode, ... }
// ctx: PluginHookSubagentContext = { runId?, childSessionKey?, requesterSessionKey? }
// return: PluginHookSubagentSpawningResult | void = { status: "ok" } | { status: "error", error: string } | void
```

**Commit:**
```bash
git commit -m "feat: implement L5 spawn control (subagent rate limiting)"
```

---

## Task 13: Implement L6 — Context Inject layer

**Files:**
- Create: `avakill-openclaw/bootstrap/AVAKILL_RULES.md`
- Create: `avakill-openclaw/src/layers/context-inject.ts`
- Test: `avakill-openclaw/src/__tests__/context-inject.test.ts`

AVAKILL_RULES.md content instructs the agent to:
1. Call `avakill_guard` before shell commands, file writes, DB queries
2. If DENIED, do NOT attempt the operation
3. Explain to user what was blocked and suggest alternatives
4. Mention `avakill fix --last` for recovery

Registered via `api.registerHook("agent:bootstrap", handler)`:
- handler pushes a `WorkspaceBootstrapFile` entry into `event.context.bootstrapFiles`
- File: `{ name: "AVAKILL_RULES.md", path: "avakill://rules", content: <rules>, missing: false }`

**Commit:**
```bash
git commit -m "feat: implement L6 context inject with AVAKILL_RULES.md"
```

---

## Task 14: Implement the plugin entry point (index.ts)

**Files:**
- Create: `avakill-openclaw/src/index.ts`
- Test: `avakill-openclaw/src/__tests__/index.test.ts`

Main `register(api)` function wiring all 6 layers:

1. Read `pluginConfig` from `api.pluginConfig`
2. Discover policy path: config.policy -> AVAKILL_POLICY env -> cwd -> ~/.config/avakill/
3. Load + validate policy YAML
4. Create PolicyEngine instance
5. Create AuditLogger (JSONL at `~/.openclaw/avakill/audit.jsonl`)
6. Create SpawnController (default 10/min)
7. Register hooks via `api.on(hookName, handler)`:
   - `"before_tool_call"` -> L1 hard-block handler
   - `"tool_result_persist"` -> L3 output-scan handler
   - `"message_sending"` -> L4 message-gate handler
   - `"subagent_spawning"` -> L5 spawn-control handler
8. Register tool via `api.registerTool(guardTool)` -> L2
9. Register bootstrap hook via `api.registerHook("agent:bootstrap", ...)` -> L6
10. Start file watcher on policy path for hot reload
11. Log: "AvaKill active. 6 enforcement layers. Policy loaded (N rules)"

Export: `{ register }` as default export (OpenClaw plugin contract).

**Commit:**
```bash
git commit -m "feat: implement plugin entry point wiring all 6 enforcement layers"
```

---

## Task 15: Write getting-started.md documentation

**Files:**
- Create: `avakill-openclaw/docs/getting-started.md`

Zero-jargon guide for OpenClaw users who have never heard of AvaKill:

1. **What is this?** — 2 sentences: AvaKill is a security firewall for AI agents. This plugin adds it to OpenClaw.
2. **Install** — one command: `openclaw plugins install avakill-openclaw`
3. **Add a policy** — full starter policy YAML inline (the default AvaKill policy)
4. **Verify it works** — concrete test: ask agent to run `rm -rf /`, see the block message
5. **What's protected** — quick list of what the 6 layers do
6. **Customize** — link to policy-guide.md
7. **Problems?** — link to troubleshooting.md

**Commit:**
```bash
git commit -m "docs: add getting-started guide for OpenClaw users"
```

---

## Task 16: Write policy-guide.md documentation

**Files:**
- Create: `avakill-openclaw/docs/policy-guide.md`

For users who want to customize rules:

1. **How policies work** — first-match-wins explained with numbered walkthrough
2. **Tool name mapping** — full table: OpenClaw name -> AvaKill canonical name
3. **Common patterns** — copy-paste YAML snippets:
   - Block all shell commands except allowlisted
   - Rate-limit web fetches
   - Block secret file reads (.env, credentials)
   - Allow-all with advisory warnings
   - Block MCP tool access
4. **Enforcement levels** — hard vs soft vs advisory with examples
5. **Conditions reference** — args_match, args_not_match, shell_safe, command_allowlist
6. **Testing changes** — hot reload, audit log inspection

**Commit:**
```bash
git commit -m "docs: add policy customization guide with YAML snippets"
```

---

## Task 17: Write troubleshooting.md documentation

**Files:**
- Create: `avakill-openclaw/docs/troubleshooting.md`

Problem-first format:

1. **"Plugin not loading"** — check `openclaw plugins list`, verify path, check JSON config
2. **"Agent ignores the guard tool"** — verify L6 contextInject enabled, check bootstrap
3. **"AvaKill blocks something it shouldn't"** — find rule in audit log, adjust policy
4. **"Policy changes not taking effect"** — hot reload, gateway restart
5. **"Audit log not writing"** — check path permissions, disk space
6. **"Rate limit too aggressive"** — adjust window and max_calls in policy

**Commit:**
```bash
git commit -m "docs: add troubleshooting guide with problem-first format"
```

---

## Task 18: Run full test suite and verify build

**Step 1:** Run `cd ~/avakill-openclaw && npx vitest run` — all tests pass
**Step 2:** Run `cd ~/avakill-openclaw && npx tsc` — clean compile
**Step 3:** Verify `dist/` output has all expected files
**Step 4:** Fix any issues, commit

---

## Task 19: Update AvaKill CLI to support OpenClaw

**Files:**
- Modify: `src/avakill/hooks/installer.py` — add OpenClaw to `_AGENT_CONFIG`
- Modify: `src/avakill/cli/setup_cmd.py` — detect OpenClaw, offer plugin install
- Modify: `src/avakill/profiles/openclaw.yaml` — set `supports_hooks: true`

Add OpenClaw entry to installer that wraps `openclaw plugins install/uninstall avakill-openclaw`. Update setup wizard to detect OpenClaw and offer install. Run `make check` to verify.

**Commit:**
```bash
cd ~/avakill
git commit -m "feat: add OpenClaw plugin install support to CLI"
```

---

## Summary

| Task | Component | Tests |
|------|-----------|-------|
| 1 | Package scaffold | build check |
| 2 | Models + YAML loader | 7 tests |
| 3 | Tool normalization | 8 tests |
| 4 | Shell safety analysis | 12 tests |
| 5 | PolicyEngine (core) | ~20 tests |
| 6 | Self-protection | 9 tests |
| 7 | Audit logger | 2 tests |
| 8 | L1: Hard Block | 3 tests |
| 9 | L2: Guard Tool | 3 tests |
| 10 | L3: Output Scan | 5 tests |
| 11 | L4: Message Gate | 3 tests |
| 12 | L5: Spawn Control | 2 tests |
| 13 | L6: Context Inject | 2 tests |
| 14 | Plugin entry point | 1 test + integration |
| 15 | getting-started.md | — |
| 16 | policy-guide.md | — |
| 17 | troubleshooting.md | — |
| 18 | Full test + build verify | — |
| 19 | AvaKill CLI integration | existing tests |

**Total: ~75 tests across 19 tasks**
