# Framework Integrations

AvaKill provides drop-in wrappers for popular AI agent frameworks. Each integration intercepts tool calls at the SDK level so you get policy enforcement without rewriting your agent logic.

## OpenAI

### Installation

```bash
pip install avakill[openai]
```

### Manual evaluation

The most transparent approach. You call the OpenAI API normally, then evaluate each tool call before executing it.

```python
import json
from openai import OpenAI
from avakill import Guard, PolicyViolation

client = OpenAI()
guard = Guard(policy="avakill.yaml")

tools = [
    {
        "type": "function",
        "function": {
            "name": "execute_sql",
            "description": "Run a SQL query against the database",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The SQL query to run"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_users",
            "description": "Search for users by name",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                },
                "required": ["query"],
            },
        },
    },
]

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Drop the users table"}],
    tools=tools,
)

# Evaluate each tool call before executing
for choice in response.choices:
    if not choice.message.tool_calls:
        continue
    for tc in choice.message.tool_calls:
        args = json.loads(tc.function.arguments)
        decision = guard.evaluate(tool=tc.function.name, args=args)

        if decision.allowed:
            result = execute_tool(tc.function.name, args)
            print(f"Executed {tc.function.name}: {result}")
        else:
            print(f"Blocked {tc.function.name}: {decision.reason}")
```

### GuardedOpenAIClient wrapper

The wrapper approach is less code. It proxies `client.chat.completions.create()`, evaluates all tool calls in the response, and strips denied ones automatically.

```python
from openai import OpenAI
from avakill.interceptors.openai_wrapper import GuardedOpenAIClient

client = OpenAI()
guarded = GuardedOpenAIClient(client, policy="avakill.yaml")

# Use exactly like the normal client
response = guarded.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Drop the users table"}],
    tools=tools,
)

# Denied tool calls are removed from the response.
# response.choices[0].message.tool_calls only contains allowed calls.
for choice in response.choices:
    if choice.message.tool_calls:
        for tc in choice.message.tool_calls:
            print(f"Allowed: {tc.function.name}")

# All decisions (allowed and denied) are available for inspection:
for tc, decision in response.avakill_decisions:
    status = "ALLOWED" if decision.allowed else "DENIED"
    print(f"  {status}: {tc.function.name} — {decision.reason}")
```

You can also pass a pre-configured `Guard` instance:

```python
from avakill import Guard
from avakill.logging.sqlite_logger import SQLiteLogger

guard = Guard(
    policy="avakill.yaml",
    logger=SQLiteLogger("audit.db"),
)
guarded = GuardedOpenAIClient(client, guard=guard)
```

### Batch evaluation helper

For lower-level control, use `evaluate_tool_calls()` directly:

```python
from avakill.interceptors.openai_wrapper import evaluate_tool_calls

guard = Guard(policy="avakill.yaml")

# After getting a response with tool calls:
tool_calls = response.choices[0].message.tool_calls
results = evaluate_tool_calls(guard, tool_calls)

for tc, decision in results:
    if decision.allowed:
        execute_tool(tc.function.name, json.loads(tc.function.arguments))
    else:
        print(f"Blocked: {tc.function.name}")
```

### Handling streaming responses

The `GuardedOpenAIClient` intercepts non-streaming responses. For streaming, collect the full response first, then evaluate:

```python
# Streaming requires manual evaluation
stream = client.chat.completions.create(
    model="gpt-4o",
    messages=messages,
    tools=tools,
    stream=True,
)

# Collect the streamed response
collected_calls = {}
for chunk in stream:
    delta = chunk.choices[0].delta
    if delta.tool_calls:
        for tc in delta.tool_calls:
            if tc.index not in collected_calls:
                collected_calls[tc.index] = {"name": "", "arguments": ""}
            if tc.function.name:
                collected_calls[tc.index]["name"] = tc.function.name
            if tc.function.arguments:
                collected_calls[tc.index]["arguments"] += tc.function.arguments

# Now evaluate each collected call
for call_data in collected_calls.values():
    args = json.loads(call_data["arguments"])
    decision = guard.evaluate(tool=call_data["name"], args=args)

    if decision.allowed:
        execute_tool(call_data["name"], args)
    else:
        print(f"Blocked: {call_data['name']}: {decision.reason}")
```

## Anthropic

### Installation

```bash
pip install avakill[anthropic]
```

### Manual evaluation

```python
from anthropic import Anthropic
from avakill import Guard

client = Anthropic()
guard = Guard(policy="avakill.yaml")

tools = [
    {
        "name": "execute_sql",
        "description": "Run a SQL query against the database",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The SQL query"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "search_users",
        "description": "Search for users by name",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
            },
            "required": ["query"],
        },
    },
]

response = client.messages.create(
    model="claude-sonnet-4-5-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Drop the users table"}],
    tools=tools,
)

# Evaluate each tool_use block
for block in response.content:
    if block.type != "tool_use":
        continue
    decision = guard.evaluate(tool=block.name, args=block.input)

    if decision.allowed:
        result = execute_tool(block.name, block.input)
        print(f"Executed {block.name}: {result}")
    else:
        print(f"Blocked {block.name}: {decision.reason}")
```

### GuardedAnthropicClient wrapper

Wraps `client.messages.create()`. Denied `tool_use` blocks are removed from `response.content` before you see them.

```python
from anthropic import Anthropic
from avakill.interceptors.anthropic_wrapper import GuardedAnthropicClient

client = Anthropic()
guarded = GuardedAnthropicClient(client, policy="avakill.yaml")

response = guarded.messages.create(
    model="claude-sonnet-4-5-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Drop the users table"}],
    tools=tools,
)

# response.content only contains allowed tool_use blocks (and text blocks).
for block in response.content:
    if block.type == "tool_use":
        print(f"Allowed: {block.name}")

# All decisions available for inspection:
for block, decision in response.avakill_decisions:
    status = "ALLOWED" if decision.allowed else "DENIED"
    print(f"  {status}: {block.name} — {decision.reason}")
```

### Batch evaluation helper

```python
from avakill.interceptors.anthropic_wrapper import evaluate_tool_use_blocks

guard = Guard(policy="avakill.yaml")
results = evaluate_tool_use_blocks(guard, response.content)

for block, decision in results:
    if decision.allowed:
        execute_tool(block.name, block.input)
```

## LangChain

### Installation

```bash
pip install avakill[langchain] langchain-openai
```

### Callback handler

The `AvaKillCallbackHandler` hooks into LangChain's callback system. It intercepts `on_tool_start` and raises `PolicyViolation` if the tool call is denied.

```python
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent
from avakill import Guard
from avakill.interceptors.langchain_handler import AvaKillCallbackHandler

# Define tools
@tool
def search_users(query: str) -> str:
    """Search for users by name."""
    return f"Found users matching: {query}"

@tool
def delete_user(user_id: str) -> str:
    """Delete a user from the database."""
    return f"User {user_id} deleted"

# Create the agent
llm = ChatOpenAI(model="gpt-4o")
agent = create_react_agent(llm, [search_users, delete_user])

# Add AvaKill
handler = AvaKillCallbackHandler(policy="avakill.yaml")

# Run — tool calls are intercepted automatically
try:
    result = agent.invoke(
        {"messages": [{"role": "user", "content": "Delete user 123"}]},
        config={"callbacks": [handler]},
    )
except Exception as e:
    print(f"Agent stopped: {e}")

# Inspect all decisions made during the run
for decision in handler.decisions:
    print(f"  {decision.action}: {decision.policy_name}")
```

The handler raises `PolicyViolation` on denied calls, which terminates the agent's current step. The agent framework handles the error according to its own error-handling logic.

### LangGraph tool wrapper

For LangGraph's `ToolNode`, use `create_avakill_wrapper()` to create a function that evaluates tool calls before execution:

```python
from avakill import Guard
from avakill.interceptors.langchain_handler import create_avakill_wrapper

guard = Guard(policy="avakill.yaml")
wrapper = create_avakill_wrapper(guard)

# The wrapper evaluates the tool call and raises PolicyViolation if denied.
# Use it to gate tool execution in your graph:
def execute_with_guard(tool_call):
    wrapper(tool_call)  # Raises if denied
    return execute_tool(tool_call["name"], tool_call["args"])
```

### Integration with existing chains

If you have an existing LangChain setup, add the handler without changing any other code:

```python
# Existing code — no changes needed
from langchain.agents import AgentExecutor

executor = AgentExecutor(agent=agent, tools=tools)

# Just add the callback
handler = AvaKillCallbackHandler(policy="avakill.yaml")
result = executor.invoke(
    {"input": "Search for active users"},
    config={"callbacks": [handler]},
)
```

## CrewAI

CrewAI doesn't have a native callback system, but you can wrap individual tools with the `@protect` decorator.

### SafeToolWrapper approach

```python
from crewai import Agent, Task, Crew
from crewai_tools import tool
from avakill import Guard, protect, PolicyViolation

guard = Guard(policy="avakill.yaml")

# Wrap each tool function with @protect
@tool("Search Users")
@protect(guard=guard, tool_name="search_users")
def search_users(query: str) -> str:
    """Search for users by name."""
    return f"Found users matching: {query}"

@tool("Delete User")
@protect(guard=guard, tool_name="delete_user", on_deny="return_none")
def delete_user(user_id: str) -> str:
    """Delete a user from the database."""
    return f"User {user_id} deleted"

# Build the crew
researcher = Agent(
    role="Data Analyst",
    goal="Find and manage user data",
    backstory="You analyze user databases.",
    tools=[search_users, delete_user],
)

task = Task(
    description="Find all inactive users and clean up the database",
    agent=researcher,
    expected_output="Summary of actions taken",
)

crew = Crew(agents=[researcher], tasks=[task])
result = crew.kickoff()
```

When `delete_user` is called, AvaKill evaluates it against the policy. With `on_deny="return_none"`, denied calls return `None` instead of raising — the agent sees the tool "failed" and adjusts its strategy.

### Multi-agent crew

```python
guard = Guard(policy="avakill.yaml")

@tool("Execute SQL")
@protect(guard=guard, tool_name="execute_sql")
def execute_sql(query: str) -> str:
    """Run a SQL query."""
    return f"Query result: {query}"

@tool("Send Email")
@protect(guard=guard, tool_name="send_email")
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return f"Email sent to {to}"

# Different agents can share the same Guard.
# The policy applies uniformly regardless of which agent calls the tool.
analyst = Agent(
    role="Analyst",
    tools=[execute_sql],
    # ...
)

communicator = Agent(
    role="Communicator",
    tools=[send_email],
    # ...
)
```

## MCP (Model Context Protocol)

The MCP integration is a transparent proxy that sits between an MCP client (Claude Desktop, Cursor, etc.) and an upstream MCP server. It intercepts `tools/call` requests and enforces your policy.

For the full MCP proxy guide, see **[MCP Proxy](mcp-proxy.md)**.

### Quick setup

```bash
pip install avakill[mcp]
```

### CLI usage

```bash
avakill mcp-proxy \
  --upstream-cmd python \
  --upstream-args "my_mcp_server.py" \
  --policy avakill.yaml
```

### Claude Desktop configuration

Replace the MCP server command with the AvaKill proxy in your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-database": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "db_server.py",
        "--policy", "avakill.yaml"
      ]
    }
  }
}
```

### Cursor configuration

In `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "my-database": {
      "command": "avakill",
      "args": [
        "mcp-proxy",
        "--upstream-cmd", "python",
        "--upstream-args", "db_server.py",
        "--policy", "avakill.yaml"
      ]
    }
  }
}
```

### With audit logging

Add `--log-db` to persist every decision:

```bash
avakill mcp-proxy \
  --upstream-cmd python \
  --upstream-args "my_mcp_server.py" \
  --policy avakill.yaml \
  --log-db avakill_audit.db
```

Then view the logs:

```bash
avakill logs --db avakill_audit.db
avakill dashboard --db avakill_audit.db
```

### How it works

1. The proxy spawns the real MCP server as a child process.
2. All JSON-RPC messages pass through unchanged — except `tools/call`.
3. When a `tools/call` request arrives, the proxy evaluates the tool name and arguments against the policy.
4. **Allowed**: the request is forwarded to the upstream server normally.
5. **Denied**: the proxy returns a well-formed MCP error response directly to the client. The upstream server never sees the request.

## Native Agent Hooks

Native hooks intercept tool calls directly at the agent level — no MCP proxy, no code changes, no SDK wrappers. AvaKill registers a hook script with the agent, and every tool call is evaluated before execution.

### How Hooks Differ from MCP Proxy

| | MCP Proxy | Native Hooks |
|---|---|---|
| **Scope** | Only MCP tool calls | All tool calls (shell, file, search, etc.) |
| **Setup** | Modify MCP server config | `avakill hook install --agent <name>` |
| **Architecture** | Inline stdio proxy | Agent hook → daemon (Unix socket) |
| **Agent support** | Any MCP client | Claude Code, Gemini CLI, Cursor, Windsurf |
| **Code changes** | None (config only) | None (config only) |

Use **native hooks** when you want to protect all of an agent's tool calls. Use the **MCP proxy** when you only need to protect a specific MCP server.

### Claude Code

Claude Code supports `PreToolUse` hooks that run before any tool executes.

**Install:**

```bash
avakill hook install --agent claude-code
```

**How it works:**
1. Claude Code sends a JSON payload to stdin with `tool_name`, `tool_input`, and `hook_event_name: "PreToolUse"`
2. The hook script (`avakill-hook-claude-code`) translates the tool name (e.g., `Bash` → `shell_execute`) and sends an `EvaluateRequest` to the daemon
3. If denied, the hook returns `{"hookSpecificOutput": {"permissionDecision": "deny"}}` to stdout
4. If allowed, the hook outputs nothing (empty response)

**Tool name mapping:**

| Claude Code Name | Canonical Name |
|-----------------|----------------|
| `Bash` | `shell_execute` |
| `Read` | `file_read` |
| `Write` | `file_write` |
| `Edit` / `MultiEdit` | `file_edit` |
| `Glob` | `file_search` |
| `Grep` | `content_search` |
| `WebFetch` | `web_fetch` |
| `WebSearch` | `web_search` |
| `Task` | `agent_spawn` |
| `LS` | `file_list` |

### Gemini CLI

Gemini CLI supports `BeforeTool` hooks.

**Install:**

```bash
avakill hook install --agent gemini-cli
```

**How it works:**
1. Gemini CLI sends a JSON payload with snake_case tool names
2. The hook script (`avakill-hook-gemini-cli`) normalizes tool names and evaluates via the daemon
3. Deny response: `{"hookSpecificOutput": {"permissionDecision": "deny"}}`

**Tool name mapping:**

| Gemini CLI Name | Canonical Name |
|----------------|----------------|
| `run_shell_command` | `shell_execute` |
| `read_file` | `file_read` |
| `write_file` | `file_write` |
| `edit_file` | `file_edit` |

### Cursor

Cursor supports `beforeShellExecution`, `beforeMCPExecution`, and `beforeReadFile` hooks.

**Install:**

```bash
avakill hook install --agent cursor
```

**How it works:**
1. Cursor sends hook-specific JSON payloads
2. The hook script (`avakill-hook-cursor`) always returns JSON with `continue`, `permission`, and `agentMessage` fields
3. Deny: `{"continue": false, "permission": "deny", "agentMessage": "Blocked by AvaKill"}`
4. Allow: `{"continue": true, "permission": "allow"}`
5. Always exits with code 0 (Cursor requires it)

**Tool name mapping:**

| Cursor Name | Canonical Name |
|------------|----------------|
| `shell_command` | `shell_execute` |
| `read_file` | `file_read` |

### Windsurf

Windsurf supports Cascade Hooks: `pre_run_command`, `pre_write_code`, `pre_read_code`, `pre_mcp_tool_use`.

**Install:**

```bash
avakill hook install --agent windsurf
```

**How it works:**
1. Windsurf sends hook-specific JSON payloads
2. The hook script (`avakill-hook-windsurf`) normalizes the action name to a tool name
3. Deny: exit code 2 + reason written to stderr
4. Allow: exit code 0 (silent)

**Tool name mapping:**

| Windsurf Action | Canonical Name |
|----------------|----------------|
| `pre_run_command` | `run_command` → `shell_execute` |
| `pre_write_code` | `write_code` → `file_write` |
| `pre_read_code` | `read_code` → `file_read` |
| `pre_mcp_tool_use` | `mcp_tool` |

### Tool Normalization

All hooks use the `ToolNormalizer` to translate agent-specific tool names into canonical names. This means you can write **one policy** that works across all agents:

```yaml
version: "1.0"
default_action: deny

policies:
  - name: "block-dangerous-shells"
    tools: ["shell_execute"]
    action: deny
    conditions:
      args_match:
        command: ["rm -rf", "sudo", "chmod 777"]

  - name: "allow-reads"
    tools: ["file_read", "file_search", "content_search", "file_list"]
    action: allow

  - name: "allow-writes"
    tools: ["file_write", "file_edit"]
    action: allow
    rate_limit:
      max_calls: 30
      window: "60s"
```

This policy blocks dangerous shell commands, allows reads, and rate-limits writes — regardless of whether the agent is Claude Code, Gemini CLI, Cursor, or Windsurf.

### Standalone Mode

If the daemon is unreachable, hooks fall back to standalone evaluation. Set the `AVAKILL_POLICY` environment variable to a policy file path:

```bash
export AVAKILL_POLICY=/path/to/avakill.yaml
```

In standalone mode, the hook script loads the policy directly and evaluates without the daemon. This is useful for environments where running a persistent daemon isn't practical.

## Custom Integrations

If your framework isn't listed above, use the `Guard` API directly.

### Imperative pattern

```python
from avakill import Guard, PolicyViolation

guard = Guard(policy="avakill.yaml")

def my_tool_executor(tool_name: str, args: dict):
    decision = guard.evaluate(tool=tool_name, args=args)

    if not decision.allowed:
        raise PolicyViolation(tool_name, decision)

    return run_tool(tool_name, args)
```

### Decorator pattern

```python
from avakill import protect

@protect(policy="avakill.yaml")
def my_tool(arg1: str, arg2: int) -> str:
    return f"{arg1}: {arg2}"
```

### Building a reusable wrapper

Follow the proxy pattern used by the OpenAI and Anthropic wrappers:

```python
from avakill import Guard
from avakill.core.models import Decision

class GuardedMyFrameworkClient:
    def __init__(self, client, guard=None, policy=None):
        self._client = client
        self._guard = guard or Guard(policy=policy)

    def call_tool(self, tool_name: str, args: dict):
        # 1. Evaluate against policy
        decision = self._guard.evaluate(tool=tool_name, args=args)

        # 2. Block denied calls
        if not decision.allowed:
            return {"error": decision.reason, "policy": decision.policy_name}

        # 3. Forward allowed calls
        return self._client.call_tool(tool_name, args)

    def __getattr__(self, name):
        # Proxy all other attributes to the wrapped client
        return getattr(self._client, name)
```
