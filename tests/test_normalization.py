"""Tests for tool name normalization."""

from avakill.core.normalization import (
    ToolNormalizer,
    denormalize_tool_name,
    normalize_tool_name,
)


class TestNormalizeToolName:
    """Tests for the normalize_tool_name() function."""

    def test_claude_code_bash_to_shell_execute(self) -> None:
        assert normalize_tool_name("Bash", "claude-code") == "shell_execute"

    def test_claude_code_read_to_file_read(self) -> None:
        assert normalize_tool_name("Read", "claude-code") == "file_read"

    def test_claude_code_write_to_file_write(self) -> None:
        assert normalize_tool_name("Write", "claude-code") == "file_write"

    def test_claude_code_edit_to_file_edit(self) -> None:
        assert normalize_tool_name("Edit", "claude-code") == "file_edit"

    def test_claude_code_multi_edit_to_file_edit(self) -> None:
        assert normalize_tool_name("MultiEdit", "claude-code") == "file_edit"

    def test_claude_code_glob_to_file_search(self) -> None:
        assert normalize_tool_name("Glob", "claude-code") == "file_search"

    def test_claude_code_grep_to_content_search(self) -> None:
        assert normalize_tool_name("Grep", "claude-code") == "content_search"

    def test_claude_code_task_to_agent_spawn(self) -> None:
        assert normalize_tool_name("Task", "claude-code") == "agent_spawn"

    def test_gemini_run_shell_to_shell_execute(self) -> None:
        assert normalize_tool_name("run_shell_command", "gemini-cli") == "shell_execute"

    def test_gemini_read_file_to_file_read(self) -> None:
        assert normalize_tool_name("read_file", "gemini-cli") == "file_read"

    def test_cursor_shell_command_to_shell_execute(self) -> None:
        assert normalize_tool_name("shell_command", "cursor") == "shell_execute"

    def test_windsurf_run_command_to_shell_execute(self) -> None:
        assert normalize_tool_name("run_command", "windsurf") == "shell_execute"

    def test_windsurf_write_code_to_file_write(self) -> None:
        assert normalize_tool_name("write_code", "windsurf") == "file_write"

    def test_mcp_double_underscore_passes_through(self) -> None:
        assert normalize_tool_name("mcp__server__tool", "claude-code") == "mcp__server__tool"

    def test_mcp_colon_passes_through(self) -> None:
        assert normalize_tool_name("mcp:server:tool", "gemini-cli") == "mcp:server:tool"

    def test_unknown_tool_passes_through(self) -> None:
        assert normalize_tool_name("some_custom_tool", "claude-code") == "some_custom_tool"

    def test_none_agent_passes_through(self) -> None:
        assert normalize_tool_name("Bash", None) == "Bash"

    def test_unknown_agent_passes_through(self) -> None:
        assert normalize_tool_name("Bash", "unknown-agent") == "Bash"


class TestToolNormalizer:
    """Tests for the ToolNormalizer class."""

    def test_default_normalizer_matches_module_function(self) -> None:
        n = ToolNormalizer()
        assert n.normalize("Bash", "claude-code") == "shell_execute"

    def test_custom_mapping_overrides_builtin(self) -> None:
        n = ToolNormalizer(custom_mappings={"claude-code": {"Bash": "custom_shell"}})
        assert n.normalize("Bash", "claude-code") == "custom_shell"

    def test_custom_mapping_preserves_other_builtins(self) -> None:
        n = ToolNormalizer(custom_mappings={"claude-code": {"Bash": "custom_shell"}})
        assert n.normalize("Read", "claude-code") == "file_read"

    def test_custom_mapping_new_agent(self) -> None:
        n = ToolNormalizer(custom_mappings={"my-agent": {"do_thing": "thing_do"}})
        assert n.normalize("do_thing", "my-agent") == "thing_do"

    def test_custom_mapping_new_agent_denormalize(self) -> None:
        n = ToolNormalizer(custom_mappings={"my-agent": {"do_thing": "thing_do"}})
        assert n.denormalize("thing_do", "my-agent") == "do_thing"

    def test_mcp_tool_passes_through(self) -> None:
        n = ToolNormalizer()
        assert n.normalize("mcp__s__t", "claude-code") == "mcp__s__t"


class TestGeminiCLINormalization:
    """Tests for Gemini CLI tool name mappings."""

    def test_search_files_to_file_search(self) -> None:
        assert normalize_tool_name("search_files", "gemini-cli") == "file_search"

    def test_list_files_to_file_list(self) -> None:
        assert normalize_tool_name("list_files", "gemini-cli") == "file_list"

    def test_web_search_to_web_search(self) -> None:
        assert normalize_tool_name("web_search", "gemini-cli") == "web_search"

    def test_web_fetch_to_web_fetch(self) -> None:
        assert normalize_tool_name("web_fetch", "gemini-cli") == "web_fetch"


class TestWindsurfNormalization:
    """Tests for Windsurf tool name mappings."""

    def test_mcp_tool_to_mcp_tool(self) -> None:
        assert normalize_tool_name("mcp_tool", "windsurf") == "mcp_tool"

    def test_read_code_to_file_read(self) -> None:
        assert normalize_tool_name("read_code", "windsurf") == "file_read"


class TestDenormalize:
    """Tests for reverse lookup."""

    def test_shell_execute_to_bash_for_claude_code(self) -> None:
        assert denormalize_tool_name("shell_execute", "claude-code") == "Bash"

    def test_shell_execute_to_run_shell_command_for_gemini(self) -> None:
        assert denormalize_tool_name("shell_execute", "gemini-cli") == "run_shell_command"

    def test_shell_execute_to_run_command_for_windsurf(self) -> None:
        assert denormalize_tool_name("shell_execute", "windsurf") == "run_command"

    def test_file_read_to_read_for_claude_code(self) -> None:
        assert denormalize_tool_name("file_read", "claude-code") == "Read"

    def test_unknown_canonical_returns_none(self) -> None:
        assert denormalize_tool_name("unknown_tool", "claude-code") is None

    def test_unknown_agent_returns_none(self) -> None:
        assert denormalize_tool_name("shell_execute", "unknown-agent") is None
