"""Tests for the AvaKill schema module and CLI command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from avakill.cli.main import cli
from avakill.schema import generate_prompt, get_json_schema, get_json_schema_string


@pytest.fixture
def runner():
    return CliRunner()


# --- get_json_schema() ---


class TestGetJsonSchema:
    def test_returns_dict(self):
        schema = get_json_schema()
        assert isinstance(schema, dict)

    def test_has_expected_top_level_keys(self):
        schema = get_json_schema()
        assert "properties" in schema
        assert "type" in schema

    def test_has_policy_properties(self):
        schema = get_json_schema()
        props = schema["properties"]
        assert "version" in props
        assert "default_action" in props
        assert "policies" in props

    def test_has_examples(self):
        schema = get_json_schema()
        assert "examples" in schema


# --- get_json_schema_string() ---


class TestGetJsonSchemaString:
    def test_returns_parseable_json(self):
        result = get_json_schema_string()
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
        assert "properties" in parsed

    def test_pretty_printed_by_default(self):
        result = get_json_schema_string()
        assert "\n" in result
        assert "  " in result

    def test_compact_mode(self):
        result = get_json_schema_string(compact=True)
        # Compact JSON has no newlines
        assert "\n" not in result
        # Still valid JSON
        parsed = json.loads(result)
        assert "properties" in parsed
        # Compact is shorter than pretty-printed
        pretty = get_json_schema_string(compact=False)
        assert len(result) < len(pretty)


# --- generate_prompt() ---


class TestGeneratePrompt:
    def test_includes_schema(self):
        prompt = generate_prompt()
        assert "JSON Schema" in prompt
        assert '"properties"' in prompt

    def test_includes_evaluation_rules(self):
        prompt = generate_prompt()
        assert "First-match-wins" in prompt
        assert "Glob syntax" in prompt
        assert "default_action" in prompt

    def test_includes_anti_patterns(self):
        prompt = generate_prompt()
        assert "Common Mistakes" in prompt
        assert "broad allow rule before a specific deny rule" in prompt

    def test_includes_self_protection(self):
        prompt = generate_prompt()
        assert "Self-Protection" in prompt
        assert "avakill approve" in prompt
        assert ".proposed.yaml" in prompt
        assert "Never write directly" in prompt

    def test_includes_examples(self):
        prompt = generate_prompt()
        assert "Example 1" in prompt
        assert "Example 2" in prompt
        assert "Example 3" in prompt
        assert "default_action:" in prompt

    def test_includes_output_instructions(self):
        prompt = generate_prompt()
        assert "Output Instructions" in prompt
        assert 'version: "1.0"' in prompt

    def test_with_tools_list(self):
        prompt = generate_prompt(tools_list=["file_read", "shell_exec", "db_query"])
        assert "file_read" in prompt
        assert "shell_exec" in prompt
        assert "db_query" in prompt
        assert "Available tools" in prompt

    def test_with_use_case(self):
        prompt = generate_prompt(use_case="code assistant for Python development")
        assert "code assistant for Python development" in prompt
        assert "Use case" in prompt

    def test_with_tools_and_use_case(self):
        prompt = generate_prompt(
            tools_list=["execute_sql", "web_search"],
            use_case="data pipeline agent",
        )
        assert "execute_sql" in prompt
        assert "data pipeline agent" in prompt

    def test_without_options(self):
        prompt = generate_prompt()
        # Should still have all core sections
        assert "AvaKill Policy Generation Prompt" in prompt
        assert "JSON Schema" in prompt
        assert "Evaluation Rules" in prompt
        # Should NOT have context section
        assert "Available tools" not in prompt
        assert "Use case" not in prompt


# --- CLI: avakill schema ---


class TestSchemaCLI:
    def test_json_output(self, runner: CliRunner):
        result = runner.invoke(cli, ["schema"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "properties" in parsed

    def test_prompt_output(self, runner: CliRunner):
        result = runner.invoke(cli, ["schema", "--format=prompt"])
        assert result.exit_code == 0
        assert "AvaKill Policy Generation Prompt" in result.output
        assert "JSON Schema" in result.output

    def test_prompt_with_tools(self, runner: CliRunner):
        result = runner.invoke(
            cli, ["schema", "--format=prompt", "--tools=file_read,shell_exec"]
        )
        assert result.exit_code == 0
        assert "file_read" in result.output
        assert "shell_exec" in result.output

    def test_prompt_with_use_case(self, runner: CliRunner):
        result = runner.invoke(
            cli, ["schema", "--format=prompt", "--use-case=code assistant"]
        )
        assert result.exit_code == 0
        assert "code assistant" in result.output

    def test_compact_json(self, runner: CliRunner):
        result = runner.invoke(cli, ["schema", "--compact"])
        assert result.exit_code == 0
        output = result.output.strip()
        # Compact JSON: no newlines
        assert "\n" not in output
        parsed = json.loads(output)
        assert "properties" in parsed

    def test_output_to_file(self, runner: CliRunner, tmp_path: Path):
        out_file = tmp_path / "schema.json"
        result = runner.invoke(cli, ["schema", "-o", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        parsed = json.loads(out_file.read_text(encoding="utf-8"))
        assert "properties" in parsed

    def test_prompt_output_to_file(self, runner: CliRunner, tmp_path: Path):
        out_file = tmp_path / "prompt.md"
        result = runner.invoke(
            cli, ["schema", "--format=prompt", "-o", str(out_file)]
        )
        assert result.exit_code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "AvaKill Policy Generation Prompt" in content


# --- Package-level lazy imports ---


class TestPackageExports:
    def test_get_json_schema_lazy_import(self):
        import avakill

        func = avakill.get_json_schema
        from avakill.schema import get_json_schema as direct

        assert func is direct

    def test_generate_prompt_lazy_import(self):
        import avakill

        func = avakill.generate_prompt
        from avakill.schema import generate_prompt as direct

        assert func is direct

    def test_in_all(self):
        import avakill

        assert "get_json_schema" in avakill.__all__
        assert "generate_prompt" in avakill.__all__
