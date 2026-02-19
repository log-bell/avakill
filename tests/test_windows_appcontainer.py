"""Tests for Windows AppContainer ctypes wrappers.

These tests use mocks since AppContainer APIs are Windows-only.
Real API tests are in TestAppContainerProfile (skipped on non-Windows).
"""

from __future__ import annotations

import sys

import pytest


class TestAppContainerNameGeneration:
    """Tests that work on all platforms (no Windows APIs needed)."""

    def test_container_name_format(self):
        from avakill.launcher.backends.windows_appcontainer import (
            container_name_from_policy,
        )

        name = container_name_from_policy("/path/to/policy.yaml")
        assert name.startswith("avakill-")
        assert len(name) <= 64

    def test_container_name_deterministic(self):
        from avakill.launcher.backends.windows_appcontainer import (
            container_name_from_policy,
        )

        name1 = container_name_from_policy("/path/to/policy.yaml")
        name2 = container_name_from_policy("/path/to/policy.yaml")
        assert name1 == name2

    def test_container_name_different_for_different_policies(self):
        from avakill.launcher.backends.windows_appcontainer import (
            container_name_from_policy,
        )

        name1 = container_name_from_policy("/path/to/policy1.yaml")
        name2 = container_name_from_policy("/path/to/policy2.yaml")
        assert name1 != name2


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
class TestAppContainerProfile:
    def test_create_profile_returns_sid(self):
        from avakill.launcher.backends.windows_appcontainer import (
            create_app_container,
            delete_app_container,
        )

        sid = create_app_container("avakill-test-create")
        assert sid is not None
        delete_app_container("avakill-test-create")

    def test_delete_profile_succeeds(self):
        from avakill.launcher.backends.windows_appcontainer import (
            create_app_container,
            delete_app_container,
        )

        create_app_container("avakill-test-delete")
        delete_app_container("avakill-test-delete")

    def test_grant_directory_access(self):
        import tempfile

        from avakill.launcher.backends.windows_appcontainer import (
            create_app_container,
            delete_app_container,
            grant_directory_access,
        )

        sid = create_app_container("avakill-test-dacl")
        with tempfile.TemporaryDirectory() as tmp:
            grant_directory_access(sid, tmp, read=True, write=False)
        delete_app_container("avakill-test-dacl")
