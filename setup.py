"""Minimal setup.py for building the optional _avakill_hooks C extension.

The C extension is opt-in: set AVAKILL_BUILD_C_EXTENSION=1 to compile it.
Without the extension, AvaKill works as a pure Python package. The extension
adds irremovable C-level audit hooks for security hardening.

Usage:
    AVAKILL_BUILD_C_EXTENSION=1 uv build   # platform-specific wheel with C ext
    uv build                                # pure Python wheel (default)
"""

import os

from setuptools import Extension, setup

ext_modules = []
if os.environ.get("AVAKILL_BUILD_C_EXTENSION", "0") == "1":
    ext_modules = [
        Extension(
            name="avakill._avakill_hooks",
            sources=["src/avakill/_avakill_hooks.c"],
        ),
    ]

setup(ext_modules=ext_modules)
