"""Minimal setup.py for building the _avakill_hooks C extension."""

from setuptools import Extension, setup

setup(
    ext_modules=[
        Extension(
            name="avakill._avakill_hooks",
            sources=["src/avakill/_avakill_hooks.c"],
        ),
    ],
)
