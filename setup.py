#!/usr/bin/env python3
"""Proxy build to setup.cfg for PyPI."""
import re

from setuptools import setup

from src import __version__


def rewrite_version(version):
    """Rewrite the version from __init__."""
    with open("setup.cfg") as f:
        setup_cfg = f.read()
    setup_cfg = re.sub(r"version = [\d.]+", "version = " + version, setup_cfg)
    with open("setup.cfg", "w") as f:
        f.write(setup_cfg)


rewrite_version(__version__)
setup()
