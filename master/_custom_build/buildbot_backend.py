# Dummy buildbackend
from __future__ import annotations

import os

from setuptools import build_meta as _orig
from setuptools.build_meta import *  # noqa: F403


def _no_install_reqs() -> bool:
    return bool(os.getenv('NO_INSTALL_REQS'))


def get_requires_for_build_sdist(config_settings: _orig._ConfigSettings = None) -> list[str]:
    if _no_install_reqs():
        return []
    return _orig.get_requires_for_build_sdist(config_settings=config_settings)


def get_requires_for_build_wheel(config_settings: _orig._ConfigSettings = None) -> list[str]:
    if _no_install_reqs():
        return []
    return _orig.get_requires_for_build_wheel(config_settings=config_settings)
