# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "slow: foundation or integration tests that are slower than unit tests",
    )
    config.addinivalue_line(
        "markers",
        "optional_adapter: tests that exercise optional detector adapters",
    )
