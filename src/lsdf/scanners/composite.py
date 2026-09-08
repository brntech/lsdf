# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Protocol

from ..surfaces import Surface
from ..types import Finding


class Scanner(Protocol):
    def scan(self, surface: Surface) -> list[Finding]:
        ...


class CompositeScanner:
    def __init__(self, scanners: list[Scanner]):
        self.scanners = scanners

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        for scanner in self.scanners:
            findings.extend(scanner.scan(surface))
        return findings
