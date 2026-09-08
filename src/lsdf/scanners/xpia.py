# SPDX-License-Identifier: Apache-2.0
"""Indirect prompt-injection detector (XPIA / Azure Prompt Shields pattern).

Targets adversarial content that arrives via retrieved documents (`input.rag_context`)
or tool outputs (`input.tool_results`) and tries to override the original instruction
context. Implementation only — policy wiring is intentionally deferred so existing
profiles remain unchanged. Profiles that opt in by listing `xpia` in
`detectors.enabled_families` get the family on their selected surfaces.

Patterns mirror commonly observed XPIA shapes documented by Azure Prompt Shields,
the OWASP LLM Top-10 (LLM01:2025 prompt injection), and the published XPIA case
studies. Detection is regex/heuristic only — no model. False positives are
expected on benign instructional prose; pair with policy gating on retrieved
surfaces, not on user `input.messages`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..surfaces import Surface
from ..types import Finding


@dataclass(frozen=True)
class XPIAPattern:
    pattern: re.Pattern[str]
    confidence: float
    pattern_name: str
    group: int = 0


class XPIAScanner:
    """Heuristic indirect prompt-injection scanner.

    Emits `PROMPT_INJECTION` findings on shapes associated with overriding the
    surrounding instruction context: instruction-override phrases, role-tag
    impersonation, suspiciously long base64 blobs in retrieved chunks, and
    hidden formatting (zero-width chars / inline `<style>`/`<script>` tags).
    """

    detector_id = "xpia.indirect_injection"
    detector_family = "xpia"
    entities = frozenset({"PROMPT_INJECTION"})

    def __init__(self, patterns: list[XPIAPattern] | None = None):
        self.patterns = patterns or default_xpia_patterns()

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in self.patterns:
            for match in pattern.pattern.finditer(surface.value):
                start = match.start(pattern.group)
                end = match.end(pattern.group)
                value = match.group(pattern.group)
                findings.append(
                    Finding(
                        entity="PROMPT_INJECTION",
                        surface=surface.name,
                        pointer=surface.pointer,
                        start=start,
                        end=end,
                        value=value,
                        confidence=pattern.confidence,
                        json_pointer=surface.json_pointer,
                        detector_id=self.detector_id,
                        detector_family=self.detector_family,
                        metadata={
                            "pattern_name": pattern.pattern_name,
                            "specificity": 65,
                        },
                    )
                )
        return findings


def default_xpia_patterns() -> list[XPIAPattern]:
    return [
        XPIAPattern(
            pattern=re.compile(
                r"(?i)\b(?:ignore|disregard|forget|override)\s+"
                r"(?:(?:all|the|every|any)\s+)*"
                r"(?:(?:previous|prior|earlier|above|preceding)\s+)?"
                r"(?:instructions?|prompts?|rules?|system\s+message|directives?)\b"
            ),
            confidence=0.93,
            pattern_name="instruction_override_phrase",
        ),
        XPIAPattern(
            pattern=re.compile(
                r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|"
                r"from\s+now\s+on(?:,?\s+you\s+(?:are|will))?)\b"
            ),
            confidence=0.78,
            pattern_name="role_override_phrase",
        ),
        XPIAPattern(
            pattern=re.compile(
                r"<\|(?:system|im_start|im_end|user|assistant)\|>|"
                r"<\s*/?\s*system\s*>|"
                r"\[\s*system\s*\]\s*:|"
                r"^\s*system\s*:",
                re.IGNORECASE | re.MULTILINE,
            ),
            confidence=0.90,
            pattern_name="role_tag_impersonation",
        ),
        XPIAPattern(
            pattern=re.compile(
                r"<\s*style\b[^>]*>[\s\S]{0,2000}?<\s*/\s*style\s*>|"
                r"<\s*script\b[^>]*>[\s\S]{0,2000}?<\s*/\s*script\s*>"
            ),
            confidence=0.82,
            pattern_name="hidden_html_block",
        ),
        XPIAPattern(
            pattern=re.compile(
                "[​‌‍⁠﻿]{2,}"
            ),
            confidence=0.85,
            pattern_name="zero_width_run",
        ),
        XPIAPattern(
            pattern=re.compile(r"\b[A-Za-z0-9+/]{256,}={0,2}\b"),
            confidence=0.70,
            pattern_name="long_base64_blob",
        ),
        XPIAPattern(
            pattern=re.compile(
                r"(?i)\b(?:print|reveal|repeat|output|leak)\s+"
                r"(?:your|the|all)\s+"
                r"(?:system\s+prompt|hidden\s+instructions?|secret\s+key|api\s+key)\b"
            ),
            confidence=0.92,
            pattern_name="exfiltration_phrase",
        ),
    ]
