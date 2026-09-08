# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import math
import os
import re
from collections import Counter

from ..surfaces import Surface
from ..types import Finding

TOKEN_RE = re.compile(r"[^ \t\r\n,\"'(){}\[\]<>]+")
PATHLIKE_SUFFIXES = (
    ".com",
    ".org",
    ".net",
    ".io",
    ".dev",
    ".local",
    ".js",
    ".ts",
    ".py",
    ".yml",
    ".yaml",
    ".json",
    ".md",
)
CREDENTIAL_SPECIALS = set("!@$%^&*+=")

# Hyphenated all-alpha compounds (e.g. "OpenAI-compatible", "local-model-network")
# clear the entropy heuristic's len ≥ 16 + Shannon ≥ 3.5 bar but are technical
# prose, not credentials. Real credentials almost always carry a digit or one
# of CREDENTIAL_SPECIALS — neither of which appears in these compounds.
_ALPHA_HYPHEN_COMPOUND_RE = re.compile(r"^[A-Za-z]+(-[A-Za-z]+)+$")

# Operators can add additional explicit deny substrings via env var (e.g. an
# internal product name that happens to score above the entropy bar). Match is
# case-insensitive and substring-based; an exact whole-token match isn't
# required so operators don't have to predict every wrapping form.
_ENTROPY_DENY_ENV_VAR = "LSDF_ENTROPY_DENY_SUBSTRINGS"


def _entropy_deny_substrings() -> tuple[str, ...]:
    raw = os.environ.get(_ENTROPY_DENY_ENV_VAR, "").strip()
    if not raw:
        return ()
    return tuple(piece.strip().lower() for piece in raw.split(";") if piece.strip())


class EntropySecretScanner:
    """Supplementary credential scanner for high-entropy secret-like values."""

    detector_id = "entropy.secret"
    detector_family = "entropy"
    entities = frozenset({"OTHER_SECRET"})

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        deny_substrings = _entropy_deny_substrings()
        for match in TOKEN_RE.finditer(surface.value):
            token = match.group(0).strip("`.,;:")
            if not token or _looks_like_url_or_path(token) or _looks_like_placeholder(token):
                continue
            if _is_alpha_hyphen_compound(token):
                continue
            if deny_substrings and _matches_deny_substring(token, deny_substrings):
                continue
            if _looks_like_credential(token):
                findings.append(
                    Finding(
                        entity="OTHER_SECRET",
                        surface=surface.name,
                        pointer=surface.pointer,
                        start=match.start(),
                        end=match.end(),
                        value=match.group(0),
                        confidence=0.78,
                        json_pointer=surface.json_pointer,
                        detector_id="entropy.secret",
                        detector_family="entropy",
                        metadata={"heuristic": "credential_entropy", "specificity": 50},
                    )
                )
        return findings


def _looks_like_credential(token: str) -> bool:
    has_alpha = any(char.isalpha() for char in token)
    has_digit = any(char.isdigit() for char in token)
    has_credential_special = any(char in CREDENTIAL_SPECIALS for char in token)
    if len(token) >= 8 and has_alpha and has_digit and has_credential_special:
        return True
    if len(token) >= 16 and _shannon_entropy(token) >= 3.5:
        return True
    return False


def _looks_like_url_or_path(token: str) -> bool:
    lowered = token.lower()
    if lowered.startswith(("http://", "https://", "//", "www.")):
        return True
    if lowered.endswith(PATHLIKE_SUFFIXES):
        return True
    slash_count = token.count("/")
    if slash_count >= 1 and not any(char in CREDENTIAL_SPECIALS for char in token):
        return True
    if "\\" in token:
        return True
    return False


def _looks_like_placeholder(token: str) -> bool:
    if token.startswith(("process.env.", "os.environ", "env.")):
        return True
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]{5,}", token))


def _is_alpha_hyphen_compound(token: str) -> bool:
    """Hyphenated all-letter compounds (no digits, no specials) are nearly
    always technical prose, not credentials. The entropy fallback otherwise
    flags `OpenAI-compatible`, `local-model-network`, etc."""
    return bool(_ALPHA_HYPHEN_COMPOUND_RE.fullmatch(token))


def _matches_deny_substring(token: str, deny_substrings: tuple[str, ...]) -> bool:
    lowered = token.lower()
    return any(needle in lowered for needle in deny_substrings)


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
