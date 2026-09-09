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
_MODEL_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9]+(?:[.:-][A-Za-z0-9]+)+$")
_TOOL_CALL_ID_RE = re.compile(r"^chatcmpl-tool-[0-9a-f]{16}$")
_RESPONSE_ID_RE = re.compile(r"^chatcmpl-[A-Za-z0-9]{8,64}$")
# Bounded approximation of vLLM's generated fingerprint, not arbitrary custom
# fingerprints or arbitrary PEP 440 local labels. Version, parallelism order
# and config-hash suffix follow vLLM's serve/utils/fingerprint.py contract.
_VLLM_FINGERPRINT_RE = re.compile(
    r"vllm-(?:dev|[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}"
    r"(?:(?:a|b|rc)[0-9]{1,6})?(?:\.post[0-9]{1,6})?(?:\.dev[0-9]{1,8})?"
    r"(?:\+(?:g[0-9a-f]{7,40}(?:\.d[0-9]{8})?(?:\.cu[0-9]{2,4})?|cu[0-9]{2,4}))?)"
    r"(?:-tp(?:[2-9]|[1-9][0-9]{1,5}))?"
    r"(?:-pp(?:[2-9]|[1-9][0-9]{1,5}))?"
    r"(?:-dp(?:[2-9]|[1-9][0-9]{1,5}))?(?:-ep)?"
    r"-(?:[0-9a-f]{8}|nohash)"
)
_SAFE_ROUTING_METADATA_LITERALS = frozenset(
    {"completion.chunk", "chat.completion", "chat.completion.chunk"}
)
_MODEL_ID_PROSE_RE = re.compile(
    r"\b(?:exact\s+)?model\s+(?:(?:id|identifier)\s+is|named)\s*$",
    re.IGNORECASE,
)
_CODE_REFERENCE_RE = re.compile(
    r"^(?:file_path|source_path|path|filename):(?:line|line_number)"
    r"(?:,(?:column|column_number))?$"
)
_CODE_FILE_REFERENCE_RE = re.compile(
    r"^(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+"
    r"\.(?:c|cc|cpp|css|go|h|html|java|js|jsx|py|rb|rs|scss|svelte|ts|tsx|vue)"
    r":\d+(?::\d+)?$"
)
_CAMEL_CASE_IDENTIFIER_RE = re.compile(r"^[a-z][A-Za-z]+$")
_CAMEL_CASE_PREFIXES = {
    "build",
    "close",
    "create",
    "delete",
    "fetch",
    "find",
    "get",
    "handle",
    "is",
    "list",
    "load",
    "make",
    "open",
    "parse",
    "read",
    "render",
    "resolve",
    "set",
    "update",
    "use",
    "write",
}
_SOURCE_GLOB_RE = re.compile(r"^(?:[A-Za-z0-9_.?*{}-]+/)+[A-Za-z0-9_.?*{}-]+$")
_SOURCE_GLOB_SUFFIXES = (
    ".c",
    ".cc",
    ".cpp",
    ".css",
    ".go",
    ".h",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".py",
    ".rb",
    ".rs",
    ".scss",
    ".svelte",
    ".ts",
    ".tsx",
    ".vue",
)
_MODEL_SECRET_MARKERS = {
    "api",
    "auth",
    "credential",
    "key",
    "pass",
    "password",
    "secret",
    "token",
}

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
            raw_token = match.group(0)
            token = raw_token.strip("`.,;:")
            if (
                not token
                or _looks_like_url_or_path(token)
                or _looks_like_placeholder(token)
                or _looks_like_code_reference(token, raw_token)
                or _looks_like_source_glob(token)
                or _looks_like_code_identifier(token, raw_token, surface.value, match.start(), match.end())
            ):
                continue
            if surface.routing_metadata and _looks_like_safe_model_identifier(token):
                continue
            if surface.routing_metadata and surface.value in _SAFE_ROUTING_METADATA_LITERALS:
                continue
            if surface.correlation_metadata and _TOOL_CALL_ID_RE.fullmatch(surface.value):
                continue
            if surface.response_id_metadata and _RESPONSE_ID_RE.fullmatch(surface.value):
                continue
            if (
                surface.provider_version_metadata
                and len(surface.value) <= 192
                and _VLLM_FINGERPRINT_RE.fullmatch(surface.value)
            ):
                continue
            if _looks_like_model_id_prose(token, surface.value, match.start()):
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


def _has_code_secret_marker(token: str) -> bool:
    lowered = token.lower()
    return any(
        marker in lowered
        for marker in ("api", "auth", "credential", "key", "pass", "password", "secret", "token")
    )


def _looks_like_code_reference(token: str, raw_token: str) -> bool:
    """Skip only backtick-delimited source references, never credential labels."""
    if not (raw_token.startswith("`") and raw_token.endswith("`")):
        return False
    if not (_CODE_REFERENCE_RE.fullmatch(token) or _CODE_FILE_REFERENCE_RE.fullmatch(token)):
        return False
    return True


def _looks_like_source_glob(token: str) -> bool:
    """Recognize conventional wildcard source paths in prompt/tool prose."""
    if not ("/" in token and ("*" in token or "?" in token)):
        return False
    if not _SOURCE_GLOB_RE.fullmatch(token):
        return False
    if not token.lower().endswith(_SOURCE_GLOB_SUFFIXES):
        return False
    return not _has_code_secret_marker(token)


def _looks_like_code_identifier(
    token: str,
    raw_token: str,
    source: str,
    start: int,
    end: int,
) -> bool:
    """Skip a long camelCase identifier only when it is visibly code-shaped."""
    if not _CAMEL_CASE_IDENTIFIER_RE.fullmatch(token) or len(token) < 16:
        return False
    if _has_code_secret_marker(token):
        return False
    segments = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", token)
    if len(segments) < 3 or segments[0].lower() not in _CAMEL_CASE_PREFIXES:
        return False
    if any(len(segment) < 2 or len(segment) > 24 for segment in segments):
        return False
    if raw_token.startswith("`") and raw_token.endswith("`"):
        return True
    before = source[start - 1 : start]
    after = source[end : end + 1]
    if before in {".", "("} or after in {".", "("}:
        return True
    context_before = source[max(0, start - 64) : start]
    return bool(
        re.search(
            r"\brename\s+[A-Za-z_][A-Za-z0-9_]*\s*->\s*$",
            context_before,
            flags=re.IGNORECASE,
        )
    )


def _is_alpha_hyphen_compound(token: str) -> bool:
    """Hyphenated all-letter compounds (no digits, no specials) are nearly
    always technical prose, not credentials. The entropy fallback otherwise
    flags `OpenAI-compatible`, `local-model-network`, etc."""
    return bool(_ALPHA_HYPHEN_COMPOUND_RE.fullmatch(token))


def _looks_like_safe_model_identifier(token: str) -> bool:
    """Recognize only provider-style routing IDs in explicitly marked fields.

    This is deliberately narrower than a generic allow-list: underscores are
    rejected, credential marker components are rejected, and a separator is
    required.  An API-shaped value in `model` therefore remains visible to the
    regex credential recognizers and is still enforced by policy.
    """

    if len(token) < 3 or len(token) > 128 or "_" in token:
        return False
    if not _MODEL_IDENTIFIER_RE.fullmatch(token):
        return False
    raw_components = [component for component in re.split(r"[.:-]+", token) if component]
    components = {component.lower() for component in raw_components}
    if len(raw_components) < 2 or not any(char.isdigit() for char in token):
        return False
    if any(
        any(marker in component for marker in _MODEL_SECRET_MARKERS)
        for component in components
    ):
        return False
    # Provider model IDs normally have short, low-entropy family/version
    # components (qwen2.5-coder:0.5b, gpt-4o). This keeps arbitrary segmented
    # high-entropy values in the normal credential heuristic.
    if raw_components[0] != raw_components[0].lower():
        return False
    if any(len(component) > 32 for component in raw_components):
        return False
    if any(len(component) >= 8 and _shannon_entropy(component) >= 3.0 for component in raw_components):
        return False
    return True


def _looks_like_model_id_prose(token: str, source: str, start: int) -> bool:
    """Skip a safe model ID only after an explicit model-ID declaration."""
    if not _looks_like_safe_model_identifier(token):
        return False
    context_before = source[max(0, start - 48) : start]
    return bool(_MODEL_ID_PROSE_RE.search(context_before))


def _matches_deny_substring(token: str, deny_substrings: tuple[str, ...]) -> bool:
    lowered = token.lower()
    return any(needle in lowered for needle in deny_substrings)


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
