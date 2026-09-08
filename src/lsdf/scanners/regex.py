# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable

from ..surfaces import Surface
from ..types import Finding


@dataclass(frozen=True)
class PatternRecognizer:
    entity: str
    pattern: re.Pattern[str]
    confidence: float
    validator: Callable[[str], bool] | None = None
    group: int | str = 0
    detector_id: str = "regex.pattern"
    context_words: tuple[str, ...] = ()
    context_window: int = 60
    context_boost: float = 0.0
    context_required: bool = False
    entity_from_match: Callable[[re.Match[str]], str] | None = None
    emits: tuple[str, ...] = ()
    # Optional deny anchor: if the matched value matches this pattern, the
    # finding is suppressed. Used for shapes the regex correctly identifies
    # but a downstream policy treats as benign — e.g. transactional EMAIL
    # local parts (`noreply@`, `support@`) that operators don't want
    # logged or redacted.
    deny_pattern: re.Pattern[str] | None = None


class RegexScanner:
    detector_id = "regex"
    detector_family = "regex"

    def __init__(self, recognizers: list[PatternRecognizer] | None = None):
        self.recognizers = recognizers or default_recognizers()
        self.entities = frozenset(
            entity
            for recognizer in self.recognizers
            for entity in (recognizer.emits or (recognizer.entity,))
        )

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        scan_value, offsets = _nfc_with_offsets(surface.value)
        for recognizer in self.recognizers:
            for match in recognizer.pattern.finditer(scan_value):
                start = offsets[match.start(recognizer.group)]
                end = offsets[match.end(recognizer.group)]
                value = surface.value[start:end]
                if recognizer.validator and not recognizer.validator(value):
                    continue
                if recognizer.deny_pattern is not None and recognizer.deny_pattern.search(value):
                    continue
                context_hit = _has_context_word(
                    scan_value,
                    match.start(recognizer.group),
                    match.end(recognizer.group),
                    recognizer.context_words,
                    recognizer.context_window,
                )
                if recognizer.context_required and not context_hit:
                    continue
                confidence = recognizer.confidence
                if context_hit and recognizer.context_boost:
                    confidence = min(1.0, confidence + recognizer.context_boost)
                entity = (
                    recognizer.entity_from_match(match)
                    if recognizer.entity_from_match is not None
                    else recognizer.entity
                )
                findings.append(
                    Finding(
                        entity=entity,
                        surface=surface.name,
                        pointer=surface.pointer,
                        start=start,
                        end=end,
                        value=value,
                        confidence=confidence,
                        json_pointer=surface.json_pointer,
                        detector_id=recognizer.detector_id,
                        detector_family="regex",
                        metadata={"group": recognizer.group, "specificity": 80},
                    )
                )
        return findings


def default_recognizers() -> list[PatternRecognizer]:
    # Specific provider/format recognizers run BEFORE the generic api_key/secret
    # patterns so the more precise detector_id wins via _resolve_overlaps when
    # spans match identically (the generic recognizer would otherwise become an
    # exact duplicate that suppresses the specific finding).
    return [
        PatternRecognizer(
            "AWS_KEY",
            re.compile(
                r"\b(?:AKIA|ASIA|AROA|AIDA|ABIA|ACCA|AGPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b"
            ),
            0.95,
            detector_id="regex.aws_access_key",
        ),
        PatternRecognizer(
            "AWS_KEY",
            re.compile(
                r"(?i)\baws[_\- ]?(?:secret[_\- ]?access[_\- ]?key|secret[_\- ]?key|sak)(?:[_\- ]?id)?[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})"
            ),
            0.85,
            validator=_not_placeholder_secret,
            group=1,
            detector_id="regex.aws_secret_access_key",
        ),
        PatternRecognizer(
            "AWS_KEY",
            re.compile(
                r"(?i)\baws[_\- ]?session[_\- ]?token[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{100,})"
            ),
            0.88,
            group=1,
            detector_id="regex.aws_session_token",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"\b(?:gh[posur]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"
            ),
            0.96,
            detector_id="regex.github_token",
        ),
        PatternRecognizer(
            "JWT",
            re.compile(
                r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
            ),
            0.85,
            validator=_jwt_payload_has_identity_claim,
            detector_id="regex.jwt",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,99}\b|\bwhsec_[A-Za-z0-9]{32,64}\b"
            ),
            0.96,
            detector_id="regex.stripe_key",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"
            ),
            0.97,
            detector_id="regex.openai_api_key",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"\bsk-ant-(?:api\d{2}|admin\d{2})-[A-Za-z0-9_\-]{88,100}\b"
            ),
            0.97,
            detector_id="regex.anthropic_api_key",
        ),
        PatternRecognizer(
            "PEM_BLOCK",
            re.compile(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
                r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
            ),
            0.99,
            detector_id="regex.pem_private_key",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\bxox[baprs]-(?:\d+-)+[A-Za-z0-9]{24,34}\b"),
            0.95,
            detector_id="regex.slack_token",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            0.96,
            detector_id="regex.google_api_key",
        ),
        PatternRecognizer(
            "PRIVATE_KEY",
            re.compile(
                r'"type"\s*:\s*"service_account"[\s\S]{0,500}?"private_key"\s*:\s*"-----BEGIN'
            ),
            0.99,
            detector_id="regex.gcp_service_account",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"\b\d+-[a-z0-9]{32}\.apps\.googleusercontent\.com\b|\b1//0[a-zA-Z0-9_\-]{43}\b"
            ),
            0.94,
            detector_id="regex.gcp_oauth",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"(?i)\btwilio[^\n]{0,40}?((?:AC|SK)[a-f0-9]{32})\b"
            ),
            0.92,
            group=1,
            detector_id="regex.twilio_sid",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"(?i)\bmailgun[^\n]{0,40}?(key-[a-f0-9]{32})\b"
            ),
            0.93,
            group=1,
            detector_id="regex.mailgun_key",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
            0.97,
            detector_id="regex.sendgrid_key",
        ),
        PatternRecognizer(
            "DATADOG_KEY",
            re.compile(
                r"(?i)\bdd[_\- ]?(?:api|app)[_\- ]?key[\"']?\s*[:=]\s*[\"']?([a-f0-9]{32,40})\b"
            ),
            0.88,
            group=1,
            detector_id="regex.datadog_key",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
            0.96,
            detector_id="regex.npm_token",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b"),
            0.97,
            detector_id="regex.pypi_token",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\b[MN][A-Za-z0-9_\-]{23,27}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b"),
            0.88,
            detector_id="regex.discord_bot_token",
        ),
        # DigitalOcean — four documented `_v1_` prefixes: Personal
        # Access (dop), OAuth (doo), Refresh (dor), and Functions
        # user-specific access key (dof). All share `_v1_` + 64 hex.
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\b(?:dop|doo|dor|dof)_v1_[a-f0-9]{64}\b"),
            0.97,
            detector_id="regex.digitalocean_token",
        ),
        # Heroku modern token — `HRKU-` prefix + 60 char body
        # (post-April 2024 format). Self-identifying — no context anchor
        # needed; same rationale as the `dop_v1_` shapes.
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\bHRKU-[A-Za-z0-9_\-]{60}\b"),
            0.97,
            detector_id="regex.heroku_token",
        ),
        # Heroku legacy UUID — context-anchored to a `heroku ...
        # key|token` label. Bare UUIDs are too common in telemetry to fire
        # without context. Separator accepts `:`, `=`, OR a single space —
        # `heroku auth:token` CLI output prints the UUID on the next line
        # with no `=`/`:` between the label and the value.
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"(?i)\bheroku[_\- ]?(?:api[_\- ]?)?(?:key|token)[\"']?(?:\s*[:=]\s*|\s+)[\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b"
            ),
            0.94,
            validator=_not_placeholder_secret,
            group=1,
            detector_id="regex.heroku_token",
        ),
        # Linode — context-anchored 64-hex (Linode personal access
        # tokens are 64 hex chars, no prefix). Same anchoring rationale as
        # Heroku: 64-hex blobs are ambiguous without context.
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"(?i)\blinode[_\- ]?(?:api[_\- ]?)?(?:key|token)[\"']?\s*[:=]\s*[\"']?([a-f0-9]{64})\b"
            ),
            0.94,
            validator=_not_placeholder_secret,
            group=1,
            detector_id="regex.linode_token",
        ),
        # Square — three documented prefixes: production access (EAAA),
        # OAuth (sq0atp-), and OAuth client (sq0csp-).
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\b(?:EAAA[A-Za-z0-9_\-]{56,80}|sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,60})\b"),
            0.94,
            detector_id="regex.square_token",
        ),
        # PayPal Braintree — `access_token$<env>$<merchantId>$<token>`
        # shape; merchantId is 16 alphanumeric, token body is 32 hex.
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b"
            ),
            0.97,
            detector_id="regex.braintree_token",
        ),
        # Atlassian — two shapes: ATATT3 (modern API token, ~180-200
        # body chars + 8-hex checksum) and ATBB (legacy Bitbucket, 16 alnum +
        # 8-hex checksum).
        PatternRecognizer(
            "API_KEY",
            re.compile(
                r"\b(?:ATATT3[A-Za-z0-9_\-]{180,200}=?[A-F0-9]{8}|ATBB[A-Za-z0-9]{16}[A-F0-9]{8})\b"
            ),
            0.95,
            detector_id="regex.atlassian_token",
        ),
        PatternRecognizer(
            "AZURE_KEY",
            re.compile(
                r"(?i)\bAccountKey\s*=\s*([A-Za-z0-9+/=]{44,88})"
            ),
            0.90,
            group=1,
            detector_id="regex.azure_storage_key",
        ),
        # Full Azure SAS query-string recognizer. The previous
        # AccountKey/SharedAccessSignature pattern's [A-Za-z0-9+/=] body could
        # only cover an AccountKey value because real SAS strings carry URL-
        # encoded chars (%2F %2B %3D) and `&`-separated params, so the old
        # pattern never even matched a SharedAccessSignature= value, and would
        # have extracted only a fragment if it did. The SAS shape is uniquely
        # identified by `sv=YYYY-MM-DD` (signed-version date format) followed
        # by `sig=` with URL-encoded base64 — both are mandatory in every SAS.
        PatternRecognizer(
            "AZURE_KEY",
            re.compile(
                r"(?i)\bsv=\d{4}-\d{2}-\d{2}(?:&[a-z]+=[^\s&'\"]+){0,15}&sig=[A-Za-z0-9%+/=_-]{40,200}"
            ),
            0.97,
            detector_id="regex.azure_sas_token",
        ),
        PatternRecognizer(
            "DATABASE_URL",
            re.compile(
                r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/]+:([^@\s/]{3,})@[^\s/]+",
            ),
            0.95,
            detector_id="regex.db_connection_url",
        ),
        PatternRecognizer(
            "BEARER_TOKEN",
            re.compile(
                r"(?i)\bauthorization[\"']?\s*[:=]\s*[\"']?bearer\s+([A-Za-z0-9_\-\.=]{20,})"
            ),
            0.87,
            validator=_not_placeholder_secret,
            group=1,
            detector_id="regex.bearer_token",
        ),
        PatternRecognizer(
            "API_KEY",
            re.compile(r"\b(?:sk|pk|api|key|token)[_-][A-Za-z0-9_\-]{16,}\b"),
            0.92,
            detector_id="regex.api_key",
        ),
        # Generic secret_assignment — keyword list widened (2026-04-30)
        # to include `bearer`, `auth`, `credential`, `passphrase`, `private_key`
        # so assignments like `passphrase = "..."` or `credential: "..."`
        # surface here rather than slipping past every recognizer. Min length
        # kept at 8 — lowering to the spec's 6 was deferred pending FP
        # measurement (a 6-char window catches benign assignments like
        # `auth = manual`).
        PatternRecognizer(
            "OTHER_SECRET",
            re.compile(
                r"(?i)\b(?P<label>secret|api[_ -]?key|token|password|bearer|auth|credential|passphrase|private[_ -]?key)\s*[:=]\s*['\"]?(?P<value>[^'\"\s{},]{8,})"
            ),
            0.85,
            validator=_not_placeholder_secret,
            group="value",
            detector_id="regex.secret_assignment",
            entity_from_match=_secret_assignment_entity,
            emits=("API_KEY", "BEARER_TOKEN", "PASSWORD", "PRIVATE_KEY", "OTHER_SECRET"),
        ),
        PatternRecognizer(
            "US_SSN",
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            0.96,
            detector_id="regex.ssn",
        ),
        # International national-ID anchor recognizer. Unified pattern that
        # fires on labeled national-identifier values across six locales:
        # Dutch (BSN, Burgerservicenummer, Sociaal nummer, Sofinummer),
        # generic English (Social Security Number, Social Number,
        # SocialSecurityNumber, Numéro_Social), French (Numéro de sécurité
        # sociale, NIR, INSEE), Italian (codice fiscale, Numero di sicurezza
        # sociale, Numero di previdenza sociale), German (Steuer-ID,
        # Steueridentifikationsnummer, Sozialnummer, Sozialversicherungs-
        # nummer), Spanish (DNI, NIE, número de seguridad social), and UK
        # (NINO, National Insurance number). Captures the value following an
        # explicit `[:#=]` delimiter — narrative SSN cases without a colon
        # ("Social Security Number is 212-92-7506") are deliberately left
        # to the US-shape `regex.ssn` recognizer above so this pattern stays
        # FP-tight on benign text. Checksum validation is intentionally
        # skipped: synthetic threat corpora generate national-ID values
        # structurally without honoring real-world checksums, so a strict
        # checksum would zero-out recall on the synthetic data; the
        # anchor + delimiter gate is what keeps benign-FP rate at zero.
        PatternRecognizer(
            "OTHER_STRONG_ID",
            re.compile(
                r"(?i)\b(?P<label>"
                # Dutch BSN family
                r"bsn(?:[\-\s]?nummer)?|burgerservicenummer|sociaal\s+nummer|sofinummer"
                # Generic Social Number (English + camelCase + French/German
                # underscore JSON variants — `socialnumber`, `Social Number`,
                # `SocialSecurityNumber`, `Numéro_Social`).
                r"|social(?:[\s\-_]*security)?[\s\-_]*number|num[ée]ro[\-_\s]+social"
                # French NIR / INSEE / sécurité sociale
                r"|num[ée]ro[\-_\s]+(?:de[\-_\s]+)?(?:s[ée]curit[ée][\-_\s]+sociale|s[ée]cu|nir|insee)"
                r"|s[ée]curit[ée]\s+sociale|\bnir\b"
                # Italian codice fiscale + welfare/social-security phrases.
                # `\bcf\b` needs no inline lookahead — the outer `[:#=]`
                # delimiter requirement already gates this short acronym
                # against benign Latin-abbreviation usage like "cf. Tabella".
                r"|codice\s+fiscale|\bcf\b"
                r"|numero\s+di\s+(?:sicurezza|previdenza)\s+sociale"
                # German Steuer-ID + Sozialnummer / Sozialversicherungsnummer
                r"|steuer[\-_\s]?id(?:entifikation(?:s[\-_\s]?nummer)?)?"
                r"|steueridentifikationsnummer|steuernummer"
                r"|sozialnummer|sozialversicherungsnummer|sozialversicherungs[\-_\s]?nummer"
                # Spanish DNI / NIE / "número de seguridad social"
                r"|\bdni\b|\bnie\b|documento\s+(?:nacional\s+)?(?:de\s+)?identi(?:dad|ficativo|ficación)"
                r"|n[uú]mero[\-_\s]+(?:de[\-_\s]+)?seguridad[\-_\s]+social|seguridad[\-_\s]+social"
                # UK NINO
                r"|\bnino\b|national\s+insurance(?:\s+number)?"
                r")"
                # Anchor → value: optional closing-quote / markdown asterisk,
                # optional whitespace, REQUIRED `[:#=]` delimiter, optional
                # opening-quote / markdown asterisk. The required delimiter
                # stops the regex from glomming the value with intervening
                # English prepositions ("Social Security Number is 212…");
                # those cases are caught by the US `regex.ssn` recognizer.
                r"[\"'\*]?\s*[:#=][\s\"'\*]*"
                # Value: alphanumeric + dot/dash/space separators, no
                # newlines, 6–30 chars total. Literal space (no `\s`)
                # prevents newline-greedy capture into the next labeled field.
                # Inner negative lookahead `(?! \- )` forbids the literal
                # space-dash-space field-separator sequence the synthetic
                # corpora use to delimit labeled fields
                # ("…D33 8 - Adresse: …") — dash + space alone in the value
                # class would otherwise let the regex absorb into the next
                # field. Literal `\s` was avoided here to keep the lookahead
                # cost O(1) per character (a `\s+`-quantified lookahead nested
                # inside a `{4,28}` outer quantifier would be super-linear in
                # value length on adversarial inputs).
                r"(?P<value>[A-Za-z0-9](?:(?! \- )[A-Za-z0-9.\- ]){4,28}[A-Za-z0-9])"
                # Stop at whitespace boundary, punctuation, quote, asterisk,
                # or end-of-string.
                r"(?=[\s,;\"'\)\]\}\.\?\!\*]|$)"
            ),
            0.86,
            group="value",
            detector_id="regex.national_id_anchored",
            entity_from_match=_national_id_anchored_entity,
            emits=("NATIONAL_ID", "TAX_ID", "OTHER_STRONG_ID"),
        ),
        PatternRecognizer(
            "BR_CPF",
            re.compile(r"(?<!\d)\d{3}[ .-]?\d{3}[ .-]?\d{3}[ .-]?\d{2}(?!\d)"),
            0.92,
            validator=_cpf_valid,
            detector_id="regex.cpf",
        ),
        # Default-profile PII baseline recognizers. The shipped `default`
        # profile previously had zero coverage for `PERSON`, `ADDRESS`,
        # `DATE_OF_BIRTH`, and `BANK_ACCOUNT`, leaving multilingual /
        # general-PII recall at ~6% on the bundled threat corpora.
        # The four recognizers below catch the structured / semi-structured
        # PII that shows up in real LLM outputs — labeled fields like
        # "First Name:", "Address:", "DOB:", "Account Number:" — without
        # firing on free prose. Each follows the same anchor + explicit
        # `[:#=]` delimiter discipline as `regex.national_id_anchored` and
        # the same `(?! \- )` field-separator lookahead inside the value
        # class. Narrative-style PII without an anchor (e.g. names in chat
        # transcripts, addresses inline in body text) is intentionally out
        # of scope for the regex layer; the `broad-pii-ml` profile's ML
        # detector covers those.
        PatternRecognizer(
            "PERSON",
            re.compile(
                # `(?i:...)` localizes case-insensitivity to the anchor; the
                # value class below stays case-sensitive so bare `Name:` only
                # captures values with a capitalized first letter (rejects
                # benign `File Name: report.pdf`).
                r"\b(?i:(?:"
                # English compound + role-prefixed name labels
                r"(?:first|last|given|family|maiden|middle|full|patient|customer|guest|primary|legal|registered|account|holder|user|student|child|parent|lessee|policyholder|recipient|beneficiary|emergency|contact)[\s_\-]*name(?:[\s_\-]*\d+)?"
                r"|account[\s_\-]+holder(?:[\s_\-]+name)?|emergency[\s_\-]+contact"
                # Snake-case JSON variants
                r"|first[_\-]?name|last[_\-]?name|given[_\-]?names?|family[_\-]?name|firstname|lastname|fullname"
                # Standalone English name-attribution labels
                r"|speaker|host|presenter|attendee|interviewer|interviewee"
                # Bare `name` (FP risk on `Project Name:` / `File Name:`
                # mitigated by capitalized-first-letter value class —
                # lowercase values like `report.pdf` skip the anchor).
                r"|name"
                # Dutch (compound or numbered: `Voornaam 1:`)
                r"|voornaam(?:[\s_]*\d+)?|achternaam|gebruikersnaam|naam(?:[\s_]*\d+)?"
                r"|leerlingnaam|studentnaam"
                # German
                r"|vorname|nachname|familienname"
                # Spanish (compound or labeled)
                r"|nombre(?:[\s_]+completo|[\s_]+y[\s_]+apellidos?)?|apellidos?(?:[\s_]+(?:paterno|materno))?"
                r"|primer[\s_]+apellido|segundo[\s_]+apellido"
                # Italian
                r"|cognome(?:[\s_]+e[\s_]+nome)?"
                # French (compound; bare `nom` skipped — too generic)
                r"|pr[ée]nom|nom[\s_]+(?:de[\s_]+famille|complet)"
                # Honorific/title anchors
                r"|title|titel|titre|titolo|t[ií]tulo"
                r"))"
                # Pre-delimiter: quotes/asterisks for markdown `**Name**:`
                r"[\"'\*]*\s*[:#=][\s\"'\*]*"
                # Value: capitalized first letter + greedy run of
                # letters/dashes/apostrophes/spaces, max 50 chars. `(?! \- )`
                # field-separator lookahead consistent with national-ID
                # recognizer. Case-sensitive (no `(?i)` flag in scope).
                r"([A-ZÀ-ÝŽ](?:(?! \- )[A-Za-zÀ-ÿŽž\-' ]){0,48}[A-Za-zÀ-ÿŽž])"
                r"(?=[\s,;\"'\)\]\}\.\?\!\*]|$)"
            ),
            0.78,
            group=1,
            detector_id="regex.person_anchored",
        ),
        PatternRecognizer(
            "PERSON",
            re.compile(
                r"\b(?i:(?:"
                r"meu\s+nome\s+[eé]\s+"
                r"|sou\s+(?:o\s+|a\s+)?"
                r"|obrigad[ao],\s+"
                r"|entendido,\s+"
                r"|de\s+nada,\s+"
                r"))"
                r"((?:Sr\.?\s+|Sra\.?\s+|Dr\.?\s+|Dra\.?\s+)?"
                r"[A-Z\u00C0-\u00DE][A-Za-z\u00C0-\u024F'-]+"
                r"(?:\s+[A-Z\u00C0-\u00DE][A-Za-z\u00C0-\u024F'-]+){1,3})"
                r"(?=[\s,;\"'\)\]\}\.\?\!]|$)"
            ),
            0.74,
            group=1,
            detector_id="regex.person_portuguese_context",
        ),
        PatternRecognizer(
            "ADDRESS",
            re.compile(
                # `(?<![A-Za-z\-])` before the anchor block is a
                # fixed-width lookbehind that prevents bare `adres` from
                # matching inside `IP-adres` / `E-mailadres` / `webadres`,
                # which Python `\b` cannot do (`-` is a non-word char so `\b`
                # matches between `IP` and `-adres`).
                r"(?<![A-Za-z\-])\b(?i:(?:"
                # English compound forms (bare `address` excluded — collides
                # with `IP address` / `MAC address` / `URL`).
                r"(?:home|business|mailing|delivery|billing|shipping|street|residential|primary|secondary|permanent|physical|postal|work)\s+address"
                r"|street(?:[\s_\-]+(?:name|address))?|street_name"
                # Snake-case JSON variants
                r"|home_?address|street_?address|secondary_?address|primary_?address|billing_?address|mailing_?address|residential_?address"
                # Dutch — lookbehind above protects bare `adres`
                r"|adres|secundair[\s_\-]+adres|hoofd[\s_\-]?adres|woonadres|huisadres"
                # German compound (bare `Adresse` excluded — collides with
                # `IP-Adresse` / `E-Mail-Adresse`).
                r"|hausanschrift|wohnanschrift|postanschrift|wohnort|anschrift"
                # Spanish
                r"|direcci[óo]n(?:[\s_\-]+(?:postal|residencial|de[\s_\-]+entrega|de[\s_\-]+casa))?"
                r"|domicilio(?:[\s_\-]+(?:postal|fiscal))?"
                # Italian
                r"|indirizzo(?:[\s_\-]+(?:di[\s_\-]+casa|postale|di[\s_\-]+residenza|fisico))?"
                # French compound only (bare `adresse` collides with
                # `adresse électronique` / `adresse e-mail`).
                r"|adresse(?:[\s_\-]+(?:postale|de[\s_\-]+r[ée]sidence|domicile|du[\s_\-]+domicile))"
                r"))"
                r"[\"'\*]*\s*[:#=][\s\"'\*]*"
                # Value: alphanumeric + ,/.-/#/'/space, 5–100 chars; literal
                # space (no `\s`) so newlines terminate the value.
                r"([A-Za-z0-9À-ÿ](?:(?! \- )[A-Za-z0-9À-ÿ.,\-#/' ]){4,98}[A-Za-z0-9À-ÿ])"
                r"(?=[\s,;\"'\)\]\}]|$)"
            ),
            0.78,
            group=1,
            detector_id="regex.address_anchored",
        ),
        PatternRecognizer(
            "ADDRESS",
            re.compile(
                r"\b(?:"
                r"Rua|Avenida|Av\.?|Travessa|Alameda|Pra[cç]a|Estrada|Rodovia"
                r"|Conjunto|Condom[ií]nio|Largo|Trecho|Distrito|Loteamento"
                r"|Lagoa|N[uú]cleo|Vila|Ch[aá]cara|Fazenda|S[ií]tio"
                r"|Residencial|Quadra"
                r")\s+"
                r"[A-Za-z0-9\u00C0-\u024F' .-]{2,80},\s*\d{1,6}"
                r"(?:,\s*[A-Za-z0-9\u00C0-\u024F' .-]{2,80}){1,3}"
                r"\s*-\s*[A-Z]{2},\s*\d{5}-?\d{3}\b"
            ),
            0.80,
            detector_id="regex.brazil_address",
        ),
        PatternRecognizer(
            "ADDRESS",
            re.compile(
                r"(?ix)\b(?:"
                # UK outward + inward postcode: SW1A 1AA, EC1A1BB, W1A 0AX.
                r"[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}"
                # Dutch postcode: 1234 AB. Require a space to avoid compact
                # product-code FPs like ABC1234DE.
                r"|\d{4}\s+[A-Z]{2}"
                # Canadian postal code: K1A 0B1.
                r"|[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\s?\d[ABCEGHJ-NPRSTV-Z]\d"
                r")\b"
            ),
            0.82,
            detector_id="regex.address_postcode_shape",
        ),
        PatternRecognizer(
            "DATE_OF_BIRTH",
            re.compile(
                r"(?i)\b(?:"
                r"(?:date[\s_\-]+of[\s_\-]+birth|d\.?o\.?b\.?|birth[\s_\-]?date|birthdate|birthday)"
                r"|date_of_birth|birth_date"
                r"|geboortedatum"
                r"|geburtsdatum|geburtstag"
                r"|fecha[\s_\-]+de[\s_\-]+nacimiento"
                r"|data[\s_\-]+di[\s_\-]+nascita"
                r"|date[\s_\-]+de[\s_\-]+naissance"
                r")"
                r"[\"'\*]*\s*[:#=][\s\"'\*]*"
                # Value: date-like — digits + month-name letters + separators,
                # 4–30 chars total. Literal space (no `\s`) so newlines
                # terminate the value before the next labeled field.
                r"([0-9A-Za-zÀ-ÿ](?:(?! \- )[0-9A-Za-zÀ-ÿ./\-, ]){2,28}[0-9A-Za-zÀ-ÿ])"
                r"(?=[\s,;\"'\)\]\}\.\?\!\*]|$)"
            ),
            0.84,
            group=1,
            detector_id="regex.date_of_birth_anchored",
        ),
        PatternRecognizer(
            "BANK_ACCOUNT",
            re.compile(
                r"(?i)\b(?:"
                r"account[\s_\-]+(?:number|#|no\.?|num\.?)|bank[\s_\-]+account(?:[\s_\-]+number)?"
                r"|routing[\s_\-]+number|aba[\s_\-]+routing"
                r"|kontonummer|bankkonto(?:nummer)?|kontoinhaber"
                r"|n[uú]mero[\s_\-]+de[\s_\-]+cuenta|cuenta[\s_\-]+(?:bancaria|corriente)"
                r"|numero[\s_\-]+di[\s_\-]+conto|conto[\s_\-]+corrente|conto[\s_\-]+bancario"
                r"|rekeningnummer|bankrekening(?:nummer)?"
                r"|num[ée]ro[\s_\-]+de[\s_\-]+compte|compte[\s_\-]+bancaire"
                r")"
                r"[\"'\*]*\s*[:#=][\s\"'\*]*"
                # Value: positive lookahead requires ≥6 digits in capture
                # (rejects "Account: open"); literal-space inner class on
                # the lookahead avoids the bounded-but-real ReDoS exposure
                # `\s` would create on long digit-free values, since `\s` and
                # the outer `{4,28}` would let the engine explore many
                # whitespace-partition states before failing.
                r"((?=(?:[A-Za-z0-9.\- ]*\d){6,})[A-Za-z0-9](?:(?! \- )[A-Za-z0-9.\- ]){4,28}[A-Za-z0-9])"
                r"(?=[\s,;\"'\)\]\}\.\?\!\*]|$)"
            ),
            0.86,
            group=1,
            detector_id="regex.bank_account_anchored",
        ),
        PatternRecognizer(
            "CREDIT_CARD",
            re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
            0.70,
            _luhn_valid,
            detector_id="regex.credit_card_luhn",
        ),
        PatternRecognizer(
            "EMAIL",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            0.94,
            detector_id="regex.email",
            deny_pattern=_email_deny_pattern(),
        ),
        PatternRecognizer(
            "PHONE",
            re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"),
            0.80,
            detector_id="regex.phone",
        ),
        PatternRecognizer(
            "PHONE",
            re.compile(r"(?<!\d)(?:\+55\s*)?\([1-9]{2}\)\s?9?\d{4}[-\s]\d{4}(?!\d)"),
            0.82,
            detector_id="regex.brazil_phone",
        ),
        PatternRecognizer(
            "MRN",
            re.compile(r"(?i)\bMRN[:# ]{0,3}[A-Z0-9-]{5,}\b"),
            0.88,
            detector_id="regex.mrn",
        ),
        PatternRecognizer(
            "IBAN",
            re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
            0.86,
            detector_id="regex.iban",
        ),
    ]


_DEFAULT_EMAIL_DENY_LOCAL_PARTS = (
    "noreply",
    "no-reply",
    "donotreply",
    "do-not-reply",
    "support",
    "info",
    "admin",
    "notifications",
    "postmaster",
    "webmaster",
    "abuse",
    "security",
)
_EMAIL_DENY_ENV_VAR = "LSDF_EMAIL_DENY_LOCAL_PARTS"


def _email_deny_pattern() -> re.Pattern[str]:
    """Compile the EMAIL recognizer's deny anchor.

    Suppresses common transactional / role-account local parts (`noreply@`,
    `support@`, etc.) which are typically not personally identifying. Operators
    can extend the list at deploy time via `LSDF_EMAIL_DENY_LOCAL_PARTS` —
    semicolon-separated, e.g. `LSDF_EMAIL_DENY_LOCAL_PARTS=billing;sales`.

    Operator-supplied entries that contain `@` or whitespace are skipped:
    the deny pattern matches an anchored local-part (`^<part>@`), so an
    entry like `billing@acme` would silently never match. Dropping these
    instead of silently no-op'ing is the safer failure mode — the operator
    sees no suppression and notices, rather than the malformed deny rule
    appearing to be "in effect" but not actually firing.
    """
    raw_extra = os.environ.get(_EMAIL_DENY_ENV_VAR, "").strip()
    extras = tuple(
        piece.strip().lower()
        for piece in raw_extra.split(";")
        if _is_valid_email_deny_local_part(piece)
    )
    parts = _DEFAULT_EMAIL_DENY_LOCAL_PARTS + extras
    alternation = "|".join(re.escape(part) for part in parts)
    return re.compile(rf"(?i)^(?:{alternation})@")


def _is_valid_email_deny_local_part(piece: str) -> bool:
    stripped = piece.strip()
    if not stripped:
        return False
    if "@" in stripped:
        return False
    return not any(char.isspace() for char in stripped)


def _has_context_word(
    text: str,
    start: int,
    end: int,
    context_words: tuple[str, ...],
    window: int,
) -> bool:
    """Return True if any context word appears within ±window chars of [start, end).

    Empty context_words always returns False (caller decides what that means via
    `context_required`/`context_boost`). Comparison is case-insensitive and
    word-boundary anchored so e.g. "labrador" doesn't match "lab".
    """
    if not context_words:
        return False
    left = max(0, start - window)
    right = min(len(text), end + window)
    haystack = text[left:right].lower()
    for word in context_words:
        if not word:
            continue
        needle = word.lower()
        index = haystack.find(needle)
        while index != -1:
            before_ok = index == 0 or not haystack[index - 1].isalnum()
            after = index + len(needle)
            after_ok = after == len(haystack) or not haystack[after].isalnum()
            if before_ok and after_ok:
                return True
            index = haystack.find(needle, index + 1)
    return False


def _nfc_with_offsets(text: str) -> tuple[str, list[int]]:
    normalized = unicodedata.normalize("NFC", text)
    if normalized == text:
        return text, list(range(len(text) + 1))
    output: list[str] = []
    offsets: list[int] = [0]
    idx = 0
    while idx < len(text):
        start = idx
        idx += 1
        while idx < len(text) and unicodedata.combining(text[idx]):
            idx += 1
        cluster = unicodedata.normalize("NFC", text[start:idx])
        output.append(cluster)
        for _ in cluster:
            offsets.append(idx)
    return "".join(output), offsets


def _luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _cpf_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if len(digits) != 11:
        return False
    if len(set(digits)) == 1:
        return False
    for check_idx, weight_start in ((9, 10), (10, 11)):
        total = sum(digits[idx] * (weight_start - idx) for idx in range(check_idx))
        expected = (total * 10) % 11
        if expected == 10:
            expected = 0
        if digits[check_idx] != expected:
            return False
    return True


def _not_placeholder_secret(value: str) -> bool:
    cleaned = value.strip("`'\";,")
    if cleaned.startswith(("process.env.", "os.environ", "env.")):
        return False
    if re.fullmatch(r"[A-Z][A-Z0-9_]{5,}", cleaned):
        return False
    if cleaned.lower() in _BENIGN_AUTH_CONFIG_VALUES:
        return False
    return True


def _secret_assignment_entity(match: re.Match[str]) -> str:
    label = _normalise_label(match.group("label"))
    if "api key" in label:
        return "API_KEY"
    if label in {"password", "passphrase"}:
        return "PASSWORD"
    if label == "bearer":
        return "BEARER_TOKEN"
    if label == "private key":
        return "PRIVATE_KEY"
    return "OTHER_SECRET"


def _national_id_anchored_entity(match: re.Match[str]) -> str:
    label = _normalise_label(match.group("label"))
    if label in {"codice fiscale", "cf"} or label.startswith("steuer"):
        return "TAX_ID"
    national_id_markers = (
        "bsn",
        "burgerservicenummer",
        "sofinummer",
        "nir",
        "insee",
        "dni",
        "nie",
        "documento",
        "nino",
        "national insurance",
    )
    if any(marker in label for marker in national_id_markers):
        return "NATIONAL_ID"
    return "OTHER_STRONG_ID"


def _normalise_label(label: str) -> str:
    decomposed = unicodedata.normalize("NFKD", label)
    ascii_label = "".join(char for char in decomposed if not unicodedata.combining(char))
    return re.sub(r"[_\-\s]+", " ", ascii_label.lower()).strip()


# Common HTTP-auth / PAM / sshd config values that the widened
# `regex.secret_assignment` keyword set would otherwise match — e.g.
# `auth = required` in /etc/pam.d/sshd or `auth = digest` in nginx config.
# These are RFC-defined enums, not secrets. Lowercased for comparison.
_BENIGN_AUTH_CONFIG_VALUES = frozenset(
    {
        "required",
        "requisite",
        "sufficient",
        "optional",
        "include",
        "substack",
        "basic",
        "digest",
        "bearer",
        "negotiate",
        "ntlm",
        "kerberos",
        "gssapi",
        "oauth",
        "anonymous",
    }
)


_JWT_IDENTITY_CLAIMS = ("email", "sub", "aud", "iss")


_JWT_PAYLOAD_MAX_CHARS = 8192


def _jwt_payload_has_identity_claim(value: str) -> bool:
    """Decode a JWT payload and require an identity-bearing claim.

    Drops the false-positive load on long base64 strings that happen to match
    the eyJ regex shape. Service tokens whose payload only carries `exp`/`iat`
    are deliberately dropped here — this detector is for identity leakage.
    Caps the decoded segment length to prevent CPU/memory pressure if a hostile
    LLM response embeds a multi-MB base64 blob that matches the JWT shape.
    """
    parts = value.split(".")
    if len(parts) != 3:
        return False
    payload_segment = parts[1]
    if len(payload_segment) > _JWT_PAYLOAD_MAX_CHARS:
        return False
    padding = "=" * (-len(payload_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_segment + padding)
    except (binascii.Error, ValueError):
        return False
    try:
        claims = json.loads(decoded.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(claims, dict):
        return False
    return any(claim in claims for claim in _JWT_IDENTITY_CLAIMS)
