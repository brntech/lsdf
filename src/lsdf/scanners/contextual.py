# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
import re

from ..surfaces import Surface
from ..types import Finding


@dataclass(frozen=True)
class ContextPattern:
    entity: str
    detector_id: str
    labels: tuple[str, ...]
    value_pattern: str
    confidence: float = 0.74


class _ContextualPatternScanner:
    detector_id = "contextual"
    detector_family = "contextual"
    default_patterns: tuple[ContextPattern, ...] = ()
    include_inline_xml = False
    include_output_shapes = False
    extra_entities: frozenset[str] = frozenset()

    def __init__(self, patterns: tuple[ContextPattern, ...] | None = None):
        self.patterns = patterns or self.default_patterns
        self.entities = frozenset(pattern.entity for pattern in self.patterns) | self.extra_entities

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in self.patterns:
            for regex in _compiled_patterns(pattern):
                for match in regex.finditer(surface.value):
                    start = match.start("value")
                    end = match.end("value")
                    start, end = _trim_span(surface.value, start, end)
                    if start >= end:
                        continue
                    value = surface.value[start:end]
                    if _is_placeholder(value):
                        continue
                    findings.append(
                        Finding(
                            entity=pattern.entity,
                            surface=surface.name,
                            pointer=surface.pointer,
                            start=start,
                            end=end,
                            value=value,
                            confidence=pattern.confidence,
                            json_pointer=surface.json_pointer,
                            detector_id=pattern.detector_id,
                            detector_family=self.detector_family,
                            metadata={"specificity": 74},
                        )
                    )
        if self.include_inline_xml:
            findings.extend(_inline_xml_findings(surface, self.detector_family))
        if self.include_output_shapes:
            findings.extend(_output_shape_findings(surface, self.detector_family))
        return _resolve_contextual_overlaps(findings)


class ContextualAnchoredScanner(_ContextualPatternScanner):
    detector_id = "contextual-anchored"
    detector_family = "contextual-anchored"
    include_inline_xml = True
    default_patterns = ()
    extra_entities = frozenset({"EMAIL", "PHONE", "PASSPORT", "DRIVER_LICENSE"})


class ContextualBroadScanner(_ContextualPatternScanner):
    detector_id = "contextual-broad"
    detector_family = "contextual-broad"
    include_output_shapes = True
    default_patterns = ()
    extra_entities = frozenset({"ADDRESS", "DATE_OF_BIRTH", "PHONE", "OTHER_STRONG_ID", "PERSON"})


class ContextualPIIScanner(ContextualBroadScanner):
    """Compatibility alias for the old scanner class name.

    The v0.2 detector family is `contextual-broad`; the old `contextual-pii`
    family is intentionally not kept as a policy alias.
    """


FIELD_VALUE = r"[^\r\n<>{}\[\]]{1,96}"
TOKEN_VALUE = r"[A-Za-z0-9][A-Za-z0-9._@:+/#%?=&;,\\\- ]{0,94}"
NAME_VALUE = r"[A-ZÀ-ÝŽ][A-Za-zÀ-ÿŽž' .\-]{0,70}"


ANCHORED_PATTERNS = (
    ContextPattern(
        "PASSPORT",
        "contextual.identity_document.passport",
        ("passport", "pasaporte"),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "DRIVER_LICENSE",
        "contextual.identity_document.driver_license",
        ("driver license", "driver_license", "rijbewijsnummer"),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "NATIONAL_ID",
        "contextual.identity_document.national_id",
        (
            "id card number",
            "id-cardnumber",
            "identity card number",
            "identiteitskaartnummer",
            "id-kaartnummer",
            "numero de identificacion",
            "número de identificación",
            "nÃºmero de identificaciÃ³n",
            "codice_di_identita",
        ),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "STUDENT_ID",
        "contextual.identity_document.student_id",
        ("student id",),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "EMPLOYEE_ID",
        "contextual.identity_document.employee_id",
        ("employee id",),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "CUSTOMER_ID",
        "contextual.identity_document.customer_id",
        ("customer id",),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "USER_ID",
        "contextual.identity_document.user_id",
        ("user id",),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "LICENSE_PLATE",
        "contextual.identity_document.license_plate",
        ("license plate",),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "PASSWORD",
        "contextual.secret_field.password",
        ("password", "pass"),
        r"[^\s\r\n<>{}\[\]]{3,96}",
        0.82,
    ),
    ContextPattern(
        "API_KEY",
        "contextual.secret_field.api_key",
        ("api key",),
        r"[^\s\r\n<>{}\[\]]{3,96}",
        0.82,
    ),
    ContextPattern(
        "BEARER_TOKEN",
        "contextual.secret_field.bearer_token",
        ("token",),
        r"[^\s\r\n<>{}\[\]]{3,96}",
        0.82,
    ),
    ContextPattern(
        "OTHER_STRONG_ID",
        "contextual.identity_document.strong_id",
        (
            "id card number",
            "id-cardnumber",
            "identity card number",
            "identiteitskaartnummer",
            "id-kaartnummer",
            "numero de identificacion",
            "número de identificación",
            "codice_di_identita",
            "socialnumber",
            "social number",
        ),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "OTHER_INTERNAL_ID",
        "contextual.identity_document.internal_id",
        (
            "form id",
            "certificate/license number",
            "certificate license number",
            "certificate number",
        ),
        TOKEN_VALUE,
        0.80,
    ),
    ContextPattern(
        "OTHER_SECRET",
        "contextual.secret_field.other",
        ("pin", "http cookie", "cookie"),
        r"[^\s\r\n<>{}\[\]]{3,96}",
        0.82,
    ),
)


BROAD_PATTERNS = (
    ContextPattern(
        "PERSON",
        "contextual.person_field",
        (
            "first name",
            "last name",
            "full name",
            "given name",
            "surname",
            "voornaam",
            "nachname",
            "vorname",
            "name_id",
            "speaker",
            "usuario",
            "company name",
            "company",
            "occupation",
            "job title",
            "employment status",
            "education level",
            "language",
            "title",
            "titulo",
            "título",
            "titolo",
        ),
        FIELD_VALUE,
        0.68,
    ),
    ContextPattern(
        "ADDRESS",
        "contextual.location_field",
        (
            "street address",
            "street",
            "building",
            "city",
            "state",
            "county",
            "country",
            "postcode",
            "postal code",
            "zip",
            "coordinate",
            "geo coordinate",
            "latitude",
            "longitude",
            "secaddress",
        ),
        FIELD_VALUE,
        0.74,
    ),
    ContextPattern(
        "DATE_OF_BIRTH",
        "contextual.date_time_field",
        (
            "date of birth",
            "birth date",
            "dob",
            "bod",
            "date",
            "datum",
            "data",
            "fecha",
            "time",
            "hora",
            "timing",
            "date and time",
            "date_time",
            "age",
        ),
        r"[A-Za-z0-9][A-Za-z0-9 .:/,\-]{0,44}",
        0.72,
    ),
    ContextPattern(
        "OTHER_PHI",
        "contextual.demographic_field",
        (
            "sex",
            "gender",
            "geslacht",
            "sesso",
            "sexo",
            "race",
            "ethnicity",
            "race ethnicity",
            "sexuality",
            "religious belief",
            "religion",
            "political view",
            "marital status",
        ),
        FIELD_VALUE,
        0.70,
    ),
    ContextPattern(
        "BLOOD_TYPE",
        "contextual.blood_type_field",
        ("blood type",),
        FIELD_VALUE,
        0.70,
    ),
)

ContextualAnchoredScanner.default_patterns = ANCHORED_PATTERNS
ContextualAnchoredScanner.extra_entities = frozenset(
    {
        "API_KEY",
        "BEARER_TOKEN",
        "DRIVER_LICENSE",
        "EMAIL",
        "EMPLOYEE_ID",
        "CUSTOMER_ID",
        "LICENSE_PLATE",
        "NATIONAL_ID",
        "OTHER_INTERNAL_ID",
        "OTHER_SECRET",
        "OTHER_STRONG_ID",
        "PASSPORT",
        "PASSWORD",
        "PHONE",
        "STUDENT_ID",
        "USER_ID",
    }
)
ContextualBroadScanner.default_patterns = BROAD_PATTERNS
ContextualBroadScanner.extra_entities = frozenset(
    {"ADDRESS", "BLOOD_TYPE", "DATE_OF_BIRTH", "PHONE", "OTHER_STRONG_ID", "PERSON", "OTHER_PHI"}
)


def _compiled_patterns(pattern: ContextPattern) -> tuple[re.Pattern[str], ...]:
    label = "|".join(re.escape(item) for item in pattern.labels)
    value = pattern.value_pattern
    return (
        re.compile(
            rf"(?im)(?<![A-Za-z])(?:{label})(?![A-Za-z])"
            rf"(?:\s*\([^)\r\n]{{0,40}}\))?\s*[:=]\s*"
            rf"[\*\"']?(?P<value>{value})",
        ),
        re.compile(
            rf"(?im)<(?:[^>]*\b(?:{label})\b[^>]*)>"
            rf"\s*(?P<value>{value})\s*</[^>]+>",
        ),
        re.compile(
            rf"(?im)(?:{label})\((?P<value>{value})\)",
        ),
    )


def _inline_xml_findings(surface: Surface, detector_family: str) -> list[Finding]:
    tag_map = {
        "driver_license": "DRIVER_LICENSE",
        "passport": "PASSPORT",
        "email": "EMAIL",
        "tel": "PHONE",
        "phone": "PHONE",
    }
    findings: list[Finding] = []
    for match in re.finditer(
        r"(?is)<(?P<tag>driver_license|passport|email|tel|phone)>"
        r"\s*(?P<value>[^<]{1,96})\s*</(?P=tag)>",
        surface.value,
    ):
        start = match.start("value")
        end = match.end("value")
        start, end = _trim_span(surface.value, start, end)
        if start >= end:
            continue
        tag = match.group("tag").lower()
        findings.append(
            Finding(
                entity=tag_map[tag],
                surface=surface.name,
                pointer=surface.pointer,
                start=start,
                end=end,
                value=surface.value[start:end],
                confidence=0.82,
                json_pointer=surface.json_pointer,
                detector_id=f"contextual.xml_{tag}",
                detector_family=detector_family,
                metadata={"specificity": 76},
            )
        )
    return findings


OUTPUT_SHAPE_PATTERNS: tuple[tuple[str, str, re.Pattern[str], float], ...] = (
    (
        "ADDRESS",
        "contextual.url_shape",
        re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\]\"')]+"),
        0.72,
    ),
    (
        "ADDRESS",
        "contextual.ipv4_shape",
        re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        0.76,
    ),
    (
        "ADDRESS",
        "contextual.ipv6_shape",
        re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
        0.74,
    ),
    (
        "ADDRESS",
        "contextual.geo_coordinate",
        re.compile(r"(?<!\w)\[?-?\d{1,2}\.\d{2,6}\s*,\s*-?\d{1,3}\.\d{2,6}\]?(?!\w)"),
        0.74,
    ),
    (
        "ADDRESS",
        "contextual.building_unit",
        re.compile(r"(?i)\b(?:Flat|Block|Pod|Ranch|Quadruplex|Section)\s+\d{1,5}\b"),
        0.70,
    ),
    (
        "DATE_OF_BIRTH",
        "contextual.date_shape",
        re.compile(
            r"(?i)\b(?:"
            r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2})?|"
            r"\d{1,2}/\d{1,2}/\d{2,4}|"
            r"\d{1,2}[/-](?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|"
            r"januari|februari|maart|april|mei|juni|juli|augustus|september|oktober|november|december|"
            r"janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre|"
            r"januar|februar|märz|maerz|april|mai|juni|juli|august|september|oktober|november|dezember|"
            r"gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre|"
            r"enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)"
            r"[/-]?\d{0,4}|"
            r"\d{1,2}(?:e|º|st|nd|rd|th)?\s+"
            r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|januari|februari|maart|april|mei|juni|juli|"
            r"janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|januar|februar|märz|maerz|"
            r"gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|enero|febrero|marzo|abril|mayo|junio|julio)"
            r"\s+\d{4}|"
            r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|januari|februari|maart|april|mei|juni|juli|"
            r"janvier|février|fevrier|mars|avril|mai|juin|juillet|août|aout|januar|februar|märz|maerz|"
            r"gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|enero|febrero|marzo|abril|mayo|junio|julio)"
            r"(?:/|\s+)\d{2,4}"
            r")\b"
        ),
        0.70,
    ),
    (
        "DATE_OF_BIRTH",
        "contextual.time_shape",
        re.compile(r"(?i)\b\d{1,2}(?::\d{2}){1,2}(?:\s?[AP]M)?\b|\b\d{1,2}h\b"),
        0.66,
    ),
    (
        "PHONE",
        "contextual.international_phone_shape",
        re.compile(r"(?<!\w)\+\d{2,3}\d{2,4}[ .-]\d{3}[ .-]\d{3,4}(?!\w)"),
        0.74,
    ),
    (
        "OTHER_STRONG_ID",
        "contextual.strong_identifier_shape",
        re.compile(r"\b(?=[A-Z0-9-]{6,28}\b)(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9][A-Z0-9-]{4,26}[A-Z0-9]\b"),
        0.70,
    ),
    (
        "PERSON",
        "contextual.username_shape",
        re.compile(r"\b(?:\d{2}[a-z][a-z0-9._-]{3,28}|[a-z][a-z0-9._-]{3,24}\d{2,})\b"),
        0.64,
    ),
)


def _resolve_contextual_overlaps(findings: list[Finding]) -> list[Finding]:
    by_span: dict[tuple[tuple[str | int, ...], tuple[str | int, ...] | None, int, int, str], Finding] = {}
    order: list[tuple[tuple[str | int, ...], tuple[str | int, ...] | None, int, int, str]] = []
    for finding in findings:
        key = (
            finding.pointer,
            finding.json_pointer,
            finding.start,
            finding.end,
            finding.value,
        )
        if key not in by_span:
            by_span[key] = finding
            order.append(key)
            continue
        if _contextual_entity_rank(finding.entity) > _contextual_entity_rank(by_span[key].entity):
            by_span[key] = finding
    return [by_span[key] for key in order]


def _contextual_entity_rank(entity: str) -> int:
    if entity.startswith("OTHER_"):
        return 0
    return 1


def _output_shape_findings(surface: Surface, detector_family: str) -> list[Finding]:
    if surface.name != "output.content":
        return []
    findings: list[Finding] = []
    for entity, detector_id, pattern, confidence in OUTPUT_SHAPE_PATTERNS:
        for match in pattern.finditer(surface.value):
            start, end = _trim_span(surface.value, match.start(), match.end())
            if start >= end:
                continue
            value = surface.value[start:end]
            if _is_placeholder(value):
                continue
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
                    detector_id=detector_id,
                    detector_family=detector_family,
                    metadata={"specificity": 62},
                )
            )
    return findings


def _trim_span(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start] in " \t\r\n*'\"`:_-":
        start += 1
    while end > start and text[end - 1] in " \t\r\n*'\"`,;.)]}`":
        end -= 1
    return start, end


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered or lowered in {"______________________", "n/a", "none", "unknown"}:
        return True
    return "placeholder" in lowered or "process.env" in lowered
