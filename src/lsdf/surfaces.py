# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Surface:
    name: str
    pointer: tuple[str | int, ...]
    value: str
    json_pointer: tuple[str | int, ...] | None = None
    # Routing fields such as a top-level OpenAI `model` identifier are still
    # scanned by normal recognizers, but supplementary heuristics may use this
    # narrow context marker to avoid treating a provider model name as a
    # credential.  It is intentionally not inferred from arbitrary text.
    routing_metadata: bool = False


def extract_surfaces(
    payload: Any,
    *,
    unknown_surface: str = "input.messages",
) -> list[Surface]:
    surfaces: list[Surface] = []
    if isinstance(payload, dict):
        _extract_openai_request(payload, surfaces)
        _extract_openai_response(payload, surfaces)
    claimed = {surface.pointer for surface in surfaces}
    _walk_unknown(payload, (), surfaces, claimed, unknown_surface)
    return _dedupe_surfaces(surfaces)


def _extract_openai_request(payload: dict[str, Any], surfaces: list[Surface]) -> None:
    for idx, message in enumerate(payload.get("messages", [])):
        if not isinstance(message, dict):
            continue
        role = message.get("role", "user")
        surface_name = {
            "system": "input.system",
            "developer": "input.developer",
            "tool": "input.tool_results",
        }.get(role, "input.messages")
        _append_content_surfaces(
            surfaces,
            surface_name,
            ("messages", idx, "content"),
            message.get("content"),
        )
        for call_idx, tool_call in enumerate(message.get("tool_calls", []) or []):
            _append_tool_call_argument_surfaces(
                surfaces,
                "output.tool_calls.arguments",
                (
                    "messages",
                    idx,
                    "tool_calls",
                    call_idx,
                    "function",
                    "arguments",
                ),
                tool_call,
            )
    for idx, chunk in enumerate(payload.get("rag_context", [])):
        _append_content_surfaces(surfaces, "input.rag_context", ("rag_context", idx), chunk)


def _extract_openai_response(payload: dict[str, Any], surfaces: list[Surface]) -> None:
    for choice_idx, choice in enumerate(payload.get("choices", [])):
        if not isinstance(choice, dict):
            continue
        for field in ("reasoning", "reasoning_content", "reasoning_details"):
            _append_content_surfaces(
                surfaces,
                "output.reasoning",
                ("choices", choice_idx, field),
                choice.get(field),
            )
        message = choice.get("message", {})
        if isinstance(message, dict):
            _append_content_surfaces(
                surfaces,
                "output.content",
                ("choices", choice_idx, "message", "content"),
                message.get("content"),
            )
            for field in ("reasoning", "reasoning_content", "reasoning_details"):
                _append_content_surfaces(
                    surfaces,
                    "output.reasoning",
                    ("choices", choice_idx, "message", field),
                    message.get(field),
                )
            for call_idx, tool_call in enumerate(message.get("tool_calls", []) or []):
                _append_tool_call_argument_surfaces(
                    surfaces,
                    "output.tool_calls.arguments",
                    (
                        "choices",
                        choice_idx,
                        "message",
                        "tool_calls",
                        call_idx,
                        "function",
                        "arguments",
                    ),
                    tool_call,
                )
    _extract_trace_payloads(payload, surfaces)


def _extract_trace_payloads(payload: dict[str, Any], surfaces: list[Surface]) -> None:
    for key in ("trace", "traces", "logs", "spans", "transcript"):
        if key in payload:
            _walk_named_surface(payload[key], (key,), "logs.traces", surfaces)


def _append_content_surfaces(
    surfaces: list[Surface],
    name: str,
    pointer: tuple[str | int, ...],
    content: Any,
    parse_json_string: bool = False,
) -> None:
    if isinstance(content, str):
        if parse_json_string and _append_json_string_surfaces(surfaces, name, pointer, content):
            return
        surfaces.append(Surface(name=name, pointer=pointer, value=content))
    elif content is not None:
        _walk_structured_content_surfaces(content, pointer, (), name, surfaces)


def _append_tool_call_argument_surfaces(
    surfaces: list[Surface],
    name: str,
    pointer: tuple[str | int, ...],
    tool_call: Any,
) -> None:
    function = tool_call.get("function", {}) if isinstance(tool_call, dict) else {}
    arguments = function.get("arguments") if isinstance(function, dict) else None
    _append_content_surfaces(surfaces, name, pointer, arguments, parse_json_string=True)


def _append_json_string_surfaces(
    surfaces: list[Surface],
    name: str,
    pointer: tuple[str | int, ...],
    content: str,
) -> bool:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return False
    before = len(surfaces)
    _walk_json_argument_surfaces(parsed, pointer, (), name, surfaces)
    return len(surfaces) > before


def _walk_json_argument_surfaces(
    payload: Any,
    pointer: tuple[str | int, ...],
    json_pointer: tuple[str | int, ...],
    name: str,
    surfaces: list[Surface],
) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            _walk_json_argument_surfaces(value, pointer, (*json_pointer, key), name, surfaces)
    elif isinstance(payload, list):
        for idx, value in enumerate(payload):
            _walk_json_argument_surfaces(value, pointer, (*json_pointer, idx), name, surfaces)
    elif isinstance(payload, (str, int, float, bool)) and payload is not None:
        surfaces.append(
            Surface(name=name, pointer=pointer, value=str(payload), json_pointer=json_pointer)
        )


def _walk_structured_content_surfaces(
    payload: Any,
    pointer: tuple[str | int, ...],
    json_pointer: tuple[str | int, ...],
    name: str,
    surfaces: list[Surface],
) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            _walk_structured_content_surfaces(value, (*pointer, key), (), name, surfaces)
    elif isinstance(payload, list):
        for idx, value in enumerate(payload):
            _walk_structured_content_surfaces(value, (*pointer, idx), (), name, surfaces)
    elif isinstance(payload, str):
        surfaces.append(Surface(name=name, pointer=pointer, value=payload, json_pointer=json_pointer or None))
    elif payload is not None and not isinstance(payload, bool):
        surfaces.append(Surface(name=name, pointer=pointer, value=str(payload), json_pointer=json_pointer or None))


def _walk_unknown(
    payload: Any,
    pointer: tuple[str | int, ...],
    surfaces: list[Surface],
    claimed: set[tuple[str | int, ...]],
    unknown_surface: str,
) -> None:
    if pointer in claimed:
        return
    if isinstance(payload, dict):
        for key, value in payload.items():
            child_pointer = (*pointer, key)
            chat_envelope = isinstance(payload, dict) and (
                isinstance(payload.get("messages"), list)
                or isinstance(payload.get("choices"), list)
            )
            if not pointer and chat_envelope and key == "model" and isinstance(value, str):
                surfaces.append(
                    Surface(
                        name=unknown_surface,
                        pointer=child_pointer,
                        value=value,
                        routing_metadata=True,
                    )
                )
                continue
            _walk_unknown(value, child_pointer, surfaces, claimed, unknown_surface)
    elif isinstance(payload, list):
        for idx, value in enumerate(payload):
            _walk_unknown(value, (*pointer, idx), surfaces, claimed, unknown_surface)
    elif isinstance(payload, str):
        surfaces.append(Surface(name=unknown_surface, pointer=pointer, value=payload))
    elif isinstance(payload, (int, float, bool)) and payload is not None:
        surfaces.append(Surface(name=unknown_surface, pointer=pointer, value=str(payload)))


def _walk_named_surface(
    payload: Any,
    pointer: tuple[str | int, ...],
    name: str,
    surfaces: list[Surface],
) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            _walk_named_surface(value, (*pointer, key), name, surfaces)
    elif isinstance(payload, list):
        for idx, value in enumerate(payload):
            _walk_named_surface(value, (*pointer, idx), name, surfaces)
    elif isinstance(payload, str):
        surfaces.append(Surface(name=name, pointer=pointer, value=payload))
    elif isinstance(payload, (int, float, bool)) and payload is not None:
        surfaces.append(Surface(name=name, pointer=pointer, value=str(payload)))


def _dedupe_surfaces(surfaces: list[Surface]) -> list[Surface]:
    seen: set[tuple[tuple[str | int, ...], tuple[str | int, ...] | None, str]] = set()
    deduped: list[Surface] = []
    for surface in surfaces:
        key = (surface.pointer, surface.json_pointer, surface.name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(surface)
    return deduped
