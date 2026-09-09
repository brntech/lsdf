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
    # Correlation fields such as OpenAI tool-call IDs are still scanned by
    # normal recognizers, but supplementary heuristics may use this narrow
    # context marker to avoid treating a provider correlation token as a
    # credential.  It is intentionally not inferred from arbitrary text.
    correlation_metadata: bool = False
    # The root `id` of a structurally valid OpenAI response envelope has a
    # narrow context marker for supplementary response-ID heuristics.  The
    # value is still scanned by normal recognizers; only the exact accepted
    # response-ID grammar may use this marker.
    response_id_metadata: bool = False
    # JSON object member names are scanned as independent argument surfaces.
    # Keep a static ordinal pointer for raw-safe findings; the original
    # member path remains available on value surfaces for internal transforms.
    argument_key_metadata: bool = False
    safe_json_pointer: tuple[str | int, ...] | None = None
    # Only a root response fingerprint gets this context. All detectors still
    # inspect the value; the entropy scanner additionally requires its narrow
    # generated-provider-version grammar before suppressing that heuristic.
    provider_version_metadata: bool = False


def extract_surfaces(
    payload: Any,
    *,
    unknown_surface: str = "input.messages",
) -> list[Surface]:
    surfaces: list[Surface] = []
    if isinstance(payload, dict):
        _extract_openai_request(payload, surfaces, unknown_surface)
        _extract_openai_response(payload, surfaces, unknown_surface)
    claimed = {surface.pointer for surface in surfaces}
    _walk_unknown(payload, (), surfaces, claimed, unknown_surface)
    return _dedupe_surfaces(surfaces)


def extract_response_content_surfaces(
    payload: Any,
    *,
    unknown_surface: str = "output.content",
) -> list[Surface]:
    """Extract only response content surfaces handled by the normal path.

    Gateway response inspection uses this narrow extractor alongside the
    response-metadata preflight.  Keeping the two surface sets separate lets
    the gateway retain normal content transforms without rescanning or
    transforming response metadata.  Trace/log payloads are deliberately left
    to the metadata path, where their existing ``logs.traces`` classification
    can be retained without mutating opaque metadata.
    """

    surfaces: list[Surface] = []
    if isinstance(payload, dict):
        _extract_openai_response(payload, surfaces, unknown_surface)
    owned_pointers = response_content_pointers(payload)
    return _dedupe_surfaces(
        surface
        for surface in surfaces
        if surface.pointer in owned_pointers
        and surface.name in {
            "output.content",
            "output.reasoning",
            "output.tool_calls.arguments",
        }
        and not surface.response_id_metadata
        and not surface.correlation_metadata
        and not surface.routing_metadata
    )


def response_content_pointers(
    payload: Any,
    *,
    streaming: bool = False,
) -> set[tuple[str | int, ...]]:
    """Return exact response fields inspected by the normal content path.

    Metadata preflight callers pass these pointers to
    :func:`extract_response_metadata_surfaces`.  Only exact known fields are
    excluded; nested extension values named ``content`` or ``arguments`` are
    still inspected as metadata.
    """

    if not isinstance(payload, dict) or not isinstance(payload.get("choices"), list):
        return set()
    pointers: set[tuple[str | int, ...]] = set()
    for choice_idx, choice in enumerate(payload["choices"]):
        if not isinstance(choice, dict):
            continue
        if streaming:
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            for field in ("content", "reasoning", "reasoning_content", "reasoning_details"):
                if isinstance(delta.get(field), str):
                    pointers.add(("choices", choice_idx, "delta", field))
            tool_calls = delta.get("tool_calls")
            if isinstance(tool_calls, list):
                for call_idx, tool_call in enumerate(tool_calls):
                    if not isinstance(tool_call, dict):
                        continue
                    function = tool_call.get("function")
                    if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                        pointers.add(
                            (
                                "choices",
                                choice_idx,
                                "delta",
                                "tool_calls",
                                call_idx,
                                "function",
                                "arguments",
                            )
                        )
            continue

        for field in ("reasoning", "reasoning_content", "reasoning_details"):
            if isinstance(choice.get(field), str):
                pointers.add(("choices", choice_idx, field))
        message = choice.get("message")
        if not isinstance(message, dict):
            continue
        if isinstance(message.get("content"), str):
            pointers.add(("choices", choice_idx, "message", "content"))
        for field in ("reasoning", "reasoning_content", "reasoning_details"):
            if isinstance(message.get(field), str):
                pointers.add(("choices", choice_idx, "message", field))
        tool_calls = message.get("tool_calls")
        if isinstance(tool_calls, list):
            for call_idx, tool_call in enumerate(tool_calls):
                if not isinstance(tool_call, dict):
                    continue
                function = tool_call.get("function")
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    pointers.add(
                        (
                            "choices",
                            choice_idx,
                            "message",
                            "tool_calls",
                            call_idx,
                            "function",
                            "arguments",
                        )
                    )
    return pointers


def extract_response_metadata_surfaces(
    payload: Any,
    *,
    unknown_surface: str = "output.content",
    excluded_pointers: set[tuple[str | int, ...]] | None = None,
    validated_tool_context: set[tuple[int, int]] | None = None,
    pointer_prefix: tuple[str | int, ...] = ("response_metadata",),
) -> list[Surface]:
    """Extract response metadata values and unknown key names safely.

    Each metadata finding receives a static ``("response_metadata", index)``
    pointer.  The original key is represented only as a scanned value, so a
    hostile JSON key cannot appear in an audit pointer.  The caller never uses
    these surfaces for payload transformation.

    ``excluded_pointers`` must contain only exact normal content fields.  A
    subtree is skipped only below one of those exact fields; arbitrary
    extension keys are traversed and scanned.  ``validated_tool_context`` is
    used by streaming callers to preserve the narrow existing tool-ID
    correlation exception across deltas.
    """

    excluded = excluded_pointers or set()
    validated = validated_tool_context or set()
    surfaces: list[Surface] = []
    metadata_index = 0
    response_envelope = _is_response_envelope(payload)
    routing_envelope = _is_chat_envelope(payload)

    def append_value(
        value: Any,
        pointer: tuple[str | int, ...],
        *,
        response_id: bool = False,
        routing: bool = False,
        correlation: bool = False,
        provider_version: bool = False,
        surface_name: str | None = None,
    ) -> None:
        nonlocal metadata_index
        if isinstance(value, str):
            surfaces.append(
                Surface(
                    name=surface_name or _metadata_surface_name(pointer, unknown_surface),
                    pointer=(*pointer_prefix, metadata_index),
                    value=value,
                    response_id_metadata=response_id,
                    routing_metadata=routing,
                    correlation_metadata=correlation,
                    provider_version_metadata=provider_version,
                )
            )
            metadata_index += 1
        elif isinstance(value, (int, float, bool)) and value is not None:
            surfaces.append(
                Surface(
                    name=surface_name or _metadata_surface_name(pointer, unknown_surface),
                    pointer=(*pointer_prefix, metadata_index),
                    value=str(value),
                    response_id_metadata=False,
                    routing_metadata=False,
                    correlation_metadata=False,
                )
            )
            metadata_index += 1

    def walk(value: Any, pointer: tuple[str | int, ...]) -> None:
        if _pointer_excluded(pointer, excluded):
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_pointer = (*pointer, key)
                if _pointer_excluded(child_pointer, excluded):
                    continue
                key_surface_name = _metadata_surface_name(child_pointer, unknown_surface)
                if (
                    isinstance(key, str)
                    and key not in _KNOWN_STRUCTURAL_KEYS
                    and not (response_envelope and child_pointer == ("prompt_token_ids",))
                ):
                    append_value(key, child_pointer, surface_name=key_surface_name)
                if (
                    isinstance(child, str)
                    and child_pointer == ("id",)
                    and response_envelope
                ):
                    append_value(child, child_pointer, response_id=True, surface_name=key_surface_name)
                elif (
                    isinstance(child, str)
                    and child_pointer == ("system_fingerprint",)
                    and response_envelope
                ):
                    append_value(child, child_pointer, provider_version=True, surface_name=key_surface_name)
                elif (
                    isinstance(child, str)
                    and child_pointer == ("model",)
                    and routing_envelope
                ):
                    append_value(child, child_pointer, routing=True, surface_name=key_surface_name)
                elif (
                    isinstance(child, str)
                    and child_pointer == ("object",)
                    and child in {"chat.completion", "chat.completion.chunk"}
                ):
                    # These fixed protocol labels are structural routing
                    # values.  Mark only the exact labels; arbitrary object
                    # values remain ordinary metadata.
                    append_value(child, child_pointer, routing=True, surface_name=key_surface_name)
                elif isinstance(child, str) and _is_response_tool_id_pointer(
                    payload, child_pointer, validated
                ):
                    append_value(child, child_pointer, correlation=True, surface_name=key_surface_name)
                else:
                    walk(child, child_pointer)
            return
        if isinstance(value, list):
            for idx, child in enumerate(value):
                walk(child, (*pointer, idx))
            return
        append_value(value, pointer)

    walk(payload, ())
    return _dedupe_surfaces(surfaces)


def _is_response_envelope(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and "messages" not in payload
        and isinstance(payload.get("choices"), list)
        and payload.get("object") in {"chat.completion", "chat.completion.chunk"}
    )


def _is_chat_envelope(payload: Any) -> bool:
    return isinstance(payload, dict) and (
        isinstance(payload.get("messages"), list)
        or isinstance(payload.get("choices"), list)
    )


def _pointer_excluded(
    pointer: tuple[str | int, ...],
    excluded: set[tuple[str | int, ...]],
) -> bool:
    return any(
        len(pointer) >= len(candidate) and pointer[: len(candidate)] == candidate
        for candidate in excluded
    )


def _metadata_surface_name(
    pointer: tuple[str | int, ...],
    unknown_surface: str,
) -> str:
    if pointer and pointer[0] in {"trace", "traces", "logs", "spans", "transcript"}:
        return "logs.traces"
    return unknown_surface


def _is_response_tool_id_pointer(
    container: dict[str, Any],
    pointer: tuple[str | int, ...],
    validated_tool_context: set[tuple[int, int]],
) -> bool:
    if not pointer or pointer[-1] != "id":
        return False
    if (
        len(pointer) == 6
        and pointer[0] == "choices"
        and isinstance(pointer[1], int)
        and pointer[2] == "message"
        and pointer[3] == "tool_calls"
        and isinstance(pointer[4], int)
        and pointer[5] == "id"
    ):
        # JSON response message tool-call IDs retain the pre-existing schema
        # bound exception: assistant message + function call with name and
        # string arguments.
        choice_idx, call_idx = pointer[1], pointer[4]
        if not isinstance(choice_idx, int) or not isinstance(call_idx, int):
            return False
        try:
            choice = container["choices"][choice_idx]
            message = choice["message"]
            tool_call = message["tool_calls"][call_idx]
        except (KeyError, IndexError, TypeError):
            return False
        return (
            isinstance(choice, dict)
            and isinstance(message, dict)
            and message.get("role") == "assistant"
            and _is_function_tool_call(tool_call)
        )
    if (
        len(pointer) == 6
        and pointer[0] == "choices"
        and isinstance(pointer[1], int)
        and pointer[2] == "delta"
        and pointer[3] == "tool_calls"
        and isinstance(pointer[4], int)
        and pointer[5] == "id"
    ):
        choice_pos, call_pos = pointer[1], pointer[4]
        # A later delta may omit the function shape; only a call context
        # validated by an earlier complete function delta may preserve the
        # exact correlation-ID exception.  Context keys use semantic protocol
        # indexes, so array reordering cannot map one call onto another.
        try:
            choice = container["choices"][choice_pos]
            tool_call = choice["delta"]["tool_calls"][call_pos]
        except (KeyError, IndexError, TypeError):
            return False
        if not is_valid_stream_tool_context(container, choice, tool_call):
            return False
        choice_idx = _semantic_index(choice, choice_pos)
        call_idx = _semantic_index(tool_call, call_pos)
        return (choice_idx, call_idx) in validated_tool_context
    return False


def is_valid_stream_tool_context(
    payload: Any,
    choice: Any,
    tool_call: Any,
) -> bool:
    """Return whether a streamed tool call has a non-contradictory shape.

    Omitted fields are normal in later Chat Completions deltas.  Explicit
    request-shaped roots, mismatched objects, non-assistant roles, and
    malformed tool/function fields must not inherit an earlier ID exemption.
    """

    if not isinstance(payload, dict) or "messages" in payload:
        return False
    if "object" in payload and payload.get("object") != "chat.completion.chunk":
        return False
    if not isinstance(choice, dict) or not isinstance(tool_call, dict):
        return False
    for container in (payload, choice, choice.get("delta")):
        if isinstance(container, dict) and "role" in container:
            if container.get("role") != "assistant":
                return False
    if "type" in tool_call and tool_call.get("type") != "function":
        return False
    function = tool_call.get("function")
    if function is not None:
        if not isinstance(function, dict):
            return False
        if "name" in function and (
            not isinstance(function.get("name"), str) or not function["name"]
        ):
            return False
        if "arguments" in function and not isinstance(function.get("arguments"), str):
            return False
    return True


def _semantic_index(value: Any, fallback: int) -> int:
    index = value.get("index", fallback) if isinstance(value, dict) else fallback
    return index if isinstance(index, int) else fallback


_KNOWN_STRUCTURAL_KEYS = frozenset(
    {
        "id",
        "object",
        "created",
        "created_at",
        "model",
        "system_fingerprint",
        "service_tier",
        "choices",
        "messages",
        "index",
        "message",
        "delta",
        "role",
        "finish_reason",
        "logprobs",
        "tool_calls",
        "tool_call",
        "tool_call_id",
        "type",
        "function",
        "name",
        "arguments",
        "content",
        "event",
        "comments",
        "retry",
        "refusal",
        "annotations",
        "usage",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "prompt_tokens_details",
        "completion_tokens_details",
        "cached_tokens",
        "cache_write_tokens",
        "audio_tokens",
        "reasoning_tokens",
        "accepted_prediction_tokens",
        "rejected_prediction_tokens",
        "system_fingerprint",
    }
)


def _extract_openai_request(
    payload: dict[str, Any], surfaces: list[Surface], unknown_surface: str
) -> None:
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
            if role == "assistant" and _is_function_tool_call(tool_call):
                _append_tool_call_id_surface(
                    surfaces,
                    unknown_surface,
                    (
                        "messages",
                        idx,
                        "tool_calls",
                        call_idx,
                        "id",
                    ),
                    tool_call,
                )
        if role == "tool":
            _append_tool_call_id_surface(
                surfaces,
                unknown_surface,
                ("messages", idx, "tool_call_id"),
                message,
                field="tool_call_id",
            )
    for idx, chunk in enumerate(payload.get("rag_context", [])):
        _append_content_surfaces(surfaces, "input.rag_context", ("rag_context", idx), chunk)


def _extract_openai_response(
    payload: dict[str, Any], surfaces: list[Surface], unknown_surface: str
) -> None:
    if _is_response_envelope(payload) and isinstance(payload.get("id"), str):
        surfaces.append(
            Surface(
                name=unknown_surface,
                pointer=("id",),
                value=payload["id"],
                response_id_metadata=True,
            )
        )
    if _is_response_envelope(payload) and isinstance(payload.get("system_fingerprint"), str):
        surfaces.append(
            Surface(
                name=unknown_surface,
                pointer=("system_fingerprint",),
                value=payload["system_fingerprint"],
                provider_version_metadata=True,
            )
        )
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
                if message.get("role") == "assistant" and _is_function_tool_call(tool_call):
                    _append_tool_call_id_surface(
                        surfaces,
                        unknown_surface,
                        (
                            "choices",
                            choice_idx,
                            "message",
                            "tool_calls",
                            call_idx,
                            "id",
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


def _append_tool_call_id_surface(
    surfaces: list[Surface],
    name: str,
    pointer: tuple[str | int, ...],
    payload: Any,
    *,
    field: str = "id",
) -> None:
    if not isinstance(payload, dict):
        return
    value = payload.get(field)
    if isinstance(value, str):
        surfaces.append(
            Surface(
                name=name,
                pointer=pointer,
                value=value,
                correlation_metadata=True,
            )
        )


def _is_function_tool_call(tool_call: Any) -> bool:
    if not isinstance(tool_call, dict) or tool_call.get("type") != "function":
        return False
    function = tool_call.get("function")
    if not isinstance(function, dict):
        return False
    name = function.get("name")
    arguments = function.get("arguments")
    return isinstance(name, str) and bool(name) and isinstance(arguments, str)


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
    safe_json_pointer: tuple[str | int, ...] = (),
) -> None:
    if isinstance(payload, dict):
        for key_index, (key, value) in enumerate(payload.items()):
            member_safe_pointer = (*safe_json_pointer, key_index)
            surfaces.append(
                Surface(
                    name=name,
                    pointer=pointer,
                    value=str(key),
                    argument_key_metadata=True,
                    safe_json_pointer=("argument", "key", *member_safe_pointer),
                )
            )
            _walk_json_argument_surfaces(
                value,
                pointer,
                (*json_pointer, key),
                name,
                surfaces,
                member_safe_pointer,
            )
    elif isinstance(payload, list):
        for idx, value in enumerate(payload):
            _walk_json_argument_surfaces(
                value,
                pointer,
                (*json_pointer, idx),
                name,
                surfaces,
                (*safe_json_pointer, idx),
            )
    elif isinstance(payload, (str, int, float, bool)) and payload is not None:
        surfaces.append(
            Surface(
                name=name,
                pointer=pointer,
                value=str(payload),
                json_pointer=json_pointer,
                safe_json_pointer=("argument", "value", *safe_json_pointer),
            )
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
    seen: set[
        tuple[
            tuple[str | int, ...],
            tuple[str | int, ...] | None,
            tuple[str | int, ...] | None,
            str,
            bool,
        ]
    ] = set()
    deduped: list[Surface] = []
    for surface in surfaces:
        key = (
            surface.pointer,
            surface.json_pointer,
            surface.safe_json_pointer,
            surface.name,
            surface.argument_key_metadata,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(surface)
    return deduped
