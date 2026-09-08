# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import codecs
import http.client
import json
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, TYPE_CHECKING

from .audit import build_audit_event
from .engine import Firewall, _decision_applies, _decisions_blocked
from .surfaces import Surface
from .transforms import apply_decisions
from .types import PolicyDecision

if TYPE_CHECKING:
    from .metrics import MetricsRecorder

DEFAULT_STREAM_HOLDBACK_CHARS = 512
STREAM_TEXT_FIELDS = ("content", "reasoning", "reasoning_content", "reasoning_details")
STREAM_REASONING_FIELDS = frozenset(("reasoning", "reasoning_content", "reasoning_details"))
STREAM_TOOL_CALL_ARGUMENTS = "tool_call_arguments"
UPSTREAM_TRANSPORT_ERROR_TYPE = "upstream_transport_error"
STREAM_TRANSPORT_ERRORS = (OSError, TimeoutError, http.client.HTTPException)


@dataclass(frozen=True)
class SseEvent:
    data: str
    event: str | None = None
    id: str | None = None
    retry: str | None = None
    comments: tuple[str, ...] = ()


@dataclass(frozen=True)
class StreamAppendResult:
    released: str
    held: str
    blocked: bool
    decisions: list[PolicyDecision]
    audit_event: dict[str, Any] | None = None
    error_event: bytes | None = None


@dataclass(frozen=True)
class StreamChunkTemplate:
    payload: dict[str, Any]
    event: SseEvent | None = None


@dataclass(frozen=True)
class StreamFlushResult:
    chunks: list[bytes]
    blocked_event: bytes | None = None
    decision_count: int = 0
    surfaces_inspected: tuple[str, ...] = ()


class StreamingInspectionState:
    def __init__(
        self,
        firewall: Firewall,
        *,
        surface_name: str,
        pointer: tuple[str | int, ...],
        holdback_chars: int = DEFAULT_STREAM_HOLDBACK_CHARS,
        metrics_recorder: "MetricsRecorder | None" = None,
    ):
        if holdback_chars < 0:
            raise ValueError("holdback_chars must be non-negative")
        self.firewall = firewall
        self.surface_name = surface_name
        self.pointer = pointer
        self.holdback_chars = holdback_chars
        self.pending = ""
        self.metrics_recorder = metrics_recorder

    def append(self, text: str) -> StreamAppendResult:
        self.pending += text
        decisions = self._inspect_pending()
        blocked = _decisions_block(self.firewall, decisions)
        if blocked:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=True,
                decisions=decisions,
                audit_event=build_audit_event(
                    decisions=decisions,
                    store_redacted_evidence=self.firewall.policy.audit.store_redacted_evidence,
                    include_policy_decision=self.firewall.policy.audit.include_policy_decision,
                    blocked=True,
                ),
            )
        return StreamAppendResult(
            released=self._release_prefix(decisions, self._commit_index(decisions)),
            held=self.pending,
            blocked=False,
            decisions=decisions,
        )

    def check_pending(self) -> StreamAppendResult:
        decisions = self._inspect_pending()
        blocked = _decisions_block(self.firewall, decisions)
        if blocked:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=True,
                decisions=decisions,
                audit_event=build_audit_event(
                    decisions=decisions,
                    store_redacted_evidence=self.firewall.policy.audit.store_redacted_evidence,
                    include_policy_decision=self.firewall.policy.audit.include_policy_decision,
                    blocked=True,
                ),
            )
        return StreamAppendResult(
            released="",
            held=self.pending,
            blocked=False,
            decisions=decisions,
        )

    def flush_with_preflight(self, preflight: StreamAppendResult) -> StreamAppendResult:
        decisions = preflight.decisions
        if preflight.blocked:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=True,
                decisions=decisions,
                audit_event=preflight.audit_event,
            )
        released = self._release_prefix(decisions, len(self.pending))
        # Preserve inspection metadata when returning the released prefix.
        # check_pending emits an audit event only for blocked content.
        return StreamAppendResult(
            released=released,
            held=self.pending,
            blocked=False,
            decisions=decisions,
            audit_event=preflight.audit_event,
        )

    def _inspect_pending(self) -> list[PolicyDecision]:
        if not self.pending:
            return []
        timer = (
            self.metrics_recorder.time_ms(
                "stream_chunk_inspection_ms",
                stream=True,
                surface=self.surface_name,
            )
            if self.metrics_recorder is not None
            else nullcontext()
        )
        with timer:
            surface = Surface(name=self.surface_name, pointer=self.pointer, value=self.pending)
            findings = self.firewall.scanner.scan(surface)
            decisions = [self.firewall.policy.decide(finding) for finding in findings]
        return [decision for decision in decisions if decision.action != "allow"]

    def _commit_index(self, decisions: list[PolicyDecision]) -> int:
        if len(self.pending) <= self.holdback_chars:
            return 0
        commit_index = len(self.pending) - self.holdback_chars
        for decision in decisions:
            finding = decision.finding
            if finding.start < commit_index < finding.end:
                commit_index = finding.start
        return commit_index

    def _release_prefix(self, decisions: list[PolicyDecision], commit_index: int) -> str:
        if commit_index <= 0:
            return ""
        prefix = self.pending[:commit_index]
        suffix = self.pending[commit_index:]
        release_decisions = [
            decision for decision in decisions if decision.finding.end <= commit_index
        ]
        release_decisions = [
            decision
            for decision in release_decisions
            if _decision_applies(decision, self.firewall.policy.mode)
        ]
        if release_decisions:
            payload = {"text": prefix}
            payload = apply_decisions(
                payload,
                release_decisions,
                token_replacer=getattr(self.firewall, "_vault_token_replacer", None)
                if getattr(self.firewall, "token_vault", None)
                else None,
            )
            prefix = payload["text"]
        self.pending = suffix
        return prefix


class StreamingToolCallArgumentState:
    def __init__(
        self,
        firewall: Firewall,
        *,
        choice_index: int,
        tool_call_index: int,
        metrics_recorder: "MetricsRecorder | None" = None,
    ):
        self.firewall = firewall
        self.choice_index = choice_index
        self.tool_call_index = tool_call_index
        self.pending = ""
        self.metrics_recorder = metrics_recorder

    def append(self, text: str) -> StreamAppendResult:
        self.pending += text
        return StreamAppendResult(
            released="",
            held=self.pending,
            blocked=False,
            decisions=[],
        )

    def check_pending(self) -> StreamAppendResult:
        inspection, error_event = self._inspect_pending()
        if error_event is not None:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=False,
                decisions=[],
                error_event=error_event,
            )
        if inspection is None:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=False,
                decisions=[],
            )
        if inspection.blocked:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=True,
                decisions=inspection.decisions,
                audit_event=inspection.audit_event,
            )
        return StreamAppendResult(
            released=_transformed_tool_arguments(inspection.transformed_payload),
            held=self.pending,
            blocked=False,
            decisions=inspection.decisions,
        )

    def flush_with_preflight(self, preflight: StreamAppendResult) -> StreamAppendResult:
        # The preflight check_pending() pass already produced the transformed
        # arguments via _inspect_pending and stashed them in preflight.released.
        # Reuse that result directly — pending hasn't changed since preflight
        # (StreamingToolCallArgumentState.append is the only mutator and is
        # not called between preflight and flush). This mirrors the text-stream
        # path, which also derives its flush output from the preflight
        # decisions without re-scanning.
        if not self.pending:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=False,
                decisions=[],
            )
        if preflight.error_event is not None:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=False,
                decisions=preflight.decisions,
                error_event=preflight.error_event,
            )
        if preflight.blocked:
            return StreamAppendResult(
                released="",
                held=self.pending,
                blocked=True,
                decisions=preflight.decisions,
                audit_event=preflight.audit_event,
            )
        released = preflight.released
        self.pending = ""
        return StreamAppendResult(
            released=released,
            held="",
            blocked=False,
            decisions=preflight.decisions,
        )

    def _inspect_pending(self):
        if not self.pending:
            return None, None
        try:
            json.loads(self.pending)
        except json.JSONDecodeError as exc:
            return None, _malformed_tool_arguments_event(
                self.choice_index,
                self.tool_call_index,
                exc,
            )
        timer = (
            self.metrics_recorder.time_ms(
                "stream_tool_call_inspection_ms",
                stream=True,
            )
            if self.metrics_recorder is not None
            else nullcontext()
        )
        with timer:
            result = self.firewall.inspect(
                _tool_argument_inspection_payload(self.pending)
            )
        return result, None


def iter_sse_events(chunks: Iterable[bytes]) -> Iterator[SseEvent]:
    decoder = codecs.getincrementaldecoder("utf-8")()
    buffer = ""
    for chunk in chunks:
        buffer += decoder.decode(chunk)
        while True:
            block, buffer = _pop_sse_block(buffer)
            if block is None:
                break
            yield _parse_sse_block(block)
    buffer += decoder.decode(b"", final=True)
    if buffer.strip():
        yield _parse_sse_block(buffer)


def format_sse_event(
    data: str | dict[str, Any],
    *,
    event: str | None = None,
    id: str | None = None,
    retry: str | None = None,
    comments: Iterable[str] = (),
) -> bytes:
    lines = []
    for comment in comments:
        lines.append(f": {comment}" if comment else ":")
    if id is not None:
        lines.append(f"id: {id}")
    if retry is not None:
        lines.append(f"retry: {retry}")
    if event:
        lines.append(f"event: {event}")
    payload = json.dumps(data, separators=(",", ":")) if isinstance(data, dict) else data
    for line in payload.splitlines() or [""]:
        lines.append(f"data: {line}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def stream_chat_completion_chunks(
    upstream_chunks: Iterable[bytes],
    firewall: Firewall,
    *,
    holdback_chars: int = DEFAULT_STREAM_HOLDBACK_CHARS,
    telemetry_callback: Callable[[dict[str, Any]], None] | None = None,
    metrics_recorder: "MetricsRecorder | None" = None,
) -> Iterator[bytes]:
    states: dict[tuple[Any, ...], Any] = {}
    last_templates: dict[tuple[Any, ...], StreamChunkTemplate] = {}
    telemetry = _new_stream_telemetry()
    try:
        for event in iter_sse_events(upstream_chunks):
            if not event.data:
                continue
            if event.data == "[DONE]":
                flush_result = _flush_stream_states(
                    states,
                    last_templates,
                    source_event=event,
                    telemetry=telemetry,
                )
                yield from flush_result.chunks
                if flush_result.blocked_event is not None:
                    _notify_stream_terminal(
                        telemetry_callback,
                        telemetry,
                        error_event=flush_result.blocked_event,
                    )
                    yield flush_result.blocked_event
                    return
                _notify_stream_terminal(
                    telemetry_callback,
                    telemetry,
                    stream_state="done",
                    blocked=False,
                )
                yield _format_sse_event_like("[DONE]", event)
                return
            try:
                payload = json.loads(event.data)
            except json.JSONDecodeError as exc:
                yield from _handle_malformed_stream_error(
                    f"Malformed upstream SSE JSON: {exc}",
                    "malformed_sse_json",
                    states,
                    last_templates,
                    source_event=event,
                    telemetry=telemetry,
                    telemetry_callback=telemetry_callback,
                )
                return
            if not isinstance(payload, dict):
                yield from _handle_malformed_stream_error(
                    "Malformed upstream SSE payload: expected object",
                    "malformed_sse_payload",
                    states,
                    last_templates,
                    source_event=event,
                    telemetry=telemetry,
                    telemetry_callback=telemetry_callback,
                )
                return
            outputs, blocked_event = _transform_stream_payload(
                payload,
                firewall,
                states,
                last_templates,
                source_event=event,
                holdback_chars=holdback_chars,
                telemetry=telemetry,
                metrics_recorder=metrics_recorder,
            )
            if blocked_event is not None:
                _notify_stream_terminal(
                    telemetry_callback,
                    telemetry,
                    error_event=blocked_event,
                )
                yield blocked_event
                return
            yield from outputs
    except UnicodeDecodeError as exc:
        yield from _handle_malformed_stream_error(
            f"Malformed upstream SSE bytes: {exc}",
            "malformed_sse_bytes",
            states,
            last_templates,
            telemetry=telemetry,
            telemetry_callback=telemetry_callback,
        )
        return
    except STREAM_TRANSPORT_ERRORS:
        yield from _handle_stream_transport_error(
            states,
            last_templates,
            telemetry=telemetry,
            telemetry_callback=telemetry_callback,
        )
        return
    had_active_stream_state = bool(states)
    flush_result = _flush_stream_states(states, last_templates, telemetry=telemetry)
    yield from flush_result.chunks
    if flush_result.blocked_event is not None:
        _notify_stream_terminal(
            telemetry_callback,
            telemetry,
            error_event=flush_result.blocked_event,
        )
        yield flush_result.blocked_event
        return
    if had_active_stream_state:
        error_event = _stream_error_event(
            "Upstream SSE stream ended before [DONE].",
            summary=_stream_summary(telemetry, "upstream_eof"),
        )
        _notify_stream_terminal(
            telemetry_callback,
            telemetry,
            error_event=error_event,
        )
        yield error_event


def _handle_stream_transport_error(
    states: dict[tuple[Any, ...], Any],
    last_templates: dict[tuple[Any, ...], StreamChunkTemplate],
    *,
    telemetry: dict[str, Any],
    telemetry_callback: Callable[[dict[str, Any]], None] | None,
) -> Iterator[bytes]:
    flush_result = _flush_stream_states(states, last_templates, telemetry=telemetry)
    yield from flush_result.chunks
    if flush_result.blocked_event is not None:
        _notify_stream_terminal(
            telemetry_callback,
            telemetry,
            error_event=flush_result.blocked_event,
        )
        yield flush_result.blocked_event
        return
    error_event = _stream_error_event(
        "Upstream stream transport error.",
        error_type=UPSTREAM_TRANSPORT_ERROR_TYPE,
        summary=_stream_summary(telemetry, UPSTREAM_TRANSPORT_ERROR_TYPE),
    )
    _notify_stream_terminal(
        telemetry_callback,
        telemetry,
        error_event=error_event,
    )
    yield error_event


def _handle_malformed_stream_error(
    message: str,
    stream_state: str,
    states: dict[tuple[Any, ...], Any],
    last_templates: dict[tuple[Any, ...], StreamChunkTemplate],
    *,
    source_event: SseEvent | None = None,
    telemetry: dict[str, Any],
    telemetry_callback: Callable[[dict[str, Any]], None] | None,
) -> Iterator[bytes]:
    flush_result = _flush_stream_states(
        states,
        last_templates,
        source_event=source_event,
        telemetry=telemetry,
    )
    yield from flush_result.chunks
    if flush_result.blocked_event is not None:
        _notify_stream_terminal(
            telemetry_callback,
            telemetry,
            error_event=flush_result.blocked_event,
        )
        yield flush_result.blocked_event
        return
    error_event = _stream_error_event(
        message,
        summary=_stream_summary(telemetry, stream_state),
    )
    _notify_stream_terminal(
        telemetry_callback,
        telemetry,
        error_event=error_event,
    )
    yield error_event


def _transform_stream_payload(
    payload: dict[str, Any],
    firewall: Firewall,
    states: dict[tuple[Any, ...], Any],
    last_templates: dict[tuple[Any, ...], StreamChunkTemplate],
    *,
    source_event: SseEvent | None,
    holdback_chars: int,
    telemetry: dict[str, Any],
    metrics_recorder: "MetricsRecorder | None" = None,
) -> tuple[list[bytes], bytes | None]:
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return [_format_sse_event_like(payload, source_event)], None
    outputs: list[bytes] = []
    passthrough_payload = json.loads(json.dumps(payload))
    touched_held_field = False
    flush_outputs: list[bytes] = []
    terminal_choice_indexes: set[int] = set()
    for choice_pos, choice in enumerate(choices):
        if not isinstance(choice, dict):
            continue
        choice_index = _choice_index(choice, choice_pos)
        if _is_terminal_choice(choice):
            terminal_choice_indexes.add(choice_index)
        delta = choice.get("delta")
        if not isinstance(delta, dict):
            continue
        touched_tool_arguments = _capture_stream_tool_call_arguments(
            payload,
            passthrough_payload,
            choice_pos,
            choice_index,
            delta,
            firewall,
            states,
            last_templates,
            source_event=source_event,
            telemetry=telemetry,
            metrics_recorder=metrics_recorder,
        )
        touched_held_field = touched_held_field or touched_tool_arguments
        for field in STREAM_TEXT_FIELDS:
            value = delta.get(field)
            if not isinstance(value, str):
                continue
            touched_held_field = True
            key = (choice_index, field)
            state = states.setdefault(
                key,
                StreamingInspectionState(
                    firewall,
                    surface_name=_surface_for_stream_field(field),
                    pointer=("text",),
                    holdback_chars=holdback_chars,
                    metrics_recorder=metrics_recorder,
                ),
            )
            _record_stream_surface(telemetry, _surface_for_stream_field(field))
            result = state.append(value)
            _record_stream_decisions(telemetry, result.decisions)
            if result.blocked:
                return [], _blocked_stream_event(
                    result.audit_event,
                    decisions=result.decisions,
                    summary=_stream_summary(telemetry, "blocked"),
                )
            last_templates[key] = StreamChunkTemplate(
                payload=_stream_template(payload, choice_pos, field),
                event=source_event,
            )
            if result.released:
                passthrough_payload["choices"][choice_pos]["delta"][field] = result.released
            else:
                passthrough_payload["choices"][choice_pos]["delta"].pop(field, None)
    for choice_index in terminal_choice_indexes:
        flush_result = _flush_stream_states(
            states,
            last_templates,
            choice_index=choice_index,
            source_event=source_event,
            telemetry=telemetry,
        )
        if flush_result.blocked_event is not None:
            return [], flush_result.blocked_event
        flush_outputs.extend(flush_result.chunks)
    if _payload_has_deliverable_data(passthrough_payload):
        outputs.append(_format_sse_event_like(passthrough_payload, source_event))
    if not touched_held_field and not outputs:
        outputs.append(_format_sse_event_like(payload, source_event))
    return [*flush_outputs, *outputs], None


def _capture_stream_tool_call_arguments(
    payload: dict[str, Any],
    passthrough_payload: dict[str, Any],
    choice_pos: int,
    choice_index: int,
    delta: dict[str, Any],
    firewall: Firewall,
    states: dict[tuple[Any, ...], Any],
    last_templates: dict[tuple[Any, ...], StreamChunkTemplate],
    *,
    source_event: SseEvent | None,
    telemetry: dict[str, Any],
    metrics_recorder: "MetricsRecorder | None" = None,
) -> bool:
    tool_calls = delta.get("tool_calls")
    if not isinstance(tool_calls, list):
        return False
    passthrough_delta = passthrough_payload["choices"][choice_pos].get("delta")
    passthrough_tool_calls = (
        passthrough_delta.get("tool_calls") if isinstance(passthrough_delta, dict) else None
    )
    if not isinstance(passthrough_tool_calls, list):
        return False
    touched_arguments = False
    for call_pos, tool_call in enumerate(tool_calls):
        if not isinstance(tool_call, dict):
            continue
        function = tool_call.get("function")
        if not isinstance(function, dict):
            continue
        arguments = function.get("arguments")
        if not isinstance(arguments, str):
            continue
        touched_arguments = True
        tool_call_index = _tool_call_index(tool_call, call_pos)
        key = _tool_call_argument_key(choice_index, tool_call_index)
        state = states.setdefault(
            key,
            StreamingToolCallArgumentState(
                firewall,
                choice_index=choice_index,
                tool_call_index=tool_call_index,
                metrics_recorder=metrics_recorder,
            ),
        )
        state.append(arguments)
        _record_stream_surface(telemetry, "output.tool_calls.arguments")
        _strip_passthrough_tool_arguments(passthrough_tool_calls, call_pos)
        last_templates[key] = StreamChunkTemplate(
            payload=_tool_call_argument_template(payload, choice_pos, tool_call_index),
            event=source_event,
        )
    return touched_arguments


def _flush_stream_states(
    states: dict[tuple[Any, ...], Any],
    last_templates: dict[tuple[Any, ...], StreamChunkTemplate],
    *,
    choice_index: int | None = None,
    source_event: SseEvent | None = None,
    telemetry: dict[str, Any] | None = None,
) -> StreamFlushResult:
    selected = [
        (key, state)
        for key, state in list(states.items())
        if choice_index is None or key[0] == choice_index
    ]
    preflight: list[tuple[tuple[int, str], StreamingInspectionState, StreamAppendResult]] = []
    decision_count = 0
    for key, state in selected:
        result = state.check_pending()
        if telemetry is not None:
            _record_state_surface(telemetry, key)
            _record_stream_decisions(telemetry, result.decisions)
        decision_count += len(result.decisions)
        if result.error_event is not None:
            return StreamFlushResult(
                chunks=[],
                blocked_event=result.error_event,
                decision_count=decision_count,
                surfaces_inspected=_telemetry_surfaces(telemetry),
            )
        if result.blocked:
            return StreamFlushResult(
                chunks=[],
                blocked_event=_blocked_stream_event(
                    result.audit_event,
                    decisions=result.decisions,
                    summary=_stream_summary(telemetry, "blocked"),
                ),
                decision_count=decision_count,
                surfaces_inspected=_telemetry_surfaces(telemetry),
            )
        preflight.append((key, state, result))

    chunks: list[bytes] = []
    for key, state, preflight_result in preflight:
        result = state.flush_with_preflight(preflight_result)
        if result.error_event is not None:
            return StreamFlushResult(
                chunks=[],
                blocked_event=result.error_event,
                decision_count=decision_count,
                surfaces_inspected=_telemetry_surfaces(telemetry),
            )
        if result.released:
            chunk_template = last_templates.get(key)
            if chunk_template is None:
                template = _minimal_stream_template_for_key(key)
                event = source_event
            else:
                template = json.loads(json.dumps(chunk_template.payload))
                event = chunk_template.event or source_event
            _set_released_stream_value(template, key, result.released)
            chunks.append(_format_sse_event_like(template, event))
        states.pop(key, None)
        last_templates.pop(key, None)
    return StreamFlushResult(
        chunks=chunks,
        decision_count=decision_count,
        surfaces_inspected=_telemetry_surfaces(telemetry),
    )


def _pop_sse_block(buffer: str) -> tuple[str | None, str]:
    separators = [separator for separator in ("\r\n\r\n", "\n\n") if separator in buffer]
    if not separators:
        return None, buffer
    separator = min(separators, key=lambda item: buffer.index(item))
    index = buffer.index(separator)
    return buffer[:index], buffer[index + len(separator) :]


def _parse_sse_block(block: str) -> SseEvent:
    data_lines: list[str] = []
    event_name: str | None = None
    event_id: str | None = None
    retry: str | None = None
    comments: list[str] = []
    for raw_line in block.splitlines():
        line = raw_line.rstrip("\r")
        if not line:
            continue
        if line.startswith(":"):
            comment = line[1:]
            if comment.startswith(" "):
                comment = comment[1:]
            comments.append(comment)
            continue
        if line.startswith("event:"):
            event_name = _sse_field_value(line[6:])
            continue
        if line.startswith("id:"):
            event_id = _sse_field_value(line[3:])
            continue
        if line.startswith("retry:"):
            retry = _sse_field_value(line[6:])
            continue
        if line.startswith("data:"):
            data_lines.append(_sse_field_value(line[5:]))
    return SseEvent(
        data="\n".join(data_lines),
        event=event_name,
        id=event_id,
        retry=retry,
        comments=tuple(comments),
    )


def _sse_field_value(value: str) -> str:
    return value[1:] if value.startswith(" ") else value


def _decisions_block(firewall: Firewall, decisions: list[PolicyDecision]) -> bool:
    return _decisions_blocked(firewall.policy.mode, decisions)


def _choice_index(choice: dict[str, Any], fallback: int) -> int:
    index = choice.get("index", fallback)
    return index if isinstance(index, int) else fallback


def _tool_call_index(tool_call: dict[str, Any], fallback: int) -> int:
    index = tool_call.get("index", fallback)
    return index if isinstance(index, int) else fallback


def _tool_call_argument_key(choice_index: int, tool_call_index: int) -> tuple[int, str, int]:
    return (choice_index, STREAM_TOOL_CALL_ARGUMENTS, tool_call_index)


def _is_tool_call_argument_key(key: tuple[Any, ...]) -> bool:
    return len(key) == 3 and key[1] == STREAM_TOOL_CALL_ARGUMENTS


def _surface_for_stream_field(field: str) -> str:
    if field in STREAM_REASONING_FIELDS:
        return "output.reasoning"
    return "output.stream_chunk"


def _payload_has_deliverable_data(payload: dict[str, Any]) -> bool:
    choices = payload.get("choices")
    if not isinstance(choices, list):
        return True
    deliverable_choices = []
    for choice in choices:
        if not isinstance(choice, dict):
            deliverable_choices.append(choice)
            continue
        delta = choice.get("delta")
        if isinstance(delta, dict) and not delta:
            choice = dict(choice)
            choice.pop("delta", None)
        elif isinstance(delta, dict):
            _prune_empty_stream_tool_calls(delta)
            if not delta:
                choice = dict(choice)
                choice.pop("delta", None)
        if _choice_has_deliverable_data(choice):
            deliverable_choices.append(choice)
    payload["choices"] = deliverable_choices
    return _payload_has_top_level_data(payload) or bool(deliverable_choices)


def _choice_has_deliverable_data(choice: dict[str, Any]) -> bool:
    for key, value in choice.items():
        if key == "index":
            continue
        if key == "delta" and value == {}:
            continue
        if value is not None:
            return True
    return False


def _payload_has_top_level_data(payload: dict[str, Any]) -> bool:
    metadata_only_keys = {"id", "object", "created", "model", "system_fingerprint"}
    for key, value in payload.items():
        if key == "choices" or key in metadata_only_keys:
            continue
        if value is not None:
            return True
    return False


def _is_terminal_choice(choice: dict[str, Any]) -> bool:
    return choice.get("finish_reason") is not None


def _strip_passthrough_tool_arguments(tool_calls: list[Any], call_pos: int) -> None:
    if call_pos >= len(tool_calls):
        return
    tool_call = tool_calls[call_pos]
    if not isinstance(tool_call, dict):
        return
    function = tool_call.get("function")
    if isinstance(function, dict):
        function.pop("arguments", None)


def _prune_empty_stream_tool_calls(delta: dict[str, Any]) -> None:
    tool_calls = delta.get("tool_calls")
    if not isinstance(tool_calls, list):
        return
    deliverable_tool_calls = []
    for tool_call in tool_calls:
        if not isinstance(tool_call, dict):
            deliverable_tool_calls.append(tool_call)
            continue
        pruned = json.loads(json.dumps(tool_call))
        function = pruned.get("function")
        if isinstance(function, dict) and not function:
            pruned.pop("function", None)
        if _tool_call_delta_has_deliverable_data(pruned):
            deliverable_tool_calls.append(pruned)
    if deliverable_tool_calls:
        delta["tool_calls"] = deliverable_tool_calls
    else:
        delta.pop("tool_calls", None)


def _tool_call_delta_has_deliverable_data(tool_call: dict[str, Any]) -> bool:
    for key, value in tool_call.items():
        if key == "index":
            continue
        if key == "function" and value == {}:
            continue
        if value is not None:
            return True
    return False


def _stream_template(payload: dict[str, Any], choice_pos: int, field: str) -> dict[str, Any]:
    template = json.loads(json.dumps(payload))
    choice = template["choices"][choice_pos]
    choice["delta"] = {field: ""}
    choice.pop("finish_reason", None)
    template["choices"] = [choice]
    return template


def _tool_call_argument_template(
    payload: dict[str, Any],
    choice_pos: int,
    tool_call_index: int,
) -> dict[str, Any]:
    template = json.loads(json.dumps(payload))
    choice = template["choices"][choice_pos]
    choice["delta"] = {
        "tool_calls": [
            {
                "index": tool_call_index,
                "function": {"arguments": ""},
            }
        ]
    }
    choice.pop("finish_reason", None)
    template["choices"] = [choice]
    return template


def _minimal_stream_template(choice_index: int, field: str) -> dict[str, Any]:
    return {"choices": [{"index": choice_index, "delta": {field: ""}}]}


def _minimal_stream_template_for_key(key: tuple[Any, ...]) -> dict[str, Any]:
    if _is_tool_call_argument_key(key):
        return {
            "choices": [
                {
                    "index": key[0],
                    "delta": {
                        "tool_calls": [
                            {
                                "index": key[2],
                                "function": {"arguments": ""},
                            }
                        ]
                    },
                }
            ]
        }
    return _minimal_stream_template(key[0], key[1])


def _set_released_stream_value(
    template: dict[str, Any],
    key: tuple[Any, ...],
    released: str,
) -> None:
    delta = template["choices"][0]["delta"]
    if _is_tool_call_argument_key(key):
        delta["tool_calls"][0]["function"]["arguments"] = released
        return
    delta[key[1]] = released


def _tool_argument_inspection_payload(arguments: str) -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "function": {
                                "arguments": arguments,
                            }
                        }
                    ]
                }
            }
        ]
    }


def _transformed_tool_arguments(payload: dict[str, Any]) -> str:
    return payload["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]


def _format_sse_event_like(data: str | dict[str, Any], source_event: SseEvent | None) -> bytes:
    if source_event is None:
        return format_sse_event(data)
    return format_sse_event(
        data,
        event=source_event.event,
        id=source_event.id,
        retry=source_event.retry,
        comments=source_event.comments,
    )


def _blocked_stream_event(
    audit_event: dict[str, Any] | None,
    *,
    decisions: list[PolicyDecision] | None = None,
    summary: dict[str, Any] | None = None,
) -> bytes:
    return _stream_error_event(
        "Stream blocked by LLM Sensitive Data Firewall policy.",
        error_type="sensitive_data_blocked",
        audit_event=audit_event,
        summary=summary
        or {
            "stream_state": "blocked",
            "decision_count": len(decisions or []),
        },
    )


def _malformed_tool_arguments_event(
    choice_index: int,
    tool_call_index: int,
    exc: json.JSONDecodeError,
) -> bytes:
    return _stream_error_event(
        "Malformed streamed tool-call arguments.",
        summary={
            "stream_state": "malformed_tool_call_arguments",
            "choice_index": choice_index,
            "tool_call_index": tool_call_index,
            "json_error": exc.msg,
            "json_error_position": exc.pos,
        },
    )


def _stream_error_event(
    message: str,
    *,
    error_type: str = "upstream_stream_error",
    audit_event: dict[str, Any] | None = None,
    summary: dict[str, Any] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "error": {
            "message": message,
            "type": error_type,
        }
    }
    if audit_event is not None:
        payload["audit_event"] = audit_event
    if summary is not None:
        payload["lsdf"] = summary
    return format_sse_event(payload, event="error")


def _new_stream_telemetry() -> dict[str, Any]:
    return {
        "decision_signatures": set(),
        "surfaces_inspected": set(),
    }


def _record_state_surface(telemetry: dict[str, Any], key: tuple[Any, ...]) -> None:
    if _is_tool_call_argument_key(key):
        _record_stream_surface(telemetry, "output.tool_calls.arguments")
        return
    _record_stream_surface(telemetry, _surface_for_stream_field(str(key[1])))


def _record_stream_surface(telemetry: dict[str, Any], surface: str) -> None:
    telemetry["surfaces_inspected"].add(surface)


def _record_stream_decisions(
    telemetry: dict[str, Any],
    decisions: list[PolicyDecision],
) -> None:
    for decision in decisions:
        finding = decision.finding
        telemetry["decision_signatures"].add(
            (
                finding.surface,
                finding.pointer,
                finding.json_pointer,
                finding.start,
                finding.end,
                finding.entity,
                finding.detector_id,
                decision.action,
                decision.rule_id,
            )
        )


def _stream_summary(telemetry: dict[str, Any] | None, stream_state: str) -> dict[str, Any]:
    return {
        "stream_state": stream_state,
        "decision_count": _telemetry_decision_count(telemetry),
        "surfaces_inspected": list(_telemetry_surfaces(telemetry)),
    }


def _telemetry_decision_count(telemetry: dict[str, Any] | None) -> int:
    if telemetry is None:
        return 0
    return len(telemetry["decision_signatures"])


def _telemetry_surfaces(telemetry: dict[str, Any] | None) -> tuple[str, ...]:
    if telemetry is None:
        return ()
    return tuple(sorted(telemetry["surfaces_inspected"]))


def _notify_stream_terminal(
    callback: Callable[[dict[str, Any]], None] | None,
    telemetry: dict[str, Any],
    *,
    stream_state: str | None = None,
    blocked: bool | None = None,
    error_event: bytes | None = None,
) -> None:
    if callback is None:
        return
    payload = _stream_error_payload(error_event) if error_event is not None else {}
    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    lsdf = payload.get("lsdf", {}) if isinstance(payload, dict) else {}
    state = stream_state or lsdf.get("stream_state") or "done"
    event: dict[str, Any] = {
        "event": "stream_terminal",
        "stream_state": state,
        "blocked": bool(blocked) if blocked is not None else error.get("type") == "sensitive_data_blocked",
        "decision_count": _telemetry_decision_count(telemetry),
        "surfaces_inspected": list(_telemetry_surfaces(telemetry)),
    }
    if error:
        event["error_type"] = error.get("type")
        event["error_message"] = error.get("message")
    if isinstance(payload, dict) and "audit_event" in payload:
        event["audit_event"] = payload["audit_event"]
    callback(event)


def _stream_error_payload(error_event: bytes | None) -> dict[str, Any]:
    if error_event is None:
        return {}
    try:
        event = next(iter_sse_events([error_event]))
        payload = json.loads(event.data)
    except (StopIteration, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}
