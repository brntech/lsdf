# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import selectors
import subprocess
import sys
import threading
import time
from typing import Any

from ..surfaces import Surface
from ..types import Finding

OPENAI_PRIVACY_FILTER_ENTITY_MAP = {
    "account_number": "BANK_ACCOUNT",
    "private_address": "ADDRESS",
    "private_date": "DATE_OF_BIRTH",
    "private_email": "EMAIL",
    "private_person": "PERSON",
    "private_phone": "PHONE",
    "secret": "OTHER_SECRET",
}


@dataclass(frozen=True)
class OpenAIPrivacyFilterDetector:
    provider: Any
    score_threshold: float | None = 0.50
    merge_gap: int = 1
    provider_metadata: dict[str, Any] | None = None

    detector_id = "openai_privacy_filter.token_classifier"
    detector_family = "openai_privacy_filter"
    entities = frozenset(OPENAI_PRIVACY_FILTER_ENTITY_MAP.values())

    def scan(self, surface: Surface) -> list[Finding]:
        started = time.perf_counter()
        spans = self.provider(surface.value)
        provider_latency_seconds = time.perf_counter() - started
        normalized = [
            span
            for span in (_span_from_result(result) for result in spans or [])
            if span is not None
        ]
        normalized = [
            span
            for span in normalized
            if self.score_threshold is None or span["score"] >= self.score_threshold
        ]
        normalized = [
            span for span in normalized if span["category"] in OPENAI_PRIVACY_FILTER_ENTITY_MAP
        ]
        return [
            self._finding_from_span(surface, span, provider_latency_seconds)
            for span in _merge_spans(normalized, self.merge_gap)
            if 0 <= span["start"] < span["end"] <= len(surface.value)
        ]

    def _finding_from_span(
        self,
        surface: Surface,
        span: dict[str, Any],
        provider_latency_seconds: float,
    ) -> Finding:
        category = span["category"]
        metadata = {
            "privacy_filter_category": category,
            "source_span_count": span["source_span_count"],
            "source_scores": span["source_scores"],
            "provider_latency_seconds": round(provider_latency_seconds, 6),
            "specificity": 75,
        }
        if self.provider_metadata:
            metadata["provider"] = dict(self.provider_metadata)
        return Finding(
            entity=OPENAI_PRIVACY_FILTER_ENTITY_MAP[category],
            surface=surface.name,
            pointer=surface.pointer,
            json_pointer=surface.json_pointer,
            start=span["start"],
            end=span["end"],
            value=surface.value[span["start"] : span["end"]],
            confidence=span["score"],
            detector_id=f"openai_privacy_filter.{category}",
            detector_family=self.detector_family,
            metadata=metadata,
        )


@dataclass(frozen=True)
class TransformersPrivacyFilterProvider:
    pipeline: Any

    def __call__(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        results = self.pipeline(text)
        return list(results or [])


_DEFAULT_WORKER_STARTUP_TIMEOUT_SECONDS = 300.0
_DEFAULT_WORKER_INFERENCE_TIMEOUT_SECONDS = 60.0
_MAX_WORKER_MESSAGE_BYTES = 8 * 1024 * 1024


@dataclass
class SubprocessPrivacyFilterProvider:
    python_executable: str
    model_name: str
    local_files_only: bool
    process: subprocess.Popen | None = None
    startup_metadata: dict[str, Any] | None = None
    startup_timeout_seconds: float = _DEFAULT_WORKER_STARTUP_TIMEOUT_SECONDS
    inference_timeout_seconds: float = _DEFAULT_WORKER_INFERENCE_TIMEOUT_SECONDS
    _lock: Any = field(default_factory=threading.Lock, init=False, repr=False)
    _stdout_buffer: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _request_id: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        self.startup_timeout_seconds = _positive_timeout(
            self.startup_timeout_seconds, "startup_timeout_seconds"
        )
        self.inference_timeout_seconds = _positive_timeout(
            self.inference_timeout_seconds, "inference_timeout_seconds"
        )

    @contextmanager
    def _serialized(self, timeout: float):
        if not self._lock.acquire(timeout=max(0.0, timeout)):
            # This caller does not own the worker; leave the active request alone.
            raise RuntimeError("OpenAI privacy-filter worker queue timeout")
        try:
            yield
        finally:
            self._lock.release()

    def __call__(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        deadline = time.monotonic() + self.inference_timeout_seconds
        with self._serialized(self.inference_timeout_seconds):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("OpenAI privacy-filter worker queue timeout")
            # Loading a replacement model has its own startup budget. Queue wait,
            # request writes and response reads share the inference budget.
            process = self._ensure_process_locked()
            deadline = time.monotonic() + remaining
            self._request_id += 1
            request_id = self._request_id
            try:
                request = json.dumps(
                    {"request_id": request_id, "text": text}, ensure_ascii=False
                ).encode("utf-8") + b"\n"
                self._write_request(process, request, deadline)
                response = self._read_message(process, deadline)
                if (
                    type(response.get("request_id")) is not int
                    or response["request_id"] != request_id
                ):
                    raise ValueError("Invalid worker response")
                if "error" in response:
                    if (
                        not isinstance(response["error"], str)
                        or not response["error"]
                        or "results" in response
                    ):
                        raise ValueError("Invalid worker error")
                else:
                    results = response.get("results")
                    if not isinstance(results, list) or not all(
                        isinstance(result, dict) for result in results
                    ):
                        raise ValueError("Invalid worker results")
                    return results
            except Exception as exc:
                self._reset_locked()
                raise RuntimeError(
                    "OpenAI privacy-filter worker inference failed "
                    f"({_worker_failure_category(exc)})"
                ) from None
            # A matching error reply is a completed, synchronized exchange. The
            # worker can handle the next request without loading the model again.
            raise RuntimeError(
                "OpenAI privacy-filter worker inference failed (model error)"
            ) from None

    def _ensure_process(self) -> subprocess.Popen:
        with self._serialized(self.startup_timeout_seconds):
            return self._ensure_process_locked()

    def _ensure_process_locked(self) -> subprocess.Popen:
        if self.process is not None and self.process.poll() is None:
            return self.process
        self._reset_locked()
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                [
                    self.python_executable,
                    "-m",
                    "lsdf.scanners.openai_privacy_filter_worker",
                    "--model-name",
                    self.model_name,
                    "--local-files-only",
                    "1" if self.local_files_only else "0",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                # Model diagnostics can contain input text and can fill a pipe.
                # Discard them; callers receive only fixed failure categories.
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
            self.process = process
            assert process.stdin is not None and process.stdout is not None
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            ready = self._read_message(
                process, started + self.startup_timeout_seconds
            )
            if (
                ready.get("status") != "ready"
                or "error" in ready
                or not isinstance(ready.get("metadata", {}), dict)
            ):
                raise ValueError("Invalid worker readiness")
            metadata = dict(ready.get("metadata", {}))
            metadata["worker_start_seconds"] = round(time.monotonic() - started, 6)
            self.startup_metadata = metadata
            return process
        except Exception as exc:
            self._reset_locked()
            raise RuntimeError(
                "OpenAI privacy-filter worker startup failed "
                f"({_worker_failure_category(exc)})"
            ) from None

    @staticmethod
    def _wait_for_pipe(pipe: Any, event: int, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        with selectors.DefaultSelector() as selector:
            selector.register(pipe, event)
            if not selector.select(remaining):
                raise TimeoutError

    def _write_request(
        self, process: subprocess.Popen, request: bytes, deadline: float
    ) -> None:
        assert process.stdin is not None
        offset = 0
        while offset < len(request):
            self._wait_for_pipe(process.stdin, selectors.EVENT_WRITE, deadline)
            try:
                written = os.write(
                    process.stdin.fileno(), request[offset : offset + 65536]
                )
            except BlockingIOError:
                continue
            if written <= 0:
                raise EOFError
            offset += written

    def _read_message(
        self, process: subprocess.Popen, deadline: float
    ) -> dict[str, Any]:
        assert process.stdout is not None
        while True:
            # Consume a complete reply already read within the I/O budget before
            # deciding whether to wait for additional bytes.
            newline = self._stdout_buffer.find(b"\n")
            if newline >= 0:
                if newline > _MAX_WORKER_MESSAGE_BYTES:
                    raise ValueError("Worker response too large")
                line = bytes(self._stdout_buffer[:newline])
                del self._stdout_buffer[: newline + 1]
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("Invalid worker message")
                return message
            if len(self._stdout_buffer) > _MAX_WORKER_MESSAGE_BYTES:
                raise ValueError("Worker response too large")
            self._wait_for_pipe(process.stdout, selectors.EVENT_READ, deadline)
            try:
                chunk = os.read(process.stdout.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                raise EOFError
            self._stdout_buffer.extend(chunk)

    def _reset_locked(self) -> None:
        process = self.process
        self.process = None
        self.startup_metadata = None
        self._stdout_buffer.clear()
        if process is None:
            return
        # Kill before closing descriptors: no blocked reader/writer may hold a
        # pipe open while cleanup waits. Reap so failed startups cannot orphan.
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def close(self) -> None:
        with self._serialized(
            self.startup_timeout_seconds + self.inference_timeout_seconds + 2
        ):
            self._reset_locked()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


_DEFAULT_INSTALLED_SCORE_THRESHOLD = 0.85


def build_installed_openai_privacy_filter_detector(
    *,
    model_name: str | None = None,
    score_threshold: float | None = None,
    merge_gap: int = 1,
    local_files_only: bool | None = None,
    startup_timeout_seconds: float | None = None,
    inference_timeout_seconds: float | None = None,
) -> OpenAIPrivacyFilterDetector:
    model_name = model_name or os.environ.get(
        "LSDF_OPENAI_PRIVACY_FILTER_MODEL",
        "openai/privacy-filter",
    )
    if score_threshold is None:
        # 0.85 cuts utility_matrix benign findings from 27 → 3 (~90%)
        # vs the bare class default 0.50, with no recall loss on either the
        # credential-shape corpus (piece_b_replay) or the ML-only PII corpus
        # (piece_b_replay_ml_pii — international phone formats + multi-cultural
        # given names that the regex layer cannot catch; each fires at ≈1.00
        # privacy-filter confidence, leaving ~15 pts of headroom). Harder PII
        # shapes could still land in the 0.70–0.84 band; env override
        # `LSDF_OPENAI_PRIVACY_FILTER_SCORE_THRESHOLD` lets operators retune
        # without rebuilding the image.
        env_threshold = os.environ.get("LSDF_OPENAI_PRIVACY_FILTER_SCORE_THRESHOLD")
        if env_threshold:
            try:
                score_threshold = float(env_threshold)
            except ValueError:
                score_threshold = _DEFAULT_INSTALLED_SCORE_THRESHOLD
        else:
            score_threshold = _DEFAULT_INSTALLED_SCORE_THRESHOLD
    if not 0.0 <= float(score_threshold) <= 1.0:
        raise ValueError(
            "OpenAIPrivacyFilterDetector score_threshold must be in [0.0, 1.0]; "
            f"got {score_threshold!r}. Check LSDF_OPENAI_PRIVACY_FILTER_SCORE_THRESHOLD."
        )
    if local_files_only is None:
        local_files_only = _env_bool("LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY", True)
    worker_python = _privacy_filter_worker_python()
    if worker_python:
        provider = SubprocessPrivacyFilterProvider(
            python_executable=worker_python,
            model_name=model_name,
            local_files_only=local_files_only,
            startup_timeout_seconds=_worker_timeout(
                startup_timeout_seconds,
                "LSDF_OPENAI_PRIVACY_FILTER_STARTUP_TIMEOUT_SECONDS",
                _DEFAULT_WORKER_STARTUP_TIMEOUT_SECONDS,
            ),
            inference_timeout_seconds=_worker_timeout(
                inference_timeout_seconds,
                "LSDF_OPENAI_PRIVACY_FILTER_INFERENCE_TIMEOUT_SECONDS",
                _DEFAULT_WORKER_INFERENCE_TIMEOUT_SECONDS,
            ),
        )
        try:
            provider._ensure_process()
        except Exception as exc:  # pragma: no cover - depends on optional worker env.
            cache_note = "cached locally" if local_files_only else "downloadable/available"
            raise RuntimeError(
                "Unable to load OpenAI privacy-filter model "
                f"'{model_name}' in worker ({cache_note}). Set "
                "LSDF_OPENAI_PRIVACY_FILTER_PYTHON, LSDF_OPENAI_PRIVACY_FILTER_MODEL, "
                "or provide detector_providers for mocked/custom output."
            ) from exc
        metadata = {
            "implementation": "transformers.token-classification.worker",
            "model_name": model_name,
            "local_files_only": local_files_only,
            "score_threshold": score_threshold,
        }
        if provider.startup_metadata:
            metadata.update(provider.startup_metadata)
        return OpenAIPrivacyFilterDetector(
            provider,
            score_threshold=score_threshold,
            merge_gap=merge_gap,
            provider_metadata=metadata,
        )
    try:
        from transformers import (
            AutoModelForTokenClassification,
            AutoTokenizer,
            pipeline,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Install transformers and a supported model cache to enable detector family "
            "'openai_privacy_filter'"
        ) from exc
    started = time.perf_counter()
    try:
        tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            local_files_only=local_files_only,
        )
        model = AutoModelForTokenClassification.from_pretrained(
            model_name,
            local_files_only=local_files_only,
        )
        classifier = pipeline(
            "token-classification",
            model=model,
            tokenizer=tokenizer,
            aggregation_strategy="none",
            device=-1,
        )
    except Exception as exc:  # pragma: no cover - depends on optional model cache shape.
        cache_note = "cached locally" if local_files_only else "downloadable/available"
        raise RuntimeError(
            "Unable to load OpenAI privacy-filter model "
            f"'{model_name}' ({cache_note}). Set LSDF_OPENAI_PRIVACY_FILTER_MODEL "
            "or provide detector_providers for mocked/custom output."
        ) from exc
    load_seconds = time.perf_counter() - started
    metadata = {
        "implementation": "transformers.token-classification",
        "model_name": model_name,
        "local_files_only": local_files_only,
        "load_seconds": round(load_seconds, 6),
    }
    parameter_count = _parameter_count(model)
    if parameter_count is not None:
        metadata["parameter_count"] = parameter_count
    metadata["score_threshold"] = score_threshold
    return OpenAIPrivacyFilterDetector(
        TransformersPrivacyFilterProvider(classifier),
        score_threshold=score_threshold,
        merge_gap=merge_gap,
        provider_metadata=metadata,
    )


def _span_from_result(result: Any) -> dict[str, Any] | None:
    category = _category(result)
    if not category:
        return None
    start = int(_field(result, "start", _field(result, "start_offset", 0)))
    end = int(_field(result, "end", _field(result, "end_offset", 0)))
    score = float(_field(result, "score", _field(result, "confidence", 0.0)))
    if start >= end:
        return None
    return {
        "category": category,
        "start": start,
        "end": end,
        "score": score,
        "source_span_count": 1,
        "source_scores": [score],
    }


def _category(result: Any) -> str | None:
    value = (
        _field(result, "category")
        or _field(result, "entity_group")
        or _field(result, "entity")
        or _field(result, "label")
    )
    if value is None:
        return None
    category = str(value).lower()
    for prefix in ("b-", "i-", "e-", "s-"):
        if category.startswith(prefix):
            category = category[len(prefix) :]
    return category


def _merge_spans(spans: list[dict[str, Any]], merge_gap: int) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for span in sorted(spans, key=lambda item: (item["start"], item["end"])):
        if not merged:
            merged.append(span)
            continue
        previous = merged[-1]
        same_category = previous["category"] == span["category"]
        near = span["start"] <= previous["end"] + merge_gap
        if same_category and near:
            previous["end"] = max(previous["end"], span["end"])
            previous["score"] = max(previous["score"], span["score"])
            previous["source_span_count"] += span["source_span_count"]
            previous["source_scores"].extend(span["source_scores"])
            continue
        merged.append(span)
    return merged


def _field(result: Any, name: str, default: Any = None) -> Any:
    if isinstance(result, dict):
        return result.get(name, default)
    return getattr(result, name, default)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _positive_timeout(value: Any, name: str) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{name} must be a positive finite number of seconds") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"{name} must be a positive finite number of seconds")
    return timeout


def _worker_timeout(value: Any, name: str, default: float) -> float:
    if value is not None:
        return _positive_timeout(value, name)
    configured = os.environ.get(name)
    if configured is None or not configured.strip():
        return default
    return _positive_timeout(configured, name)


def _worker_failure_category(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, EOFError):
        return "closed pipe"
    if isinstance(exc, OSError):
        return "I/O error"
    return "invalid response"


def _privacy_filter_worker_python() -> str | None:
    configured = os.environ.get("LSDF_OPENAI_PRIVACY_FILTER_PYTHON")
    if configured is not None:
        try:
            valid = bool(configured) and Path(configured).is_file() and os.access(
                configured, os.X_OK
            )
        except (OSError, ValueError):
            valid = False
        if not valid:
            raise ValueError(
                "LSDF_OPENAI_PRIVACY_FILTER_PYTHON must name an executable file"
            )
        return configured
    default = Path("/opt/lsdf-openai-privacy-filter/bin/python")
    return str(default) if default.is_file() and str(default) != sys.executable else None


def _parameter_count(model: Any) -> int | None:
    try:
        return int(sum(parameter.numel() for parameter in model.parameters()))
    except Exception:
        return None
