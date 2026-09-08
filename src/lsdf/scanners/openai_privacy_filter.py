# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
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


@dataclass
class SubprocessPrivacyFilterProvider:
    python_executable: str
    model_name: str
    local_files_only: bool
    process: subprocess.Popen | None = None
    startup_metadata: dict[str, Any] | None = None

    def __call__(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        process = self._ensure_process()
        request = json.dumps({"text": text}, ensure_ascii=False)
        assert process.stdin is not None
        assert process.stdout is not None
        try:
            process.stdin.write(request + "\n")
            process.stdin.flush()
            response_line = process.stdout.readline()
        except BrokenPipeError as exc:
            self.process = None
            raise RuntimeError("OpenAI privacy-filter worker exited before responding") from exc
        if not response_line:
            stderr = _worker_stderr_tail(process)
            self.process = None
            raise RuntimeError(
                "OpenAI privacy-filter worker returned no response"
                + (f": {stderr}" if stderr else "")
            )
        response = json.loads(response_line)
        if response.get("error"):
            raise RuntimeError(str(response["error"]))
        return list(response.get("results") or [])

    def _ensure_process(self) -> subprocess.Popen:
        if self.process is not None and self.process.poll() is None:
            return self.process
        started = time.perf_counter()
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
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        assert process.stdout is not None
        ready_line = process.stdout.readline()
        if not ready_line:
            stderr = _worker_stderr_tail(process)
            self.process = None
            raise RuntimeError(
                "OpenAI privacy-filter worker failed to start"
                + (f": {stderr}" if stderr else "")
            )
        ready = json.loads(ready_line)
        if ready.get("error"):
            self.process = None
            raise RuntimeError(str(ready["error"]))
        self.process = process
        metadata = dict(ready.get("metadata") or {})
        metadata["worker_start_seconds"] = round(time.perf_counter() - started, 6)
        self.startup_metadata = metadata
        return process

    def close(self) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        for pipe in (process.stdin, process.stdout, process.stderr):
            try:
                if pipe is not None:
                    pipe.close()
            except Exception:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def __del__(self) -> None:
        self.close()


_DEFAULT_INSTALLED_SCORE_THRESHOLD = 0.85


def build_installed_openai_privacy_filter_detector(
    *,
    model_name: str | None = None,
    score_threshold: float | None = None,
    merge_gap: int = 1,
    local_files_only: bool | None = None,
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


def _privacy_filter_worker_python() -> str | None:
    configured = os.environ.get("LSDF_OPENAI_PRIVACY_FILTER_PYTHON")
    if configured:
        return configured if Path(configured).exists() else None
    default = Path("/opt/lsdf-openai-privacy-filter/bin/python")
    return str(default) if default.exists() and str(default) != sys.executable else None


def _worker_stderr_tail(process: subprocess.Popen) -> str:
    stderr = process.stderr
    if stderr is None:
        return ""
    try:
        return stderr.read()[-500:]
    except Exception:
        return ""


def _parameter_count(model: Any) -> int | None:
    try:
        return int(sum(parameter.numel() for parameter in model.parameters()))
    except Exception:
        return None
