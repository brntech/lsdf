# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-name", required=True)
    parser.add_argument("--local-files-only", choices=("0", "1"), default="1")
    args = parser.parse_args()

    local_files_only = args.local_files_only == "1"
    try:
        from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

        started = time.perf_counter()
        tokenizer = AutoTokenizer.from_pretrained(
            args.model_name,
            local_files_only=local_files_only,
        )
        model = AutoModelForTokenClassification.from_pretrained(
            args.model_name,
            local_files_only=local_files_only,
        )
        classifier = pipeline(
            "token-classification",
            model=model,
            tokenizer=tokenizer,
            aggregation_strategy="none",
            device=-1,
        )
        metadata = {
            "worker_model_class": type(model).__name__,
            "worker_tokenizer_class": type(tokenizer).__name__,
            "worker_load_seconds": round(time.perf_counter() - started, 6),
        }
        _write({"status": "ready", "metadata": metadata})
    except Exception as exc:
        _write({"error": f"{type(exc).__name__}: {exc}"})
        return 1

    for line in sys.stdin:
        try:
            request = json.loads(line)
            results = classifier(str(request.get("text", "")))
            _write({"results": _jsonable(results)})
        except Exception as exc:
            _write({"error": f"{type(exc).__name__}: {exc}"})
    return 0


def _write(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if hasattr(value, "item"):
        return value.item()
    return value


if __name__ == "__main__":
    raise SystemExit(main())
