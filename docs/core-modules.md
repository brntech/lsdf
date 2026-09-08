# Core Modules

## 1. Gateway

OpenAI-compatible API surface that can sit between applications and model providers.

## 2. Surface parser

Normalizes LLM request/response objects into scan surfaces.

## 3. Detection engine

Combines regex detectors, entropy/secrets detectors, Presidio recognizers, NER recognizers, custom business recognizers, and contextual rules.

## 4. Policy engine

Decides what to do based on data type, surface, confidence, severity, tenant, environment, and destination.

Executable actions: allow, warn, redact, mask, tokenize, block, and log only. Manual approval is not implemented.

## 5. Transformation engine

Applies privacy-preserving transformations such as replacement, partial masking, hashing, encryption, reversible tokenization, and pseudonymization.

## 6. Tool-call firewall

Scans and enforces policy before tool execution. This is a core differentiator because tool-call arguments can carry sensitive data even when final assistant text appears safe.

## 7. RAG/context scanner

Scans retrieved documents and chunks before they are inserted into model context.

## 8. Trace/log sanitizer

Prevents sensitive data from entering observability systems, traces, logs, analytics, and transcript-like payloads. A distinct stored-transcript policy surface is not implemented.

## 9. Audit/event system

Records decisions without storing raw sensitive values unless explicitly configured.

## 10. Evaluation harness

Runs benchmark prompts and traces through the firewall to measure leakage reduction, false positives, overblocking, and latency.
