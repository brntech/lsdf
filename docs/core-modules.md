# Core Modules

## 1. Gateway

OpenAI-compatible API surface that can sit between applications and model providers.

## 2. Surface parser

Normalizes LLM request/response objects into scan surfaces.

## 3. Detection engine

Combines configured regex, entropy, medical-pattern, contextual, and separately installed detector families. Application-supplied detectors use the library registry extension point.

## 4. Policy engine

Matches findings by entity/category, surface, and confidence using the configured policy. Tenant, environment, and destination are not built-in rule matchers.

Rules support redact, mask, tokenize, block, replace, hash, and encrypt. Monitor mode or per-rule observe behavior records findings without ordinary enforcement. Manual approval is not implemented. See [Policy Model](policy-model.md).

## 5. Transformation engine

Applies redact, mask, tokenize, replace, hash, and encrypt actions. Reversible tokenization uses encrypted vault mode.

## 6. Tool-call firewall

Inspects model-returned tool-call arguments before release to the client, including assembled streamed arguments. The application owns actual tool execution; LSDF does not intercept a tool or MCP connection automatically.

## 7. RAG/context scanner

Scans retrieved documents and chunks before they are inserted into model context.

## 8. Trace/log sanitizer

Sanitizes supplied trace/log/span and transcript-like payloads through application library or CLI hooks. A distinct stored-transcript policy surface is not implemented.

## 9. Audit/event system

Records decisions without storing raw sensitive values unless explicitly configured.

## 10. Evaluation harness

Runs benchmark prompts and traces through the firewall to measure leakage reduction, false positives, overblocking, and latency.
