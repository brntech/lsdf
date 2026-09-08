# Integration Recipes

Date: 2026-04-28

Use LSDF as an OpenAI-compatible proxy at `http://localhost:8080/v1`. Keep all LSDF commands inside Docker Compose.

## Start The Gateway

Demo upstream:

```bash
docker compose up demo-upstream
```

Gateway:

```bash
docker compose run --rm cli init --upstream demo --audit-jsonl-path /workspace/.lsdf/audit.jsonl --metrics-jsonl-path /workspace/.lsdf/metrics.jsonl --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

LiteLLM Proxy:

```bash
docker compose run --rm cli init --upstream litellm --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

Recommended topology:

```text
app -> LSDF gateway -> LiteLLM Proxy -> provider fleet
```

Dependency-free topology smoke, using an OpenAI-compatible proxy-shaped service rather than bundling LiteLLM itself. The runner uses SSE streaming so this catches LSDF/proxy streaming URL and response-shape issues:

```bash
docker compose --profile litellm-demo up --build --abort-on-container-exit --exit-code-from litellm-demo-runner litellm-demo-runner
docker compose --profile litellm-demo down
```

OpenRouter:

```bash
docker compose run --rm cli init --upstream openrouter --output .lsdf.env --force
docker compose --env-file .lsdf.env up gateway
```

Set upstream provider keys outside committed files. Application clients still point at `http://localhost:8080/v1`; LSDF forwards to `https://openrouter.ai/api/v1`.

One-command golden demo:

```bash
docker compose --profile demo up --build --abort-on-container-exit --exit-code-from demo-runner demo-runner
```

LM Studio:

```bash
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:1234 \
  docker compose up gateway
```

Local vLLM:

```bash
LSDF_UPSTREAM_BASE_URL=http://host.docker.internal:8000 \
  docker compose up gateway
```

Generic OpenAI-compatible provider:

```bash
LSDF_UPSTREAM_BASE_URL=https://provider.example \
LSDF_UPSTREAM_API_KEY=your-provider-key \
  docker compose up gateway
```

## OpenRouter Via LSDF

Curl through LSDF:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "content-type: application/json" \
  -H "authorization: Bearer local-dev-key" \
  -d '{"model":"openrouter/auto","messages":[{"role":"user","content":"hello"}]}'
```

Python OpenAI-compatible client:

```python
from openai import OpenAI

client = OpenAI(base_url="http://localhost:8080/v1", api_key="local-dev-key")
response = client.chat.completions.create(
    model="openrouter/auto",
    messages=[{"role": "user", "content": "hello"}],
)
```

JavaScript OpenAI-compatible client:

```javascript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8080/v1",
  apiKey: "local-dev-key",
});

const response = await client.chat.completions.create({
  model: "openrouter/auto",
  messages: [{ role: "user", content: "hello" }],
});
```

LiteLLM application code can still point at LSDF:

```python
import litellm

response = litellm.completion(
    model="openai/openrouter/auto",
    api_base="http://localhost:8080/v1",
    api_key="local-dev-key",
    messages=[{"role": "user", "content": "hello"}],
)
```

OpenRouter app-attribution headers are optional provider metadata. Configure them in the application or upstream gateway if needed; LSDF does not rewrite attribution headers in this pass.

## Curl

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "content-type: application/json" \
  -d @examples/quickstart/response_redact_request.json
```

Streaming:

```bash
curl -N http://localhost:8080/v1/chat/completions \
  -H "content-type: application/json" \
  -d @examples/quickstart/stream_redact_request.json
```

## OpenAI-Compatible Python Client

Configure the client base URL to LSDF:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="not-used-by-lsdf",
)

response = client.chat.completions.create(
    model="local-model",
    messages=[{"role": "user", "content": "Summarize this account note."}],
)
```

## LangChain

Point the OpenAI-compatible model wrapper at LSDF:

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="http://localhost:8080/v1",
    api_key="not-used-by-lsdf",
    model="local-model",
)
```

## LlamaIndex

```python
from llama_index.llms.openai_like import OpenAILike

llm = OpenAILike(
    api_base="http://localhost:8080/v1",
    api_key="not-used-by-lsdf",
    model="local-model",
)
```

## LiteLLM

```python
import litellm

response = litellm.completion(
    model="openai/local-model",
    api_base="http://localhost:8080/v1",
    api_key="not-used-by-lsdf",
    messages=[{"role": "user", "content": "Summarize this note."}],
)
```

## OpenAI-Compatible JavaScript Client

```javascript
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://localhost:8080/v1",
  apiKey: "not-used-by-lsdf",
});

const response = await client.chat.completions.create({
  model: "local-model",
  messages: [{ role: "user", content: "Summarize this account note." }],
});
```

## Runnable Integration Proof

The dependency-free runner exercises the same OpenAI-compatible shapes used by Python/JS clients, framework wrappers, RAG, streaming, tool calls, and observability hooks:

```bash
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario python-client --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario javascript-client --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario streaming-chat --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario rag-context --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario tool-call --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario observability
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario langchain --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario llamaindex --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario litellm --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario litellm-proxy --gateway-base-url http://host.docker.internal:8080/v1
docker compose run --rm python examples/integrations/runnable_client_examples.py --scenario end-to-end --gateway-base-url http://host.docker.internal:8080/v1
```

## Observability Sanitizer Hook

Use the CLI for shape-based trace/log/span payloads:

```bash
docker compose run --rm cli sanitize-observability examples/quickstart/observability.json
```

Use `logs.traces` semantics when explaining a trace payload:

```bash
docker compose run --rm cli explain examples/quickstart/observability.json --unknown-surface logs.traces
```

## Audit And Proof

Summarize gateway audit JSONL:

```bash
docker compose run --rm cli audit-summary .lsdf/audit.jsonl
```

Generate a safe protection report:

```bash
docker compose run --rm cli protection-report --format markdown
docker compose run --rm cli proof-bundle --output .lsdf/proof --format markdown
```

## Metrics, Vault, And Security Ops

```bash
docker compose run --rm cli metrics-summary .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli quickstart-report --gateway-base-url http://host.docker.internal:8080 --audit-jsonl-path .lsdf/audit.jsonl --metrics-jsonl-path .lsdf/metrics.jsonl --format markdown
docker compose run --rm cli vault status --vault-path .lsdf/vault.sqlite
docker compose run --rm cli vault check --vault-path .lsdf/vault.sqlite
docker compose run --rm cli audit-export .lsdf/audit.jsonl --target generic
docker compose run --rm cli security-report --format markdown
docker compose run --rm cli simulate-policy evals/basic.json --format markdown
```
