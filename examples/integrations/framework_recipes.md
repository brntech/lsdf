# Framework Recipes

Use LSDF as the OpenAI-compatible base URL: `http://localhost:8080/v1`.

## LangChain

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(base_url="http://localhost:8080/v1", api_key="not-used-by-lsdf", model="local-model")
```

## LlamaIndex

```python
from llama_index.llms.openai_like import OpenAILike

llm = OpenAILike(api_base="http://localhost:8080/v1", api_key="not-used-by-lsdf", model="local-model")
```

## LiteLLM

```python
import litellm

litellm.completion(
    model="openai/local-model",
    api_base="http://localhost:8080/v1",
    api_key="not-used-by-lsdf",
    messages=[{"role": "user", "content": "Summarize this note."}],
)
```
