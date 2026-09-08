FROM python:3.11-slim AS runtime-base

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace/src

WORKDIR /workspace

COPY pyproject.toml README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md ./
COPY src/ src/
COPY policies/ policies/
# Policy validation requires the first-party foundation fixtures.
COPY tests/foundation/fixtures/ tests/foundation/fixtures/
COPY evals/safety_matrix.json evals/utility_matrix.json evals/observability_matrix.json evals/

RUN pip install --no-cache-dir -e .

EXPOSE 8080
ENTRYPOINT ["python3", "-m", "lsdf.cli"]
CMD ["gateway", "--host", "0.0.0.0", "--port", "8080"]

FROM runtime-base AS base

COPY . .
ENTRYPOINT []
CMD ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]

FROM runtime-base AS runtime-optional

ENV HF_HOME=/opt/lsdf-cache/huggingface \
    LSDF_OPENAI_PRIVACY_FILTER_LOCAL_FILES_ONLY=true \
    LSDF_PROFILE=broad-pii-ml

RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.11.0+cpu && \
    pip install --no-cache-dir presidio-analyzer==2.2.362 transformers==4.51.0 gliner==0.2.22 && \
    python3 -m venv --system-site-packages /opt/lsdf-openai-privacy-filter && \
    /opt/lsdf-openai-privacy-filter/bin/pip install --no-cache-dir transformers==5.7.0 && \
    pip install --no-cache-dir https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl

ENV LSDF_OPENAI_PRIVACY_FILTER_PYTHON=/opt/lsdf-openai-privacy-filter/bin/python

FROM runtime-optional AS optional-detectors

COPY . .
ENV LSDF_PROFILE=default
ENTRYPOINT []
CMD ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]

# A build without --target produces the lightweight gateway.
FROM runtime-base AS runtime
