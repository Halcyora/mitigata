# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS node_runtime

FROM python:3.11-slim

WORKDIR /app

COPY --from=node_runtime /usr/local/bin/node /usr/local/bin/node

COPY engine/requirements.txt /tmp/requirements.txt
RUN --mount=type=secret,id=custom_ca,required=false \
    if [ -f /run/secrets/custom_ca ]; then \
        cp /run/secrets/custom_ca /usr/local/share/ca-certificates/custom-ca.crt \
        && update-ca-certificates \
        && PIP_CERT=/etc/ssl/certs/ca-certificates.crt pip install --no-cache-dir -r /tmp/requirements.txt; \
    else \
        pip install --no-cache-dir -r /tmp/requirements.txt; \
    fi

COPY engine /app/engine
COPY app /app/app
COPY scripts /app/scripts

# Cache the exact model revision into the image so scans run locally and do not
# spend their five-minute DAST budget downloading model weights.
ENV HF_HOME=/opt/huggingface-cache
RUN python -c "from transformers import AutoModel, AutoTokenizer; model='microsoft/graphcodebert-base'; rev='9b8660679da59fe3e7423b03efa48d41944eec42'; AutoTokenizer.from_pretrained(model, revision=rev, use_fast=True); AutoModel.from_pretrained(model, revision=rev, use_safetensors=True)"

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "engine.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
