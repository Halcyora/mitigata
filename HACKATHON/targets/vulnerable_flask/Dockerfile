FROM python:3.11-slim-bookworm

WORKDIR /apps

ENV APP_PORT=5050 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt /tmp/requirements.txt
COPY wheelhouse/ /tmp/wheels/
RUN pip install --no-cache-dir --no-index --find-links=/tmp/wheels \
    -r /tmp/requirements.txt

COPY source/app/ /apps/
COPY patch_runtime.py /tmp/patch_runtime.py
RUN python /tmp/patch_runtime.py /apps/app.py \
    && mkdir -p /apps/Files /apps/instance \
    && chown -R 10001:10001 /apps

USER 10001:10001
EXPOSE 5050
CMD ["python", "app.py"]
