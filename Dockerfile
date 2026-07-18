# syntax=docker/dockerfile:1.7
ARG DOCKERHUB_REGISTRY=docker.io
ARG UV_DEFAULT_INDEX
ARG UV_INDEX_URL
ARG UV_EXTRA_INDEX_URL

FROM ${DOCKERHUB_REGISTRY}/astral/uv:0.10.11 AS uv
FROM ${DOCKERHUB_REGISTRY}/library/python:3.12-slim
ARG UV_DEFAULT_INDEX
ARG UV_INDEX_URL
ARG UV_EXTRA_INDEX_URL

COPY --from=uv /uv /uvx /bin/

WORKDIR /srv/xdr-mock

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PATH="/srv/xdr-mock/.venv/bin:$PATH"

# 先按 lock 装运行时依赖（不含 dev、不装本项目），利用层缓存
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    if [ -n "${UV_DEFAULT_INDEX}" ]; then export UV_DEFAULT_INDEX="${UV_DEFAULT_INDEX}"; fi; \
    if [ -n "${UV_INDEX_URL}" ]; then export UV_INDEX_URL="${UV_INDEX_URL}"; fi; \
    if [ -n "${UV_EXTRA_INDEX_URL}" ]; then export UV_EXTRA_INDEX_URL="${UV_EXTRA_INDEX_URL}"; fi; \
    uv sync --frozen --no-dev --no-install-project

# 只拷代码，不拷厂商规范数据（DataOpenDocument 运行时通过 volume 挂载）
COPY app ./app
COPY config.example.yaml ./config.yaml

# 规范数据目录：把 trustguard-docs/xdr-api-data-specs 挂到 /data
ENV XDR_DATA_ROOT=/data/DataOpenDocument
ENV XDR_STATE_DB_PATH=/state/xdr_mock.sqlite3

EXPOSE 8443

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443"]
