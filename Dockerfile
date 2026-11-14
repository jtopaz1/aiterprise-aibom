# aiterprise-scan container: docker run --rm -v "$PWD:/src" ghcr.io/jtopaz1/aiterprise-scan
# The engine has no runtime dependencies; the image is the standard library plus one wheel.
FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip install --no-cache-dir --disable-pip-version-check build==1.6.1 setuptools==84.2.1 wheel==0.48.0 \
    && python -m build --wheel --no-isolation --outdir /dist

FROM python:3.12-slim
LABEL org.opencontainers.image.title="aiterprise-scan" \
      org.opencontainers.image.description="Local-first AI supply-chain scanner that emits an AI-BOM and judges it" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/jtopaz1/aiterprise-aibom"
COPY --from=build /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-deps /tmp/*.whl && rm /tmp/*.whl \
    && useradd --create-home --uid 10001 scanner
USER scanner
ENV AITERPRISE_HOME=/home/scanner/.aiterprise \
    AITERPRISE_CACHE_DIR=/home/scanner/.cache/aiterprise \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
ENTRYPOINT ["aiterprise-scan"]
CMD ["scan", "."]
