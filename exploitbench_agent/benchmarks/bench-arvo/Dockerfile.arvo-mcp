# Layers a portable Python 3.12 + MCP server onto an ARVO vulnerable image.
# Built per-bug: FROM n132/arvo:<id>-vul, add standalone python, override entrypoint.
# Standalone python runs on glibc 2.17+ so it works on ARVO's Ubuntu 16.04 bases.
ARG ARVO_BASE
FROM ${ARVO_BASE}
ARG ARVO_ID
ARG ARVO_PROJECT
ARG ARVO_FUZZ_TARGET
ARG ARVO_SANITIZER
ARG ARVO_CRASH_TYPE
# Install curl if missing (needed to fetch portable python)
RUN (command -v curl >/dev/null) || (apt-get update -qq && apt-get install -y -qq curl ca-certificates 2>/dev/null) || (yum install -y curl ca-certificates 2>/dev/null) || true
# Fetch portable CPython (python-build-standalone, Astral), ~50MB.
RUN mkdir -p /opt && cd /opt && \
    (curl -fsSL -o python.tar.gz https://github.com/astral-sh/python-build-standalone/releases/download/20250818/cpython-3.12.5+20250818-x86_64-unknown-linux-gnu-install_only.tar.gz \
     || curl -fsSL -o python.tar.gz https://github.com/astral-sh/python-build-standalone/releases/download/20240415/cpython-3.12.3+20240415-x86_64-unknown-linux-gnu-install_only.tar.gz) \
    && tar xzf python.tar.gz && rm python.tar.gz \
    && /opt/python/bin/python3 --version
RUN /opt/python/bin/python3 -m pip install --no-cache-dir "mcp>=1.1,<2"
RUN mkdir -p /rlenv/mcp /rlenv/problem /rlenv/workspace && chmod 777 /rlenv/workspace
COPY server.py /rlenv/mcp/server.py
COPY description.txt /rlenv/problem/description.txt
ENV ARVO_ID=${ARVO_ID} \
    ARVO_PROJECT=${ARVO_PROJECT} \
    ARVO_FUZZ_TARGET=${ARVO_FUZZ_TARGET} \
    ARVO_SANITIZER=${ARVO_SANITIZER} \
    ARVO_CRASH_TYPE=${ARVO_CRASH_TYPE} \
    ARVO_DESCRIPTION_PATH=/rlenv/problem/description.txt \
    RLENV_WORKSPACE_DIR=/rlenv/workspace \
    PATH=/opt/python/bin:${PATH}
ENTRYPOINT ["/opt/python/bin/python3", "/rlenv/mcp/server.py"]
