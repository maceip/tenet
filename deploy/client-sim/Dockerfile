FROM node:22-bookworm-slim

ARG CLAUDE_CODE_VERSION=2.1.162

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

# Primary path: pre-built static binary (produced by scripts/build_binary.py or CI).
# For development you can extend the build context or override the COPY to install
# the package from source using uv (see updated build-client-sim-image.sh).
COPY dist/tenet-linux-x86_64 /usr/local/bin/tenet || true
COPY config/live-enclave.json /etc/tenet/live-enclave.json || true
COPY config/join-pack.json /etc/tenet/join-pack.json || true
COPY config/live-mailbox-client.json /etc/tenet/live-mailbox-client.json || true
COPY deploy/client-sim/entrypoint.sh /usr/local/bin/tenet-client-entrypoint

RUN chmod +x /usr/local/bin/tenet /usr/local/bin/tenet-client-entrypoint 2>/dev/null || true \
  && mkdir -p /var/lib/tenet-client /var/log/tenet-client /workspace

ENV JOIN_PACK=/etc/tenet/join-pack.json \
    POR_TIMEOUT=120 \
    PROMPT=Monet \
    TENET_CLIENT_ID=client-sim-1 \
    TENET_NAT_PROFILE=nat \
    TENET_CONTEXT_DIR=/var/lib/tenet-client/context \
    TENET_LOG_DIR=/var/log/tenet-client

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/tenet-client-entrypoint"]
CMD ["ask"]
