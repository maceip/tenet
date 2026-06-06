FROM node:22-bookworm-slim

ARG CLAUDE_CODE_VERSION=2.1.162

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

COPY dist/tenet-linux-x86_64 /usr/local/bin/tenet
COPY config/live-enclave.json /etc/tenet/live-enclave.json
COPY config/join-pack.json /etc/tenet/join-pack.json
COPY config/live-mailbox-client.json /etc/tenet/live-mailbox-client.json
COPY deploy/client-sim/entrypoint.sh /usr/local/bin/tenet-client-entrypoint

RUN chmod +x /usr/local/bin/tenet /usr/local/bin/tenet-client-entrypoint \
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
