#!/bin/sh
# Legacy EIF entry: in-TEE stub relay+expert (gate A demo only — item 9 shortcut).
ip link set lo up 2>/dev/null || true
ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
cd /app
PYTHONPATH=/app MATCHER_HOST=127.0.0.1 MATCHER_PORT=8080 python3.11 run_matcher_live.py &
exec bountynet enclave /app --cmd true
