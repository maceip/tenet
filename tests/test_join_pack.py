"""Join pack loader and renderer."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tenet.edges.cli.join_pack import JOIN_PACK_SCHEMA, JoinPack
from tenet.experts.live_enclave import LiveEnclaveConfig
from tenet.experts.live_client import LiveMailboxClientConfig


def test_render_join_pack_from_live_configs(tmp_path):
    root = Path(__file__).resolve().parents[1]
    enclave = root / "config" / "live-enclave.json"
    mailbox = root / "config" / "live-mailbox-client.json"
    if not enclave.is_file() or not mailbox.is_file():
        return

    out = tmp_path / "join-pack.json"
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "render-join-pack.py"),
            str(enclave),
            str(mailbox),
            str(out),
        ],
        check=True,
        cwd=root,
    )
    pack = JoinPack.load(out)
    assert pack.matcher_url().startswith("https://")
    assert "/v1/match" in pack.match_endpoint()
    LiveEnclaveConfig.from_dict(pack.matcher)
    LiveMailboxClientConfig.load(pack.asker_mailbox_config)

    raw = json.loads(out.read_text(encoding="utf-8"))
    assert raw["schema"] == JOIN_PACK_SCHEMA
