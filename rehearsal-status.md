# Demo rehearsal status — 2026-06-07

## Ready for stage

| Item | Status |
|---|---|
| **macOS / Linux / Windows binaries** | Built in `dist/` |
| **join-pack.json** | Re-rendered with fresh signing key (`config/beta-secrets.env`, gitignored) |
| **Berlin single-machine demo** | **REHEARSED** — see `demo-recording.txt` (real Claude, Neukölln verdict, scam flags) |
| **Asker bundle** | `dist/asker-bundle.zip` (join-pack + mailbox + all three binaries) |

### Stage command (safe path)

```bash
cd ~/tenet
./scripts/demo/run-safe.sh
```

Auto cascade: `present.py` (if key) → `berlin_pick.py` → `demo-recording.txt` replay.

Manual modes:

```bash
MODE=present ./scripts/demo/run-safe.sh          # screencast pacing (needs key)
MODE=berlin  ./scripts/demo/run-safe.sh          # raw mixnet demo (works without key)
MODE=replay  ./scripts/demo/run-safe.sh          # offline hard fallback
MODE=sim-host ./scripts/demo/run-safe.sh         # sim host mesh + berlin_pick
```

Expected live run: `fallback_used = False`, Neukölln recommendation, Marzahn scam warning.

---

## Not ready (live production `tenet ask`)

| Blocker | Detail |
|---|---|
| **ARC credential** | Live Nitro matcher returns `400 unsupported ARC credential version: tenet.arc.noop_credential.2026-06` — client sends noop ARC; deployed EIF expects a different version. Affects macOS after join-pack fix. |
| **Windows native `aw`** | Stripped PATH demo requires embedded `aw`; Windows binary was built without embed. macOS binary has embedded `aw`. |

Cross-host `deploy-network-clients.sh` was re-run after join-pack refresh; both LAN clients failed (Windows: no `aw`; WSL: prompt quoting + same ARC path if reached).

**Recommendation:** Demo `berlin_pick.py` on one Mac. Narrate live network / cross-platform from `demo.md`; do not rely on production `tenet ask` until matcher accepts client ARC or EIF is redeployed.

---

## Files

- `demo-recording.txt` — cleaned transcript of successful rehearsal
- `demo.md` — stage script and talking points
- `config/beta-secrets.env` — `TENET_JOIN_PACK_SIGNING_KEY_HEX` (do not commit)
