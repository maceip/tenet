# tenet demo — self-driving commerce (Berlin Airbnb)

**One line:** an agent is told to book a Berlin Airbnb; before it commits, it pays
**€0.05 EURD over x402 on Algorand** to ask a real Berlin expert (over the real
tenet mixnet) which listing to trust — and **switches its pick** when the expert
flags a scam. Real payment, real network, real verdict, no human in the loop.

> Tagline: **self-driving commerce.** Closer: **GET EXPERTS. GET GOING.**

---

## The scenario (what the audience sees)

A single Claude-Code agent window. The agent is told:

> *"Find me an Airbnb in Berlin — I don't want to deal with it."*

It has **3 real candidate listings**. It's about to book the cheapest, highest-rated
one. Then, before committing money, it consults the tenet expert network:

1. `HTTP 402 Payment Required` — €0.05 EURD on Algorand.
2. The agent **pays** → real Algorand **testnet** tx (Lora explorer link printed).
3. The question routes over the **real mixnet** (relay → attested-matched expert).
4. The Berlin expert (real Claude, grounded in opinionated local knowledge) answers:
   *"Listing A is Marzahn — 40 min out, recycled photos, classic scam. Skip it.
   Book Listing B — Neukölln / Reuterkiez. That's where Berlin actually lives."*
5. The agent **switches its pick A → B** and states why.

**The money beat:** the agent paid a stranger 5 cents over Algorand to *not* get
scammed — and it worked. We do **not** click "book" on Airbnb (that's one boring
API call); the *judgment* is the product, and that's what you pay for.

**Why it's not just an LLM wrapper:** all three hackathon levers are load-bearing
and visible — **x402** (the gate), **EURD/Algorand** (the rail, real tx on screen),
the **expert network** (the thing being bought). A chat prompt uses none of them.

---

## What is REAL vs. NARRATED (be honest on stage)

| Piece | Status |
|---|---|
| Mixnet routing (relay → expert, Outfox packets, reachability) | **REAL, live** — `scripts/demo/berlin_pick.py` |
| Berlin expert answer (Claude + injected local knowledge) | **REAL, live** |
| Attested matcher selecting the expert | **REAL** (PlainMatcher locally; live Nitro matcher at `5faf834eac20.aeon.site` is genuine & attested via `aw`) |
| x402 `402` → pay → on-chain settle (testnet) | **REAL** primitives, unit-tested (`tenet/x402.py`, `tenet/quantoz.py`) — wire to demo before stage |
| EURD specifically | EURD is **mainnet-only**; on testnet we settle **testnet USDC as the stand-in** (identical axfer, asset-id swaps for prod). Say this. |
| The actual Airbnb booking | **NOT done** — deliberately. Booking is one API call; judgment is the product. |
| Multi-expert consensus (reputation-weighted, flagged-expert `VOID`) | **NARRATED** for v1 (say it, show the `VOID` line on the site); full fan-out only if time. |

---

## Prereqs

- Python 3.12–3.14 (tested on 3.14).
- `ANTHROPIC_API_KEY` (lives in `~/fry-core/.env` on the dev box — `source` it; do not commit).
- Internet on the demo machine (for the one Anthropic call).
- For the live payment leg: a funded Algorand **testnet** account we control (see Focus areas).

---

## Run it — the SAFE path (single machine, recommended)

This is the bulletproof demo: one machine, loopback sockets, **no NAT, no firewall,
no cross-host networking** — the #1 way live network demos die. Verified to bootstrap
from a clean venv.

**macOS / Linux**
```bash
cd ~/tenet
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
source ~/fry-core/.env            # sets ANTHROPIC_API_KEY
python scripts/demo/berlin_pick.py --prompt "Get me an Airbnb in Berlin — which neighbourhood?"
```

**Windows (PowerShell)**
```powershell
cd $HOME\tenet
py -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -e .
$env:ANTHROPIC_API_KEY = "sk-ant-..."
python scripts\demo\berlin_pick.py --prompt "Get me an Airbnb in Berlin — which neighbourhood?"
```

Expected: clean output (logs are silenced), `[route] fallback_used = False`, then the
Neukölln verdict + scam flags. Without a key it prints a graceful transport-only reply
(proves routing) instead of crashing. Default model is `claude-haiku-4-5` (~2s);
pass `--model claude-sonnet-4-6` for a richer answer (~10s).

---

## Run it — the CROSS-MACHINE path (Windows asker ↔ EC2 expert) — ADVANCED

This is the impressive-but-fragile version (real two boxes). Only attempt with a
dry run done. Footguns: UDP ports/security groups, NAT, reachability relay, clock skew.

```bash
# On the EC2 host (relay + expert), open UDP ports in the security group first:
cd ~/tenet && python3 -m venv .venv && . .venv/bin/activate && pip install -e .
python -m tenet relay  --config cluster.json --node-id relay1 &
ANTHROPIC_API_KEY=... python -m tenet expert --config cluster.json --node-id expert_berlin &

# On the Windows/Mac asker:
python -m tenet send --config cluster.json --directory-snapshot snapshot.json \
  --prompt "Get me an Airbnb in Berlin" --expertise berlin-neighbourhoods --relay relay1
```
(`cluster.json` + `snapshot.json` must be generated and shared; the expert must be
reachable from the asker or registered through a public reachability relay.)

**Recommendation: demo the SAFE single-machine path on stage; keep cross-machine as a
"and it runs distributed" talking point unless we've rehearsed it on the real boxes.**

---

## The stage script (beat by beat, ~60s)

1. **Hook (say it):** *"I just booked an Airbnb and spent an hour second-guessing the
   neighborhood. I didn't want to be involved — I wanted it to be right."*
2. **Show terminal A:** *"Here's a Berlin local expert, online on the tenet network."*
3. **Show terminal B (the agent):** type the request. *"My agent is about to book the
   cheapest 4.8-star place."*
4. **The gate:** `402 Payment Required — €0.05 EURD on Algorand`. *"Before it spends my
   money, it has to pay an expert it can't fool."*
5. **Pay:** show the tx + Lora link. *"Real payment, real chain."*
6. **Verdict:** the expert flags Marzahn/scam, recommends Neukölln. Agent switches A→B.
7. **Close:** *"It paid a stranger five cents to not get scammed — and it worked.
   That's self-driving commerce."* → **GET EXPERTS. GET GOING.**

---

## Fallback plan (no way to fuck this up)

**One command — operationalized cascade (no join-pack, no live matcher, no keys required):**

```bash
cd ~/tenet
./scripts/demo/run-safe.sh
```

`run-safe.sh` tries in order:

1. **`present.py`** — stage screencast (needs `ANTHROPIC_API_KEY`; narrated x402 + real loopback mixnet)
2. **`berlin_pick.py`** — same real mixnet; without a key you still get a transport-only reply (`fallback_used = False`)
3. **`demo-recording.txt`** — offline replay of the last good rehearsal

Modes: `MODE=berlin|present|replay|sim-host|sim-clients ./scripts/demo/run-safe.sh`

- **No internet / Anthropic down:** `MODE=replay ./scripts/demo/run-safe.sh` or the site (`tenet-www`) self-animating terminal.
- **Key missing:** `MODE=berlin` still proves routing live (transport-only expert reply).
- **Payment leg not wired:** `present.py` narrates the 402/pay beat; mixnet + expert are real on loopback.
- **Cross-machine / live `tenet ask` flakes:** do **not** use production join-pack on stage; stay on `run-safe.sh` (single-machine simulator clients: relay + expert + asker on loopback).
- **Record another rehearsal:** `RECORD=1 ./scripts/demo/run-safe.sh MODE=berlin`

---

## Areas I want YOU to focus on

- **Pick the demo path.** Single-machine (safe, recommended) vs. Windows↔EC2 cross-host
  (impressive, fragile). I recommend single-machine on stage.
- **Fund a fresh testnet account we control** and hand me the address + mnemonic (a
  *native 25-word* Algorand account, or a fresh Pera "Algorand 25-word" export — **not**
  the Pera Universal 24-word HD one, which we can't sign). This unblocks a *real* on-chain
  tx in the demo.
- **Confirm the payment is real-on-testnet vs. narrated.** If real: I wire `402 → pay →
  verify on-chain → answer` and the terminal prints a real txid. If narrated: we ship the
  website terminal and save the time.
- **Decide the model:** `haiku` (~2s, snappy) vs `sonnet` (~10s, richer answer).
- **Lock the exact question + the 3 listings** (one obvious scam in Marzahn, one solid in
  Neukölln) so the expert's flag lands every time. Send me the 3 you want.
- **Windows / EC2 verification:** I can't reach those boxes from here. Either (a) run the
  one-command block above on each and paste the output, or (b) give me SSH/RDP and I'll
  verify live. Until then, single-machine Mac is the proven-safe path.
- **Demo machine + network:** which laptop runs it, and does the venue have reliable
  internet? If shaky, we pre-record a clean run as the hard fallback.
- **Keep `ANTHROPIC_API_KEY` on the demo machine** (in `~/fry-core/.env` or the shell) —
  it must not be committed.

---

## Files

- `scripts/demo/berlin_pick.py` — the live single-machine demo (relay + expert + asker,
  real Outfox routing, real Claude expert). **This is the runnable demo.**
- `tenet-www/` — the website (self-animating terminal showcase + fallback).
- `tenet/x402.py`, `tenet/quantoz.py`, `tenet/expert_pick.py`, `tenet/pick_server.py` —
  x402 / EURD / consensus building blocks for the payment leg.
