# oblivious-core

Constant-time oblivious top-K selection in Rust — in-TEE hardening of
`tenet/experts/oblivious.py` (**STATUS.md** items **6** / **7**).

Project status and queue: **`../STATUS.md`** only.

## Build (PyO3 extension)

From repo root:

```bash
./scripts/build-oblivious-core.sh
```

When installed, `tenet.experts.oblivious.oblivious_top_k` uses the Rust CMOV path automatically.

## Why

Inside the TEE the operator can't read content but can watch access patterns.
This crate uses [`subtle`](https://docs.rs/subtle) for branchless selects so the
timing trace is data-independent.

Verified: `cargo test`, `tests/test_oblivious_rust.py` when the extension is built.
