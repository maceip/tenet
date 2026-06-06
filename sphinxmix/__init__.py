# -*- coding: utf-8 -*-
"""The ``sphinxmix`` package implements the Outfox mix packet format
and P-OR mixnet protocol.

Outfox (Rial, Piotrowska, Halpin, 2025) uses per-hop KEM, AEAD headers,
HKDF key derivation, LIONESS PRP for payload encryption, and ML-DSA-65
signatures. The packet format is extended with per-layer timestamps,
dummy traffic flags, and return-path circuit support.

Security properties validated by the proof suite (Scherer et al., 2023):
  - GDH assumption (KEM rejects degenerate shared secrets)
  - Service model (payload tagging detected at exit, PRP destroys contents)
  - Nymserver elimination (SURB embedded in forward payload)
"""

VERSION = "0.1.0"

class SphinxException(Exception):
    pass
