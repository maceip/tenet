"""tenet — the expert-routing network.

Layered platform, dependencies pointing down only:

    packet (Sphinx packet format)
      -> mixnet (sealed-routing substrate)
        -> enclave (attested-workload host)
          -> capabilities (experts, llm, ...)
            -> edges (cli, ...)

The substrate never imports a capability or edge. This is enforced by
``tests/test_layering.py``, not by documentation. A new contributor picks the
folder for their archetype (capability / workload / transport / provider / edge)
and the import direction is checked in CI.
"""
