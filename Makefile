.PHONY: smoke test test-integration test-product test-live test-all install-aw verify-live plain-matcher enclave-check enclave-match demo-mailbox-e2e

ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

smoke:
	./scripts/smoke.sh

test: smoke

test-integration:
	./scripts/test.sh integration

test-product:
	./scripts/test.sh product

test-live:
	./scripts/test.sh live

test-all:
	./scripts/test.sh all

install-aw:
	./scripts/install-aw.sh

verify-live:
	./scripts/verify-live.sh

demo-mailbox-e2e:
	./scripts/demo-mailbox-e2e.sh

demo:
	./scripts/demo-live-product.sh

expert-plan:
	./scripts/demo-expert-plan-live.sh

oblivious-core:
	./scripts/build-oblivious-core.sh

plain-matcher:
	./scripts/run-plain-matcher.sh

enclave-check:
	python3 -m por enclave check

enclave-match:
	@test -n "$(PROMPT)" || (echo "usage: make enclave-match PROMPT='your question'" >&2; exit 2)
	python3 -m por enclave match --prompt "$(PROMPT)"
