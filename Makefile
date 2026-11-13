# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

NODE ?= node
REUSE ?= reuse

.PHONY: check build test lint reuse family lockstep example

check: build lint reuse test example

build:
	$(NODE) --no-warnings=ExperimentalWarning scripts/build.mjs

test:
	$(NODE) --test test/*.test.ts

lint:
	$(NODE) scripts/lint.mjs

reuse:
	$(REUSE) lint

family:
	./scripts/family.sh

lockstep:
	./scripts/lockstep.sh

example:
	$(NODE) examples/quickstart.ts
