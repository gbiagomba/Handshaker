PACKAGE := handshaker
BIN := target/release/$(PACKAGE)

.PHONY: all build debug run test fmt ci clean generate-audit-matrix verify-docs

all: build

build:
	cargo build --release

debug:
	cargo build

run: build
	$(BIN) $(ARGS)

install:
	bash scripts/install.sh

test:
	cargo test --all

generate-audit-matrix:
	python3 scripts/generate_finding_audit_matrix.py

verify-docs:
	python3 scripts/check_finding_index_sync.py

fmt:
	cargo fmt --all || true

ci: fmt test build

clean:
	cargo clean
