PACKAGE := handshaker
BIN := target/release/$(PACKAGE)

.PHONY: all build debug run test fmt ci clean

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

fmt:
	cargo fmt --all || true

ci: fmt test build

clean:
	cargo clean
