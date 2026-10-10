.PHONY: all build test lint fmt cov check install clean rebuild help

## Default target
all: check

## Build in debug mode
build:
	cargo build --all-targets

## Run all tests
test:
	cargo test

## Run clippy with all warnings as errors
lint:
	cargo clippy --all-targets -- -D warnings

## Check formatting without modifying files
fmt:
	cargo fmt --all --check

## Run code coverage
cov:
	cargo llvm-cov

## Run fmt + lint + test + cov (required before every commit)
check: fmt lint test cov
	@echo "--- all checks passed"

## Install to ~/.cargo/bin
install:
	cargo install --path .

## Remove build artifacts
clean:
	cargo clean

## Clean, rebuild image, re-init, and run (requires Apple container CLI)
rebuild: clean install
	container image prune -a
	open-sandbox init --force
	open-sandbox build
	open-sandbox run

## Show available targets
help:
	@grep -E '^## ' Makefile | sed 's/## //'
