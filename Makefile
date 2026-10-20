.PHONY: build check test clippy run docker-up docker-down

build:
	cargo build --workspace

check:
	cargo fmt -- --check
	cargo check --workspace
	cargo test --workspace
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

run:
	cargo run -p the-standard-service

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down
