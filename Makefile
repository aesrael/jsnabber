.PHONY: help server worker dev deploy test clean

# Default target
help:
	@echo "JSNabber - Makefile Commands"
	@echo "=============================="
	@echo ""
	@echo "  make server    - Run native server (localhost:3000)"
	@echo "  make worker    - Run worker locally (localhost:8787)"
	@echo "  make dev       - Run both server and worker"
	@echo "  make deploy    - Deploy worker to Cloudflare"
	@echo "  make test      - Run all tests"
	@echo "  make clean     - Clean build artifacts"

# Development
server:
	@echo "🚀 Starting JSNabber Server on http://localhost:3000"
	cd crates/jsnabber-server && cargo run

worker:
	@echo "⚡ Starting Cloudflare Worker on http://localhost:8787"
	cd crates/jsnabber-worker && npx wrangler dev

dev:
	@echo "🚀 Starting both Server and Worker..."
	@make -j2 server worker

# Deployment
deploy:
	@echo "☁️  Deploying to Cloudflare..."
	cd crates/jsnabber-worker && npx wrangler deploy

# Testing
test:
	@echo "🧪 Running all tests..."
	cargo test --workspace

# Maintenance
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	rm -rf crates/jsnabber-worker/build
