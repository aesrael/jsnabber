#!/bin/bash
# Build script for WASM target (Cloudflare Workers)
# NOTE: Currently non-functional with rquickjs - see docs/WASM_STATUS.md

set -e

echo "🔨 Building jsnabber-core for WASM..."

# Install wasm32-unknown-unknown target if not present
rustup target add wasm32-unknown-unknown

# Check if wasm-pack is installed
if ! command -v wasm-pack &> /dev/null; then
    echo "⚠️  wasm-pack not found. Installing..."
    cargo install wasm-pack
fi

# Build the worker crate for WASM
echo "📦 Building worker crate..."
cd crates/jsnabber-worker
wasm-pack build --target bundler --release

echo "✅ WASM build complete!"
echo "📦 Output: crates/jsnabber-worker/pkg/"
