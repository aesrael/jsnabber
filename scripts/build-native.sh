#!/bin/bash
# Build script for native target (Linux/macOS/Windows)

set -e

echo "🔨 Building jsnabber for native..."

# Build all workspace members in release mode
cargo build --release --workspace

echo "✅ Native build complete!"
echo "📦 Binaries:"
echo "   - target/release/jsnabber-server"
ls -lh target/release/jsnabber-server 2>/dev/null || echo "   (server binary)"
