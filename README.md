# JSNabber

A high-performance JavaScript dynamic analysis sandbox for detecting malicious behavior in untrusted code.

## Overview

JSNabber executes potentially malicious JavaScript in isolated sandboxes to extract behavioral features for classification. Built with Rust and QuickJS, it provides:

- **Edge-tier triage** via Cloudflare Workers (WASM)
- **Deep analysis** via native backend services
- **Portable architecture** - same core, multiple deployment targets
- **Resource limits** - instruction counting, memory limits, timeouts
- **API instrumentation** - track eval, fetch, timers, and more

## Architecture

```
┌─────────────────────────────────────┐
│  Rust Core (jsnabber-core)          │  ← Portable sandbox engine
│  - rquickjs execution harness       │
│  - Instrumentation & logging        │
│  - Feature extraction                │
└─────────────────────────────────────┘
         ↓                    ↓
    ┌─────────┐         ┌──────────┐
    │ Edge    │         │ Backend  │
    │ (WASM)  │         │ (Native) │
    └─────────┘         └──────────┘
```

## Project Structure

- `crates/jsnabber-core` - Core sandbox engine (portable)
- `crates/jsnabber-worker` - Cloudflare Worker (edge tier)
- `crates/jsnabber-server` - Backend analysis service
- `tests/` - Integration tests and malware samples
- `scripts/` - Build scripts (native only for now)

## Quick Start

### Development

```bash
# Run core tests
cargo test --package jsnabber-core

# Run all tests
cargo test --workspace

# Build for production
cargo build --release
```

### Usage

```rust
use jsnabber_core::{Sandbox, ExecutionLimits};

let sandbox = Sandbox::new(ExecutionLimits::edge())?;
let result = sandbox.execute(r#"
    console.log("Hello from sandbox!");
    eval("1 + 1");
"#)?;

println!("Instruction count: {}", result.instruction_count);
println!("API calls: {:?}", result.instrumentation_log);
```

## Security Model

⚠️ **JSNabber assumes all analyzed code is hostile.**

- QuickJS provides isolation but is **not a security boundary**
- Always deploy with OS-level isolation (containers, Workers isolates)
- Never run untrusted analysis on production infrastructure
- See [SECURITY.md](SECURITY.md) for details

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

This project is not yet open source but is designed with open-source best practices for future release.
