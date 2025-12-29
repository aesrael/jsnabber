# JSNabber

A high-performance **Hybrid JavaScript Analysis Sandbox** for detecting malicious behavior in untrusted code. JSNabber combines static analysis, dynamic execution, and function discovery to catch obfuscated malware that traditional scanners miss.

## 🎯 Features

- **Hybrid Analysis Engine**:
  - **Static Analysis**: Regex-based pattern detection for immediate risk flags (e.g., `eval`, `document.cookie`).
  - **Dynamic Execution**: Runs code in a secure QuickJS sandbox, logging all API calls (`fetch`, `atob`, `eval`).
  - **Function Discovery**: Automatically finds and executes dormant functions that aren't called by the main script (e.g., hidden backdoors).
- **Web Interface**: Clean, dark-mode UI for pasting code, uploading files, or fetching URLs.
- **Granular Instrumentation**: 
  - **Storage**: Tracking `localStorage` and `sessionStorage`.
  - **System**: Monitoring `process`, `require`, and Node.js stubs.
  - **Evasion**: Catching `Reflect`/`Proxy` usage and stealth signatures.
  - **DOM**: Flagging dynamic script and iframe child creation.
  - **Crypto**: Monitoring cryptographic operations and key access.
- **Portable Architecture**: Core engine runs on both Native (Rust/Tokio) and Edge (WASM/Cloudflare Workers).

## 🚀 Quick Start

### Prerequisites
- [Rust](https://rustup.rs/) (latest stable)

### Running the Server
Start the backend server and Web UI:

```bash
cargo run -p jsnabber-server
```

Then open **[http://localhost:3000](http://localhost:3000)** in your browser.

### Running Tests
Verify the engine against included malware samples:

```bash
cargo test --package jsnabber-core
```

## 📚 Documentation

- **[Technical Deep Dive](TECHNICAL_DEEP_DIVE.md)**: A comprehensive guide to the architecture, execution flow, and codebase.
- **[Malware Test Report](tests/malware-samples/README.md)**: Analysis results from real world samples.

## 🏗️ Project Structure

- `crates/jsnabber-core/`: The heart of the engine. Contains the sandbox, instrumentation, and analysis logic.
- `crates/jsnabber-server/`: Axum-based web server that hosts the API and static UI.
- `crates/jsnabber-worker/`: Cloudflare Worker adapter for edge deployment.
- `public/`: Static web assets (HTML/CSS/JS) for the frontend.
- `tests/malware-samples/`: Real-world malware samples for verification.

## 🛡️ Security Model

⚠️ **JSNabber assumes all analyzed code is hostile.**

- QuickJS provides isolation but is **not a robust security boundary** on its own.
- **Always deploy with OS-level isolation** (Docker containers, gVisor, or Cloudflare Workers isolates).
- Never run untrusted analysis on sensitive production infrastructure without proper sandboxing.

## License

MIT / Apache-2.0
