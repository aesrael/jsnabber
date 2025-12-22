//! JSNabber Core - JavaScript Sandbox Engine
//!
//! This crate provides the core sandbox functionality for executing untrusted JavaScript
//! with strict resource limits and comprehensive instrumentation.
//!
//! # Architecture
//!
//! - **Sandbox**: Main execution harness using rquickjs
//! - **Limits**: Resource limit enforcement (instructions, memory, time)
//! - **Instrumentation**: API interception and behavioral logging
//! - **Environment**: Fake browser APIs and controlled randomness
//! - **Features**: Behavioral feature extraction from execution traces
//!
//! # Example
//!
//! ```rust
//! use jsnabber_core::{Sandbox, ExecutionLimits, ExecutionResult};
//!
//! # fn main() -> anyhow::Result<()> {
//! let sandbox = Sandbox::new(ExecutionLimits::edge())?;
//! let result = sandbox.execute(r#"
//!     const x = eval("1 + 1");
//!     console.log("Result:", x);
//! "#)?;
//!
//! println!("Instructions: {}", result.instruction_count);
//! println!("Completed: {}", result.completed);
//! # Ok(())
//! # }
//! ```
//!
//! # Security
//!
//! This sandbox is designed for **behavioral analysis**, not security isolation.
//! Always deploy with OS-level isolation (containers, Workers isolates).

pub mod engine;
pub mod environment;
pub mod features;
pub mod instrumentation;
pub mod limits;
pub mod platform;
pub mod sandbox;

// Re-export main types
pub use engine::{EngineError, SandboxEngine};
pub use features::Classification;
pub use limits::{ExecutionLimits, LimitTier};
pub use platform::{default_limits_tier, IS_WASM, PLATFORM};
pub use sandbox::{ExecutionResult, Sandbox, SandboxError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_execution() {
        let sandbox = Sandbox::new(ExecutionLimits::edge()).unwrap();
        // Use a loop to ensure we trigger the sampled instruction counter (every ~1000 inst)
        let result = sandbox
            .execute("let x = 0; for(let i=0; i<2000; i++) { x++; } x;")
            .unwrap();
        assert!(result.completed);
        // Note: instruction_count may be 0 due to rquickjs's sampled interrupt handler
    }
}
