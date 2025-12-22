use crate::environment::Environment;
use crate::limits::ExecutionLimits;
use crate::sandbox::ExecutionResult;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Initialization error: {0}")]
    Initialization(String),
    #[error("Execution error: {0}")]
    Execution(String),
    #[error("Resource limit exceeded: {0}")]
    LimitExceeded(String),
}

/// Abstract interface for a JavaScript engine
pub trait SandboxEngine: Send + Sync {
    /// Execute codes in the engine with limits and environment
    fn execute(
        &self,
        code: &str,
        limits: &ExecutionLimits,
        env: &Environment,
    ) -> Result<ExecutionResult, EngineError>;
}

#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "wasm")]
pub mod wasm;

/// Get the default engine for the current platform
pub fn get_default_engine() -> Box<dyn SandboxEngine> {
    #[cfg(feature = "wasm")]
    {
        Box::new(wasm::WasmQuickJsEngine::new())
    }
    #[cfg(all(not(feature = "wasm"), feature = "native"))]
    {
        Box::new(native::RQuickJsEngine::new())
    }
    #[cfg(all(not(feature = "wasm"), not(feature = "native")))]
    {
        panic!("No JavaScript engine enabled! Enable 'native' or 'wasm' feature.")
    }
}
