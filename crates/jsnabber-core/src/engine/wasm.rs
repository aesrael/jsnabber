use crate::engine::{EngineError, SandboxEngine};
use crate::environment::Environment;
use crate::features::BehavioralFeatures;
use crate::instrumentation::InstrumentationLog;
use crate::limits::ExecutionLimits;
use crate::sandbox::ExecutionResult;
use quickjs_wasm_rs::JSContextRef;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct WasmQuickJsEngine;

impl WasmQuickJsEngine {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxEngine for WasmQuickJsEngine {
    fn execute(
        &self,
        code: &str,
        _limits: &ExecutionLimits, // Note: limits are enforced by Cloudflare Workers platform
        env: &Environment,
    ) -> Result<ExecutionResult, EngineError> {
        // quickjs-wasm-rs doesn't expose interrupt handlers.
        // Cloudflare Workers enforces CPU time limits (10-50ms) at the platform level.
        let start_time = Instant::now();
        let instr_log = Arc::new(Mutex::new(InstrumentationLog::new(1000)));

        let mut context = JSContextRef::default();

        // Register hooks (WASM version)
        crate::instrumentation::register_wasm_hooks(&mut context, Arc::clone(&instr_log))
            .map_err(|e| EngineError::Initialization(e.to_string()))?;

        crate::environment::register_wasm_environment(&mut context, env)
            .map_err(|e| EngineError::Initialization(e.to_string()))?;

        let result = context.eval_global("main.js", code);

        let (completed, error, return_value) = match result {
            Ok(value) => {
                let json = match value.as_str() {
                    Ok(s) => Some(s.to_string()),
                    Err(_) => None,
                };
                (true, None, json)
            }
            Err(e) => (false, Some(format!("{:?}", e)), None),
        };

        let logs = instr_log.lock().unwrap().entries().to_vec();
        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        let res = ExecutionResult {
            completed,
            instruction_count: 0, // Not supported in this setup
            execution_time_ms,
            peak_memory_bytes: None,
            error,
            return_value,
            logs,
            env: env.clone(),
            features: BehavioralFeatures::default(),
            analysis: crate::sandbox::AnalysisMetadata::default(),
        };

        Ok(ExecutionResult {
            features: BehavioralFeatures::extract(&res, code.len()),
            ..res
        })
    }
}
