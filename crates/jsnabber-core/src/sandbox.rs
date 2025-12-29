use crate::engine::{get_default_engine, SandboxEngine};
use crate::limits::ExecutionLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during sandbox execution
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Failed to initialize runtime: {0}")]
    InitializationError(String),

    #[error("Execution exceeded instruction limit ({0} instructions)")]
    InstructionLimitExceeded(u64),

    #[error("Execution exceeded time limit ({0:?})")]
    TimeLimitExceeded(std::time::Duration),

    #[error("Execution exceeded memory limit")]
    MemoryLimitExceeded,

    #[error("JavaScript execution error: {0}")]
    ExecutionError(String),

    #[error("Invalid limits: {0}")]
    InvalidLimits(String),

    #[error("Engine error: {0}")]
    EngineError(String),
}

/// Metadata about how the code was analyzed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// How the code was executed (script, module, or strict mode fallback)
    pub execution_mode: ExecutionMode,
    /// Whether function discovery was performed
    pub function_discovery_enabled: bool,
    /// Number of functions discovered and executed
    pub functions_discovered: usize,
    /// Entry points that were automatically called
    pub entry_points_called: Vec<String>,
    /// Whether the code used ES6 imports
    pub used_es6_modules: bool,
    /// Whether unknown APIs were accessed (via fallback proxy)
    pub accessed_unknown_apis: bool,
    /// Static analysis results (pattern detection without execution)
    pub static_analysis: crate::static_analysis::StaticAnalysis,
}

/// How the JavaScript code was executed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExecutionMode {
    /// Executed as a standard script
    Script,
    /// Executed as an ES6 module
    Module,
    /// Executed in strict mode (without 'with' wrapper)
    StrictScript,
}

impl Default for AnalysisMetadata {
    fn default() -> Self {
        Self {
            execution_mode: ExecutionMode::Script,
            function_discovery_enabled: true,
            functions_discovered: 0,
            entry_points_called: Vec::new(),
            used_es6_modules: false,
            accessed_unknown_apis: false,
            static_analysis: crate::static_analysis::StaticAnalysis::default(),
        }
    }
}

/// Result of JavaScript execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether execution completed successfully
    pub completed: bool,
    /// Number of instructions executed
    pub instruction_count: u64,
    /// Wall-clock execution time in milliseconds
    pub execution_time_ms: u64,
    /// Peak memory usage in bytes (if available)
    pub peak_memory_bytes: Option<usize>,
    /// Error message if execution failed
    pub error: Option<String>,
    /// Return value (if any, as JSON)
    pub return_value: Option<String>,
    /// Instrumentation logs
    pub logs: Vec<crate::instrumentation::LogEntry>,
    /// Environment configuration (Phase 3)
    pub env: crate::environment::Environment,
    /// Behavioral features (Phase 4)
    pub features: crate::features::BehavioralFeatures,
    /// Analysis metadata - explains what was analyzed and how
    pub analysis: AnalysisMetadata,
}

/// Result of multi-environment execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiEnvironmentResult {
    /// Results from each environment
    pub results: Vec<ExecutionResult>,
    /// Whether all environments produced the same behavior
    pub consistent: bool,
    /// Variance metrics
    pub variance: EnvironmentVariance,
}

/// Variance metrics across environments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentVariance {
    /// Different return values observed
    pub unique_return_values: usize,
    /// Different error messages observed
    pub unique_errors: usize,
    /// Range of instruction counts (min, max)
    pub instruction_count_range: (u64, u64),
    /// Different log patterns observed
    pub unique_log_patterns: usize,
}

/// JavaScript sandbox using a pluggable engine
pub struct Sandbox {
    limits: ExecutionLimits,
    env: crate::environment::Environment,
    engine: Box<dyn SandboxEngine>,
}

impl Sandbox {
    /// Create a new sandbox with the given limits and default engine
    pub fn new(limits: ExecutionLimits) -> Result<Self, SandboxError> {
        limits.validate().map_err(SandboxError::InvalidLimits)?;

        Ok(Self {
            limits,
            env: crate::environment::Environment::default(),
            engine: get_default_engine(),
        })
    }

    /// Update environment configuration
    pub fn with_environment(mut self, env: crate::environment::Environment) -> Self {
        self.env = env;
        self
    }

    /// Execute JavaScript code in the sandbox
    pub fn execute(&self, code: &str) -> Result<ExecutionResult, SandboxError> {
        self.engine
            .execute(code, &self.limits, &self.env)
            .map_err(|e| SandboxError::EngineError(e.to_string()))
    }

    /// Execute JavaScript code in multiple environments
    pub fn execute_multi(
        &self,
        code: &str,
        environments: &[crate::environment::Environment],
    ) -> Result<MultiEnvironmentResult, SandboxError> {
        let mut results = Vec::new();

        for env in environments {
            let result = self
                .engine
                .execute(code, &self.limits, env)
                .map_err(|e| SandboxError::EngineError(e.to_string()))?;
            results.push(result);
        }

        let variance = calculate_variance(&results);
        let consistent = variance.unique_return_values <= 1 && variance.unique_errors <= 1;

        Ok(MultiEnvironmentResult {
            results,
            consistent,
            variance,
        })
    }
}

/// Calculate variance metrics across execution results
fn calculate_variance(results: &[ExecutionResult]) -> EnvironmentVariance {
    use std::collections::HashSet;

    let unique_return_values: HashSet<_> = results
        .iter()
        .map(|r| r.return_value.as_ref().map(|s| s.as_str()).unwrap_or(""))
        .collect();

    let unique_errors: HashSet<_> = results
        .iter()
        .map(|r| r.error.as_ref().map(|s| s.as_str()).unwrap_or(""))
        .filter(|s| !s.is_empty())
        .collect();

    let instruction_counts: Vec<_> = results.iter().map(|r| r.instruction_count).collect();
    let min_inst = *instruction_counts.iter().min().unwrap_or(&0);
    let max_inst = *instruction_counts.iter().max().unwrap_or(&0);

    // Simple log pattern comparison (count unique log sequences)
    let unique_log_patterns: HashSet<_> = results
        .iter()
        .map(|r| {
            r.logs
                .iter()
                .map(|log| format!("{:?}", log.event_type))
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();

    EnvironmentVariance {
        unique_return_values: unique_return_values.len(),
        unique_errors: unique_errors.len(),
        instruction_count_range: (min_inst, max_inst),
        unique_log_patterns: unique_log_patterns.len(),
    }
}
