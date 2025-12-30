use crate::engine::{EngineError, SandboxEngine};
use crate::environment::Environment;
use crate::features::BehavioralFeatures;
use crate::instrumentation::InstrumentationLog;
use crate::limits::ExecutionLimits;
use crate::sandbox::ExecutionResult;
use rquickjs::loader::{Loader, Resolver};
use rquickjs::{Context, Module, Runtime};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ... (existing imports)

pub struct RQuickJsEngine;

impl RQuickJsEngine {
    pub fn new() -> Self {
        Self
    }
}

// Stub resolver/loader for ES6 modules
struct StubResolver;
impl Resolver for StubResolver {
    fn resolve<'js>(
        &mut self,
        _ctx: &rquickjs::Ctx<'js>,
        _base: &str,
        name: &str,
    ) -> rquickjs::Result<String> {
        Ok(format!("stub:{}", name))
    }
}

struct StubLoader;
impl Loader for StubLoader {
    fn load<'js>(
        &mut self,
        ctx: &rquickjs::Ctx<'js>,
        _path: &str,
    ) -> rquickjs::Result<rquickjs::Module<'js>> {
        // Return a safe stub module
        Module::declare(
            ctx.clone(),
            _path,
            r#"
            export default new Proxy({}, {
                get: (target, prop) => {
                    return function() { return undefined; };
                }
            });
        "#,
        )
    }
}

impl SandboxEngine for RQuickJsEngine {
    fn execute(
        &self,
        code: &str,
        limits: &ExecutionLimits,
        env: &Environment,
    ) -> Result<ExecutionResult, EngineError> {
        let start_time = Instant::now();

        // Run static analysis first (before execution)
        let static_analysis = crate::static_analysis::StaticAnalysis::analyze(code);

        let instr_log = Arc::new(Mutex::new(InstrumentationLog::new(1000)));

        // 1. Initialize Runtime
        let runtime = Runtime::new().map_err(|e| EngineError::Initialization(e.to_string()))?;

        // Register module loader
        runtime.set_loader(StubResolver, StubLoader);

        // 2. Setup Limits and Interrupt Handler *BEFORE* creating the context
        runtime.set_memory_limit(limits.max_memory_bytes);

        // ... (rest of setup)
        let instruction_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let max_inst = limits.max_instructions;
        let inst_clone = Arc::clone(&instruction_count);

        let start_time_clone = start_time.clone();
        let max_wall_time = limits.max_wall_time;

        let active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let active_clone = Arc::clone(&active);

        runtime.set_interrupt_handler(Some(Box::new(move || {
            if !active_clone.load(std::sync::atomic::Ordering::Relaxed) {
                return false;
            }
            if start_time_clone.elapsed() > max_wall_time {
                return true;
            }
            let current = inst_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if current >= max_inst {
                return true;
            }
            false
        })));

        // 3. Initialize Context
        let context =
            Context::full(&runtime).map_err(|e| EngineError::Initialization(e.to_string()))?;

        let result_internal = context.with(|ctx| {
            // Register hooks (Native version)
            if let Err(e) =
                crate::instrumentation::register_native_hooks(&ctx, Arc::clone(&instr_log))
            {
                // ... (error handling)
                if e.is_exception() {
                    let catch = ctx.catch();
                    return Err(EngineError::Initialization(format!(
                        "Instrumentation error: {:?}",
                        catch
                    )));
                }
                return Err(EngineError::Initialization(format!(
                    "Instrumentation error: {}",
                    e
                )));
            }
            if let Err(e) = crate::environment::register_native_environment(&ctx, env) {
                // ... (error handling)
                if e.is_exception() {
                    let catch = ctx.catch();
                    return Err(EngineError::Initialization(format!(
                        "Environment error: {:?}",
                        catch
                    )));
                }
                return Err(EngineError::Initialization(format!(
                    "Environment error: {}",
                    e
                )));
            }

            // NOW enable the instruction limit
            active.store(true, std::sync::atomic::Ordering::Relaxed);

            // Attempt 1: Standard Script
            let result_internal = match ctx.eval::<rquickjs::Value, _>(code.as_bytes()) {
                Ok(val) => {
                    active.store(false, std::sync::atomic::Ordering::Relaxed);
                    Ok((true, None, Some(format!("{:?}", val))))
                }
                Err(e) => {
                    // Check error type
                    let is_exception = e.is_exception();
                    let catch_msg = if is_exception {
                        format!("{:?}", ctx.catch())
                    } else {
                        e.to_string()
                    };

                    // Logic to decide on retries
                    let is_strict_error =
                        catch_msg.contains("strict mode") || catch_msg.contains("invalid keyword");
                    let is_module_error = catch_msg.contains("import")
                        || catch_msg.contains("export")
                        || code.contains("import ")
                        || code.contains("export ");

                    if is_module_error {
                        // Attempt 2: Module (Unwrapped, uses Loader)
                        match Module::declare(ctx.clone(), "main", code.as_bytes()) {
                            Ok(module) => {
                                match module.eval() {
                                    Ok(_) => {
                                        active.store(false, std::sync::atomic::Ordering::Relaxed);
                                        Ok((true, None, Some("Module Loaded".to_string())))
                                    }
                                    Err(e) => {
                                        active.store(false, std::sync::atomic::Ordering::Relaxed);
                                        // Module execution failed (runtime)
                                        let msg = if e.is_exception() {
                                            format!("{:?}", ctx.catch())
                                        } else {
                                            e.to_string()
                                        };
                                        Ok((false, Some(msg), None))
                                    }
                                }
                            }
                            Err(e) => {
                                active.store(false, std::sync::atomic::Ordering::Relaxed);
                                Ok((false, Some(e.to_string()), None))
                            }
                        }
                    } else if is_strict_error {
                        // Attempt 3: Unwrapped Script (Strict mode doesn't allow 'with')
                        match ctx.eval::<rquickjs::Value, _>(code) {
                            Ok(val) => {
                                active.store(false, std::sync::atomic::Ordering::Relaxed);
                                Ok((true, None, Some(format!("{:?}", val))))
                            }
                            Err(e) => {
                                active.store(false, std::sync::atomic::Ordering::Relaxed);
                                let msg = if e.is_exception() {
                                    format!("{:?}", ctx.catch())
                                } else {
                                    e.to_string()
                                };
                                Ok((false, Some(msg), None))
                            }
                        }
                    } else {
                        // Real error in wrapped script
                        active.store(false, std::sync::atomic::Ordering::Relaxed);

                        // Check limits
                        let is_interrupted = catch_msg.to_lowercase().contains("interrupted")
                            || e.to_string().to_lowercase().contains("interrupted")
                            || catch_msg.is_empty()
                            || catch_msg.contains("null");

                        if is_interrupted {
                            let elapsed = start_time.elapsed();
                            let msg = if elapsed > max_wall_time {
                                format!("Wall-time limit of {:?} exceeded", max_wall_time)
                            } else {
                                format!("Instruction limit of {} exceeded", max_inst)
                            };
                            Ok((false, Some(msg), None))
                        } else {
                            Ok((false, Some(catch_msg), None))
                        }
                    }
                }
            };

            // Run function discovery if execution completed successfully
            // This discovers and calls dormant functions that weren't triggered by top-level code
            if let Ok((completed, error, _)) = &result_internal {
                if *completed && error.is_none() {
                    // Re-enable instruction limit for function discovery
                    active.store(true, std::sync::atomic::Ordering::Relaxed);

                    match ctx.eval::<(), _>(crate::instrumentation::FUNCTION_DISCOVERY_JS) {
                        Ok(_) => {
                            // Function discovery completed successfully
                        }
                        Err(e) => {
                            // Log but don't fail - function discovery is best-effort
                            if e.is_exception() {
                                let _ = ctx.catch(); // Clear the exception
                            }
                        }
                    }

                    active.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }

            result_internal
        })?;

        let (completed, error, return_value) = result_internal;

        let logs = instr_log.lock().unwrap().entries().to_vec();
        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        let final_inst = instruction_count.load(std::sync::atomic::Ordering::Relaxed);

        // Extract analysis metadata from logs
        let mut analysis = crate::sandbox::AnalysisMetadata::default();

        // Determine execution mode
        analysis.execution_mode = if return_value
            .as_ref()
            .map(|v| v.contains("Module Loaded"))
            .unwrap_or(false)
        {
            crate::sandbox::ExecutionMode::Module
        } else if code.contains("\"use strict\"") || code.contains("'use strict'") {
            crate::sandbox::ExecutionMode::StrictScript
        } else {
            crate::sandbox::ExecutionMode::Script
        };

        analysis.used_es6_modules =
            analysis.execution_mode == crate::sandbox::ExecutionMode::Module;

        // Extract function discovery info from logs
        let mut entry_points = Vec::new();
        let mut function_count = 0;
        let mut has_unknown_apis = false;

        for log in &logs {
            if let crate::instrumentation::EventType::Other(ref event) = log.event_type {
                if event == "function_discovery" {
                    if let Some(ref payload) = log.payload {
                        if payload.contains("Calling common entry point:") {
                            // Extract entry point name
                            if let Some(name) = payload.split("Calling common entry point: ").nth(1)
                            {
                                let name = name.trim_end_matches("()");
                                entry_points.push(name.to_string());
                            }
                        } else if payload.contains("Calling discovered function:") {
                            function_count += 1;
                        }
                    }
                } else if event == "undefined_global" {
                    has_unknown_apis = true;
                }
            }
        }

        analysis.functions_discovered = function_count;
        analysis.entry_points_called = entry_points;
        analysis.accessed_unknown_apis = has_unknown_apis;
        analysis.static_analysis = static_analysis;

        let result = ExecutionResult {
            completed,
            instruction_count: final_inst,
            execution_time_ms,
            peak_memory_bytes: Some(runtime.memory_usage().memory_used_size as usize),
            error,
            return_value,
            logs,
            env: env.clone(),
            features: BehavioralFeatures::default(),
            analysis,
        };

        Ok(ExecutionResult {
            features: BehavioralFeatures::extract(&result, code.len(), code),
            ..result
        })
    }
}
