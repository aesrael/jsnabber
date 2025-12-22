use crate::engine::{EngineError, SandboxEngine};
use crate::environment::Environment;
use crate::features::BehavioralFeatures;
use crate::instrumentation::InstrumentationLog;
use crate::limits::ExecutionLimits;
use crate::sandbox::ExecutionResult;
use rquickjs::{Context, Runtime};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub struct RQuickJsEngine;

impl RQuickJsEngine {
    pub fn new() -> Self {
        Self
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
        let instr_log = Arc::new(Mutex::new(InstrumentationLog::new(1000)));

        // 1. Initialize Runtime
        let runtime = Runtime::new().map_err(|e| EngineError::Initialization(e.to_string()))?;

        // 2. Setup Limits and Interrupt Handler *BEFORE* creating the context
        runtime.set_memory_limit(limits.max_memory_bytes);

        let instruction_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let max_inst = limits.max_instructions;
        let inst_clone = Arc::clone(&instruction_count);

        // Wall-time timeout for tight loops
        // QuickJS interrupt handlers only fire at safe points (function calls, loop back-edges).
        // Tight loops like `while(true) { x = 1; }` don't hit these points often enough.
        // Wall-time check catches them when instruction counting can't.
        // See: https://github.com/quickjs-ng/quickjs/blob/master/quickjs.c#L1847
        let start_time_clone = start_time.clone();
        let max_wall_time = limits.max_wall_time;

        // Only interrupt if execution is actually "running" code
        let active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let active_clone = Arc::clone(&active);

        runtime.set_interrupt_handler(Some(Box::new(move || {
            if !active_clone.load(std::sync::atomic::Ordering::Relaxed) {
                return false; // Do NOT interrupt during initialization
            }

            // Check wall-time first (catches tight loops)
            if start_time_clone.elapsed() > max_wall_time {
                return true; // Interrupt due to timeout!
            }

            // Then check instruction count
            let current = inst_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if current >= max_inst {
                return true; // Interrupt due to instruction limit!
            }

            false // Continue
        })));

        // 3. Initialize Context
        let context =
            Context::full(&runtime).map_err(|e| EngineError::Initialization(e.to_string()))?;

        let result_internal = context.with(|ctx| {
            // Register hooks (Native version)
            if let Err(e) =
                crate::instrumentation::register_native_hooks(&ctx, Arc::clone(&instr_log))
            {
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

            match ctx.eval::<rquickjs::Value, _>(code) {
                Ok(val) => {
                    active.store(false, std::sync::atomic::Ordering::Relaxed);
                    Ok((true, None, Some(format!("{:?}", val))))
                }
                Err(e) => {
                    active.store(false, std::sync::atomic::Ordering::Relaxed);
                    if e.is_exception() {
                        let catch = ctx.catch();
                        // Check if it was our limit
                        let msg = format!("{:?}", catch);
                        if msg.contains("interrupted") {
                            let elapsed = start_time.elapsed();
                            if elapsed > max_wall_time {
                                return Err(EngineError::LimitExceeded(format!(
                                    "Wall-time limit of {:?} exceeded",
                                    max_wall_time
                                )));
                            } else {
                                return Err(EngineError::LimitExceeded(format!(
                                    "Instruction limit of {} exceeded",
                                    max_inst
                                )));
                            }
                        }
                        Ok((false, Some(msg), None))
                    } else {
                        Ok((false, Some(e.to_string()), None))
                    }
                }
            }
        })?;

        let (completed, error, return_value) = result_internal;

        let logs = instr_log.lock().unwrap().entries().to_vec();
        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        let final_inst = instruction_count.load(std::sync::atomic::Ordering::Relaxed);

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
        };

        Ok(ExecutionResult {
            features: BehavioralFeatures::extract(&result, code.len()),
            ..result
        })
    }
}
