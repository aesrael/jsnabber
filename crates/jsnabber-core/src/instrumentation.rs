//! Instrumentation and logging infrastructure (Phase 2 foundation)
//!
//! Provides structured logging for API calls and behavioral events.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Types of instrumentation events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    /// eval() call
    Eval,
    /// Function constructor
    FunctionConstructor,
    /// String decoding (atob, fromCharCode, etc.)
    StringDecode,
    /// Timer (setTimeout, setInterval)
    Timer,
    /// Random number generation
    Random,
    /// Network-like API (fetch, XMLHttpRequest)
    Network,
    /// DOM access
    DomAccess,
    /// Other/custom event
    Other(String),
}

/// Single instrumentation log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Event type
    pub event_type: EventType,

    /// Timestamp (milliseconds since execution start)
    pub timestamp_ms: u64,

    /// Optional payload (e.g., eval'd code, URL)
    pub payload: Option<String>,
}

/// Bounded circular buffer for instrumentation logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstrumentationLog {
    /// Log entries (bounded)
    entries: Vec<LogEntry>,

    /// Maximum number of entries
    max_entries: usize,

    /// Start time for relative timestamps
    #[serde(skip)]
    start_time: Option<Instant>,

    /// Number of dropped entries (when buffer is full)
    dropped_count: usize,
}

/// Thread-safe wrapper for InstrumentationLog
pub type AtomicLog = Arc<Mutex<InstrumentationLog>>;

impl InstrumentationLog {
    /// Create a new instrumentation log with the given capacity
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            max_entries,
            start_time: Some(Instant::now()),
            dropped_count: 0,
        }
    }

    /// Add a log entry
    pub fn log(&mut self, event_type: EventType, payload: Option<String>) {
        let timestamp_ms = self
            .start_time
            .map(|start| start.elapsed().as_millis() as u64)
            .unwrap_or(0);

        let entry = LogEntry {
            event_type,
            timestamp_ms,
            payload,
        };

        if self.entries.len() < self.max_entries {
            self.entries.push(entry);
        } else {
            // Circular buffer: overwrite oldest
            let index = self.dropped_count % self.max_entries;
            self.entries[index] = entry;
            self.dropped_count += 1;
        }
    }

    /// Get all log entries
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Get number of dropped entries
    pub fn dropped_count(&self) -> usize {
        self.dropped_count
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.dropped_count = 0;
        self.start_time = Some(Instant::now());
    }
}

/// --- Native (rquickjs) Implementation ---
#[cfg(feature = "native")]
pub fn register_native_hooks(ctx: &rquickjs::Ctx<'_>, log: AtomicLog) -> rquickjs::Result<()> {
    use rquickjs::Function;
    let globals = ctx.globals();

    let log_fn = Arc::clone(&log);
    globals.set(
        "__jsnabber_log",
        Function::new(
            ctx.clone(),
            move |event_name: String, payload: Option<String>| {
                let mut l = log_fn.lock().unwrap();
                let event_type = match event_name.as_str() {
                    "eval" => EventType::Eval,
                    "FunctionConstructor" => EventType::FunctionConstructor,
                    "atob" => EventType::StringDecode,
                    "fromCharCode" => EventType::StringDecode,
                    "random" => EventType::Random,
                    "timer" => EventType::Timer,
                    "network" => EventType::Network,
                    _ => EventType::Other(event_name),
                };
                l.log(event_type, payload);
            },
        ),
    )?;

    globals.set(
        "__js_atob",
        Function::new(ctx.clone(), move |input: String| {
            use base64::{engine::general_purpose, Engine as _};
            match general_purpose::STANDARD.decode(&input) {
                Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
                Err(_) => Err(rquickjs::Error::Exception),
            }
        }),
    )?;

    // Inject window and location stubs
    ctx.eval::<(), _>(
        r#"
        const __location = {
            href: 'https://sandbox.local/',
            hostname: 'https://sandbox.local',
            host: 'https://sandbox.local',
            protocol: 'https:',
            port: '',
            pathname: '/',
            search: '',
            hash: '',
            origin: 'https://sandbox.local'
        };
        
        globalThis.location = __location;
        globalThis.window = {
            get location() { return __location; }
        };
    "#,
    )?;

    ctx.eval::<(), _>(INSTRUMENTATION_JS)?;

    Ok(())
}

/// --- WASM (quickjs-wasm-rs) Implementation ---
#[cfg(feature = "wasm")]
pub fn register_wasm_hooks(
    ctx: &mut quickjs_wasm_rs::JSContextRef,
    log: AtomicLog,
) -> anyhow::Result<()> {
    use quickjs_wasm_rs::JSValue;
    let global = ctx.global_object()?;

    let log_fn = Arc::clone(&log);
    let log_cb = ctx.wrap_callback(move |_ctx, _this, args| {
        let event_name = args.get(0).and_then(|v| v.as_str().ok()).unwrap_or("other");
        let payload = args
            .get(1)
            .and_then(|v| v.as_str().ok())
            .map(|s| s.to_string());

        let mut l = log_fn.lock().unwrap();
        let event_type = match event_name {
            "eval" => EventType::Eval,
            "FunctionConstructor" => EventType::FunctionConstructor,
            "atob" => EventType::StringDecode,
            "fromCharCode" => EventType::StringDecode,
            "random" => EventType::Random,
            "timer" => EventType::Timer,
            "network" => EventType::Network,
            _ => EventType::Other(event_name.to_string()),
        };
        l.log(event_type, payload);

        Ok(JSValue::Undefined)
    })?;
    global.set_property("__jsnabber_log", log_cb)?;

    let atob_cb = ctx.wrap_callback(move |_ctx, _this, args| {
        use base64::{engine::general_purpose, Engine as _};
        let input = args.get(0).and_then(|v| v.as_str().ok()).unwrap_or("");
        match general_purpose::STANDARD.decode(input) {
            Ok(bytes) => {
                let s = String::from_utf8_lossy(&bytes).to_string();
                Ok(JSValue::String(s))
            }
            Err(_) => Ok(JSValue::Undefined),
        }
    })?;
    global.set_property("__js_atob", atob_cb)?;

    ctx.eval_global("instrumentation.js", INSTRUMENTATION_JS)?;

    Ok(())
}

// Load instrumentation JavaScript from external file
const INSTRUMENTATION_JS: &str = include_str!("instrumentation.js");

impl Default for InstrumentationLog {
    fn default() -> Self {
        Self::new(1000)
    }
}
