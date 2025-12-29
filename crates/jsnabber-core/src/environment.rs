use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Environment configuration for sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    /// Seed for Math.random()
    pub random_seed: u64,
    /// Frozen timestamp for Date (milliseconds)
    pub frozen_timestamp: i64,
    /// Fake navigator user agent
    pub user_agent: String,
}

impl Default for Environment {
    fn default() -> Self {
        Self::chrome_windows()
    }
}

impl Environment {
    /// Chrome on Windows (default)
    pub fn chrome_windows() -> Self {
        Self {
            random_seed: 42,
            frozen_timestamp: 1640000000000,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
        }
    }

    /// Firefox on Linux
    pub fn firefox_linux() -> Self {
        Self {
            random_seed: 1337,
            frozen_timestamp: 1650000000000,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
                .to_string(),
        }
    }

    /// Safari on macOS
    pub fn safari_macos() -> Self {
        Self {
            random_seed: 9999,
            frozen_timestamp: 1660000000000,
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15".to_string(),
        }
    }

    /// Create a custom environment
    pub fn custom(random_seed: u64, frozen_timestamp: i64, user_agent: impl Into<String>) -> Self {
        Self {
            random_seed,
            frozen_timestamp,
            user_agent: user_agent.into(),
        }
    }

    /// Generate a set of diverse environments for multi-environment testing
    pub fn diverse_set() -> Vec<Self> {
        vec![
            Self::chrome_windows(),
            Self::firefox_linux(),
            Self::safari_macos(),
        ]
    }
}

/// --- Native (rquickjs) Implementation ---
#[cfg(feature = "native")]
pub fn register_native_environment(
    ctx: &rquickjs::Ctx<'_>,
    env: &Environment,
) -> rquickjs::Result<()> {
    use rquickjs::{Function, Object};
    let globals = ctx.globals();

    // 1. Random
    let rng = Arc::new(Mutex::new(Pcg64::seed_from_u64(env.random_seed)));
    globals.set(
        "__jsnabber_random",
        Function::new(ctx.clone(), move || {
            let mut rng = rng.lock().unwrap();
            rng.gen::<f64>()
        }),
    )?;

    // 2. Date
    let frozen_ms = env.frozen_timestamp;
    globals.set(
        "__jsnabber_now",
        Function::new(ctx.clone(), move || frozen_ms),
    )?;

    ctx.eval::<(), _>(ENVIRONMENT_JS)?;

    // 3. Navigator/Screen
    let navigator = Object::new(ctx.clone())?;
    navigator.set("userAgent", env.user_agent.clone())?;
    navigator.set("platform", "Win32")?;
    globals.set("navigator", navigator)?;

    let screen = Object::new(ctx.clone())?;
    screen.set("width", 1920)?;
    globals.set("screen", screen)?;

    Ok(())
}

/// --- WASM (quickjs-wasm-rs) Implementation ---
#[cfg(feature = "wasm")]
pub fn register_wasm_environment(
    ctx: &mut quickjs_wasm_rs::JSContextRef,
    env: &Environment,
) -> anyhow::Result<()> {
    use quickjs_wasm_rs::JSValue;
    let global = ctx.global_object()?;

    // 1. Random
    let rng = Arc::new(Mutex::new(Pcg64::seed_from_u64(env.random_seed)));
    let random_cb = ctx.wrap_callback(move |_ctx, _this, _args| {
        let mut rng = rng.lock().unwrap();
        let val: f64 = rng.gen();
        Ok(JSValue::Float(val))
    })?;
    global.set_property("__jsnabber_random", random_cb)?;

    // 2. Date
    let frozen_ms = env.frozen_timestamp;
    let now_cb =
        ctx.wrap_callback(move |_ctx, _this, _args| Ok(JSValue::Float(frozen_ms as f64)))?;
    global.set_property("__jsnabber_now", now_cb)?;

    ctx.eval_global("environment.js", ENVIRONMENT_JS)?;

    // 3. Navigator/Screen
    let navigator = ctx.object_value()?;
    navigator.set_property("userAgent", ctx.value_from_str(&env.user_agent)?)?;
    navigator.set_property("platform", ctx.value_from_str("Win32")?)?;
    global.set_property("navigator", navigator)?;

    let screen = ctx.object_value()?;
    screen.set_property("width", ctx.value_from_i32(1920)?)?;
    global.set_property("screen", screen)?;

    Ok(())
}

const ENVIRONMENT_JS: &str = r#"
(function() {
    Math.random = function() { return __jsnabber_random(); };

    const NativeDate = globalThis.Date;
    function FrozenDate(...args) {
        if (args.length === 0) return new NativeDate(__jsnabber_now());
        return new NativeDate(...args);
    }
    FrozenDate.now = function() { return __jsnabber_now(); };
    FrozenDate.prototype = NativeDate.prototype;
    globalThis.Date = FrozenDate;

    globalThis.window = globalThis;
    globalThis.self = globalThis;
    globalThis.location = { 
        href: 'https://example.com/',
        hostname: 'example.com',
        protocol: 'https:',
        host: 'example.com',
        pathname: '/',
        search: '',
        hash: '',
        origin: 'https://example.com'
    };
})();
"#;
