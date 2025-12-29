use jsnabber_core::{ExecutionLimits, Sandbox};

/// weirdness_analysis.rs - Stress testing the sandbox with "weird" JS behaviors
///
/// This suite covers:
/// 1. Prototype Pollution
/// 2. Proxy Abuse
/// 3. Symbol-only Obfuscation (AAEncode style)
/// 4. Circular Structures
/// 5. Massive Allocations (DoS)
/// 6. Infinite Recursion/Loops
/// 7. Native Function Overwrites
/// 8. Getter/Setter Side-effects

#[test]
fn test_prototype_pollution() {
    let code = r#"
        // Attempt to pollute Object.prototype
        var payload = '{"__proto__": {"polluted": true}}';
        var obj = JSON.parse(payload);
        if (Object.prototype.polluted) {
            throw new Error("Prototype Successfully Polluted!");
        }
    "#;
    let sandbox = Sandbox::new(ExecutionLimits::backend()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);

    // We expect the sandbox to either contain the pollution (if valid JS behavior)
    // BUT critical: It shouldn't crash the engine or affect other contexts.
    // For this single execution, if it runs without engine panic, that's a pass.
    assert!(
        result.is_ok(),
        "Prototype pollution attempt caused engine error"
    );
}

#[test]
fn test_proxy_bomb() {
    // A proxy that throws on any interaction
    let code = r#"
        const bomb = new Proxy({}, {
            get: function() { throw "Boom!"; },
            set: function() { throw "Boom!"; },
            has: function() { throw "Boom!"; },
            ownKeys: function() { throw "Boom!"; }
        });
        
        // Instrumentation often tries to inspect objects. 
        // If our instrumentation isn't robust, this will crash the logging logic.
        
        try {
            console.log(bomb); // Should trigger instrumentation inspection
        } catch(e) {}
    "#;
    let sandbox = Sandbox::new(ExecutionLimits::backend()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);

    // It's acceptable for the script to error, but the SANDBOX process must not panic.
    if let Ok(res) = result {
        println!("Proxy bomb result: {:?}", res);
    }
    // We check that we didn't panic (implicit in test passing)
}

#[test]
fn test_symbol_obfuscation() {
    // "JJEncode" / "AAEncode" style - using only symbols to weird out parsers
    // construct 'alert(1)' using only []()+!
    let code = r#"
        // Constructing "1" -> +!![]
        // Constructing "false" -> ![] + []
        // This is valid JS, just ugly. Should run fine.
        var x = (![]+[])[+[]]; // 'f'
        var y = (![]+[])[+!![]]; // 'a'
    "#;
    let sandbox = Sandbox::new(ExecutionLimits::backend()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);
    assert!(result.is_ok(), "Symbol obfuscation failed to execute");
}

#[test]
fn test_deep_recursion_dos() {
    // Stack overflow attempt
    let code = r#"
        function dive(depth) {
            if (depth % 100 === 0) Math.random(); 
            dive(depth + 1);
        }
        try {
            dive(0);
        } catch(e) {
            // Expected RangeError: Maximum call stack size exceeded
        }
    "#;
    let sandbox = Sandbox::new(ExecutionLimits::backend()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);

    match result {
        Ok(res) => {
            // It might timeout (WallTime) or error gracefully.
            println!("Recursion result: {:?}", res.error);
        }
        Err(e) => {
            // Limits exceeded is also fine
            println!("Recursion hit limit: {}", e);
        }
    }
}

#[test]
fn test_massive_allocation() {
    // Memory limit test
    let code = r#"
        var arr = [];
        while(true) {
            arr.push(new Array(100000).join('a'));
        }
    "#;
    // Set strict memory limit (e.g. 50MB)
    let mut limits = ExecutionLimits::backend();
    limits.max_memory_bytes = 50 * 1024 * 1024;

    let sandbox = Sandbox::new(limits).expect("Sandbox creation failed");
    let result = sandbox.execute(code);

    // Should fail with memory limit/error, NOT panic the OS process
    match result {
        Ok(res) => assert!(res.error.is_some(), "Should have reported an error"),
        Err(e) => assert!(
            e.to_string().contains("Memory"),
            "Should be memory error: {}",
            e
        ),
    }
}

#[test]
fn test_native_overwrite() {
    // Verify robustness against overwriting globals our instrumentation relies on/uses
    let code = r#"
        // Overwrite standard constructors
        Array = null;
        Object = function() { throw "Fake Object"; };
        JSON.stringify = null;
        
        // This makes 'console.log' calls potentially dangerous if they use JSON.stringify internally
        console.log("Test log");
    "#;
    let sandbox = Sandbox::new(ExecutionLimits::backend()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);

    assert!(result.is_ok(), "Native overwrite caused sandbox failure");
}

#[test]
fn test_getter_bomb() {
    // Defining a getter on Object.prototype could impact instrumentation
    let code = r#"
        Object.defineProperty(Object.prototype, "id", {
            get: function() { 
                throw "Getter Bomb!"; 
            }
        });
        
        var x = {};
        // Accessing x.id triggers it.
        // Does our instrumentation access random properties?
    "#;
    let sandbox = Sandbox::new(ExecutionLimits::backend()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);
    assert!(result.is_ok(), "Getter bomb caused sandbox failure");
}

#[test]
fn test_unknown_api_robustness() {
    // Verify that access to completely unknown, unstubbed APIs does not crash execution
    let code = r#"
        if (typeof globalThis.__magic_global_proxy === 'undefined') {
             throw new Error("__magic_global_proxy is missing!");
        }
        
        // Debug Proxy Behavior
        if (!('UnknownPlugin' in globalThis.__magic_global_proxy)) {
            throw new Error("Proxy 'in' check failed: UnknownPlugin not found in proxy");
        }
        // Direct access
        var p = globalThis.__magic_global_proxy.UnknownPlugin;
        if (typeof p === 'undefined') {
             throw new Error("Proxy get failed: " + p);
        }
        
        // Attempts to use a made-up plugin via window
        try {
            var up = window.UnknownPlugin;
            if (typeof up === 'undefined') {
                 // Log keys of window/globalProxy to see what's happening
                 throw new Error("window.UnknownPlugin is undefined.");
            }
            
            var val = up.detect("malware");
            // Should be able to chain calls on the result (recursive stub)
            val.report().send();
        } catch(e) {
            // It MUST NOT throw.
            throw new Error("Caught error accessing window.UnknownPlugin: " + e.name + ": " + e.message);
        }
    "#;
    let sandbox = Sandbox::new(ExecutionLimits::backend()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);

    // Check logs to confirm we saw the access
    if let Ok(res) = &result {
        let logs_str = format!("{:?}", res.logs);
        println!("Logs: {}", logs_str);
        assert!(
            logs_str.contains("UnknownPlugin"),
            "Should have logged access to UnknownPlugin"
        );
    }

    // The execution should be successful (Result::Ok and NO Execution error)
    match &result {
        Ok(res) => assert!(
            res.error.is_none(),
            "Execution failed with JS error: {:?}",
            res.error
        ),
        Err(e) => panic!("Sandbox internal error: {:?}", e),
    }

    assert!(
        result.is_ok(),
        "Unknown API caused sandbox failure: {:?}",
        result.err()
    );
}
