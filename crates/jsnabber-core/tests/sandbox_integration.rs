//! Integration tests for jsnabber-core
//!
//! Tests with real-world JavaScript samples including obfuscated code

use jsnabber_core::{ExecutionLimits, Sandbox};

#[test]
fn test_benign_library_jquery_snippet() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();

    // Simplified jQuery-like code
    let code = r#"
        (function(window) {
            var $ = function(selector) {
                return document.querySelectorAll(selector);
            };
            window.$ = $;
        })(typeof window !== 'undefined' ? window : {});
    "#;

    let result = sandbox.execute(code).unwrap();
    assert!(result.completed);
    // Note: instruction_count may be 0 due to rquickjs sampling
}

#[test]
fn test_obfuscated_jsfuck() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();

    // JSFuck encoding of: alert(1)
    // This is a simple example - real JSFuck is much longer
    let code = "[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]]";

    let _result = sandbox.execute(code).unwrap();
    // Should execute without crashing (even if it errors)
    // Note: instruction_count may be 0 due to rquickjs sampling
}

#[test]
fn test_eval_chain() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();

    // Multiple layers of eval
    let code = r#"
        eval("eval(\"eval('1 + 1')\")")
    "#;

    let result = sandbox.execute(code).unwrap();
    assert!(result.completed);
}

#[test]
fn test_base64_decode() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();

    // Common malware pattern: base64 encoded payload
    let code = r#"
        var payload = "Y29uc29sZS5sb2coJ2hlbGxvJyk=";  // "console.log('hello')"
        // atob not available in QuickJS by default, so this will error
        // but shouldn't crash
        try {
            atob(payload);
        } catch(e) {
            "handled";
        }
    "#;

    let _result = sandbox.execute(code).unwrap();
    // Note: instruction_count may be 0 due to rquickjs sampling
}

#[test]
fn test_infinite_loop_termination() {
    let sandbox = Sandbox::new(ExecutionLimits::edge()).unwrap();

    let code = "while(true) { var x = 1; }";

    let result = sandbox.execute(code).unwrap();
    // Should hit instruction limit and return completed = false
    assert!(!result.completed);
    assert!(result
        .error
        .as_ref()
        .map(|e| e.contains("limit"))
        .unwrap_or(false));
}

#[test]
fn test_recursive_bomb() {
    let sandbox = Sandbox::new(ExecutionLimits::edge()).unwrap();

    let code = r#"
        function bomb() {
            bomb();
        }
        bomb();
    "#;

    let result = sandbox.execute(code).unwrap();
    // Should hit instruction limit or stack overflow and return completed = false
    assert!(!result.completed);
}

#[test]
fn test_array_bomb() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();

    // Try to allocate huge array
    let code = "var arr = new Array(100000000);";

    let _result = sandbox.execute(code).unwrap();
    // QuickJS is lazy, so this might complete
    // Just verify it doesn't crash
}

#[test]
fn test_string_concatenation_bomb() {
    let sandbox = Sandbox::new(ExecutionLimits::edge()).unwrap();

    let code = r#"
        var s = "";
        for(var i = 0; i < 1000000; i++) {
            s += "x";
        }
    "#;

    let result = sandbox.execute(code).unwrap();
    // Should hit instruction limit and return completed = false
    assert!(!result.completed);
}

#[test]
fn test_promise_syntax() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();

    // Verify async/await syntax works
    let code = r#"
        async function test() {
            return Promise.resolve(42);
        }
        test();
    "#;

    let result = sandbox.execute(code).unwrap();
    assert!(result.completed);
}

#[test]
fn test_syntax_variations() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();

    // ES6+ syntax
    let code = r#"
        const x = [1, 2, 3];
        const y = x.map(n => n * 2);
        const [a, b, c] = y;
        ({ a, b, c });
    "#;

    let result = sandbox.execute(code).unwrap();
    assert!(result.completed);
}

#[test]
fn test_bootstrap_library() {
    let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap();
    let code = include_str!("fixtures/bootstrap.min.js");

    let _result = sandbox.execute(code).unwrap();
    // Bootstrap checks for window/document existence.
    // As long as it doesn't crash the sandbox, we are good.
}
