//! Example: Platform-aware execution

use jsnabber_core::{default_limits_tier, ExecutionLimits, Sandbox, IS_WASM, PLATFORM};

fn main() -> anyhow::Result<()> {
    println!("=== Platform Detection ===");
    println!("Platform: {}", PLATFORM);
    println!("Is WASM: {}", IS_WASM);
    println!("Default tier: {:?}\n", default_limits_tier());

    // Use platform-appropriate defaults
    let limits = match default_limits_tier() {
        tier @ _ => {
            println!("Using {:?} tier limits", tier);
            ExecutionLimits::edge() // Edge for WASM, Backend for native
        }
    };

    let sandbox = Sandbox::new(limits)?;

    // Test execution
    let code = r#"
        const platform = typeof window !== 'undefined' ? 'browser' : 'server';
        ({ platform, result: 42 })
    "#;

    let result = sandbox.execute(code)?;
    println!("Execution result:");
    println!("  Completed: {}", result.completed);
    println!("  Instructions: {}", result.instruction_count);
    println!("  Return value: {:?}", result.return_value);

    Ok(())
}
