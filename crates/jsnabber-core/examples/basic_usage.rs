//! Example: Basic sandbox usage

use jsnabber_core::{ExecutionLimits, Sandbox};

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("=== JSNabber Core - Example Usage ===\n");

    // Example 1: Simple execution
    println!("1. Simple execution:");
    let sandbox = Sandbox::new(ExecutionLimits::edge())?;
    let result = sandbox.execute("2 + 2")?;
    println!("   Result: {:?}", result.return_value);
    println!("   Instructions: {}", result.instruction_count);
    println!("   Time: {}ms\n", result.execution_time_ms);

    // Example 2: Eval detection
    println!("2. Eval usage:");
    let result = sandbox.execute(r#"eval("1 + 1")"#)?;
    println!("   Completed: {}", result.completed);
    println!("   Instructions: {}\n", result.instruction_count);

    // Example 3: Error handling
    println!("3. Syntax error:");
    let result = sandbox.execute("this is not valid")?;
    println!("   Completed: {}", result.completed);
    println!("   Error: {:?}\n", result.error);

    // Example 4: Instruction limit
    println!("4. Instruction limit (infinite loop):");
    let result = sandbox.execute("while(true) {}");
    match result {
        Ok(_) => println!("   Unexpected success"),
        Err(e) => println!("   Caught: {}\n", e),
    }

    // Example 5: Backend limits
    println!("5. Backend tier (relaxed limits):");
    let backend_sandbox = Sandbox::new(ExecutionLimits::backend())?;
    let result = backend_sandbox.execute(
        r#"
        let sum = 0;
        for(let i = 0; i < 100000; i++) {
            sum += i;
        }
        sum;
    "#,
    )?;
    println!("   Result: {:?}", result.return_value);
    println!("   Instructions: {}", result.instruction_count);
    println!("   Memory: {:?} bytes\n", result.peak_memory_bytes);

    // Example 6: Obfuscated code
    println!("6. Obfuscated code:");
    let result = sandbox.execute(
        r#"
        (function() {
            var _0x1234 = ['log', 'hello'];
            console[_0x1234[0]](_0x1234[1]);
        })();
    "#,
    )?;
    println!("   Completed: {}", result.completed);
    println!("   Instructions: {}\n", result.instruction_count);

    println!("=== All examples completed ===");
    Ok(())
}
