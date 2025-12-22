//! Test to verify interrupt handler behavior

use jsnabber_core::{ExecutionLimits, Sandbox};

fn main() {
    println!("Testing interrupt handler with tight loop...");

    let sandbox = Sandbox::new(ExecutionLimits::custom(
        10_000, // Very low limit
        16 * 1024 * 1024,
        std::time::Duration::from_secs(5),
    ))
    .unwrap();

    let code = "while(true) { var x = 1; }";

    println!("Executing: {}", code);
    let result = sandbox.execute(code);

    match result {
        Ok(r) => println!("✅ Completed: {:?}", r),
        Err(e) => println!("❌ Error (expected): {:?}", e),
    }
}
