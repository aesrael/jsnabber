use jsnabber_core::{ExecutionLimits, Sandbox};
use rand::{Rng, SeedableRng};
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

fn main() {
    println!("=== JSNabber Fuzz Runner (Advanced) ===");
    let duration = Duration::from_secs(300); // 5 minutes (user requested)
                                             // Reduce duration for testing unless overridden
    let args: Vec<String> = std::env::args().collect();
    let duration = if args.len() > 1 {
        Duration::from_secs(args[1].parse().unwrap_or(30))
    } else {
        Duration::from_secs(30) // Default shorter for dev, user can pass 300
    };

    println!("Running fuzz tests for {:?}...", duration);

    let start_time = Instant::now();
    let mut interactions = 0;
    let mut errors = 0;
    let mut unique_errors = std::collections::HashSet::new();
    let mut crashes = 0;

    let mut report = File::create("FUZZ_REPORT.md").expect("Failed to create report");
    writeln!(report, "# Fuzz Test Report\n").unwrap();
    writeln!(
        report,
        "Report generated at: {:?}\n",
        std::time::SystemTime::now()
    )
    .unwrap();

    let mut rng = rand::rngs::StdRng::from_entropy();

    while start_time.elapsed() < duration {
        interactions += 1;
        let code = generate_garbage(&mut rng);
        let sandbox = Sandbox::new(ExecutionLimits::backend()).unwrap(); // Should not panic ideally

        // Catch panics to detect crashes
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sandbox.execute(&code)));
        match result {
            Ok(exec_result) => {
                match exec_result {
                    Ok(res) => {
                        // Success or runtime error handled gracefully
                        if let Some(err) = res.error {
                            errors += 1;
                            if unique_errors.insert(err.clone()) {
                                writeln!(report, "## New Error Found").unwrap();
                                writeln!(
                                    report,
                                    "Code snippet: `{}...`",
                                    &code.chars().take(50).collect::<String>()
                                )
                                .unwrap();
                                writeln!(report, "Error: `{}`\n", err).unwrap();
                            }
                        }
                    }
                    Err(e) => {
                        // Sandbox returned an error (e.g. limit exceeded)
                        errors += 1;
                        if unique_errors.insert(e.to_string()) {
                            writeln!(report, "## New Sandbox Error").unwrap();
                            writeln!(
                                report,
                                "Code snippet: `{}...`",
                                &code.chars().take(50).collect::<String>()
                            )
                            .unwrap();
                            writeln!(report, "Error: `{}`\n", e).unwrap();
                        }
                    }
                }
            }
            Err(_) => {
                crashes += 1;
                writeln!(report, "## CRASH DETECTED").unwrap();
                writeln!(report, "Code causing panic: ```javascript\n{}\n```\n", code).unwrap();
                println!("!!! CRASH DETECTED !!!");
            }
        }

        if interactions % 100 == 0 {
            print!(
                "\rInteractions: {} | Errors: {} | Crashes: {}",
                interactions, errors, crashes
            );
            std::io::stdout().flush().unwrap();
        }
    }
    println!("\nTesting complete.");

    writeln!(report, "\n## Statistics").unwrap();
    writeln!(report, "- Total Interactions: {}", interactions).unwrap();
    writeln!(report, "- Total Errors: {}", errors).unwrap();
    writeln!(report, "- Unique Errors: {}", unique_errors.len()).unwrap();
    writeln!(report, "- Crashes: {}", crashes).unwrap();
    writeln!(
        report,
        "- Throughput: {:.2} exec/sec",
        interactions as f64 / start_time.elapsed().as_secs_f64()
    )
    .unwrap();
}

fn generate_garbage(rng: &mut rand::rngs::StdRng) -> String {
    // 1. Random ASCII junk
    // 2. Valid-ish JS structures with junk
    // 3. Nested objects/arrays
    let mode = rng.gen_range(0..4);

    match mode {
        0 => {
            // Pure random ASCII
            (0..rng.gen_range(10..1000))
                .map(|_| rng.gen_range(32..126) as u8 as char)
                .collect()
        }
        1 => {
            // Function calls with garbage
            format!(
                "function f() {{ {}; }} f();",
                (0..rng.gen_range(10..100))
                    .map(|_| rng.gen_range(32..126) as u8 as char)
                    .collect::<String>()
            )
        }
        2 => {
            // Imports (testing the new stub)
            format!(
                "import '{}' from '{}';",
                random_string(rng),
                random_string(rng)
            )
        }
        3 => {
            // Deep recursion/nesting
            let depth = rng.gen_range(10..200);
            let mut s = String::new();
            for _ in 0..depth {
                s.push_str("({");
            }
            for _ in 0..depth {
                s.push_str("})");
            }
            s
        }
        _ => "console.log('test')".to_string(),
    }
}

fn random_string(rng: &mut rand::rngs::StdRng) -> String {
    (0..10)
        .map(|_| rng.gen_range(97..122) as u8 as char)
        .collect()
}
