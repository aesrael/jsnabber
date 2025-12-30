use crate::instrumentation::EventType;
use crate::sandbox::ExecutionResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Assessment of the analyzed script
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Classification {
    /// No suspicious behavior detected
    Benign,
    /// Some suspicious indicators found (e.g., eval usage)
    Suspicious,
    /// Highly likely to be malicious (e.g., behaviors paired with obfuscation)
    Malicious,
    /// Inconclusive or resource limits hit too early
    Inconclusive,
}

/// Level of code obfuscation detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ObfuscationLevel {
    /// No obfuscation detected
    #[default]
    None,
    /// Likely minified or lightly obfuscated
    Low,
    /// Obfuscated (e.g., string hex encoding)
    Medium,
    /// Heavily obfuscated or packed (high entropy)
    High,
}

/// Extracted behavioral features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralFeatures {
    /// Overall classification
    pub classification: Classification,

    /// Detected obfuscation level
    pub obfuscation_level: ObfuscationLevel,

    /// API call counts by type
    pub api_call_counts: HashMap<String, usize>,

    /// Instruction density (instructions / millisecond)
    pub instruction_density: f64,

    /// Peak payload entropy (max entropy found in any log payload)
    pub max_payload_entropy: f64,

    /// Average payload entropy
    pub avg_payload_entropy: f64,

    /// Total dynamically generated code size (sum of eval payloads)
    pub total_expansion_bytes: usize,

    /// Expansion factor (total_expansion_bytes / input_code_size)
    pub expansion_factor: f64,
}

impl Default for Classification {
    fn default() -> Self {
        Self::Inconclusive
    }
}

impl BehavioralFeatures {
    /// Extract features from an execution result
    pub fn extract(result: &ExecutionResult, input_size: usize, source_code: &str) -> Self {
        let mut api_call_counts = HashMap::new();
        let mut total_entropy = 0.0;
        let mut entropy_count = 0;
        let mut max_entropy = 0.0;
        let mut total_expansion = 0;

        // Known entry points probed by the harness - ignore these for evasion detection
        let harness_probes = [
            "main",
            "init",
            "start",
            "run",
            "execute",
            "onLoad",
            "onReady",
            "setup",
            "bootstrap",
            "launch",
            "begin",
            "entry",
            "onError",
            "onComplete",
            "onSuccess",
            "onInit",
            "onChange",
            "onClick",
            "onSubmit",
            "DOMContentLoaded",
            "addEventListener",
        ];

        for log in &result.logs {
            match &log.event_type {
                EventType::Network => {
                    *api_call_counts.entry("network".to_string()).or_insert(0) += 1
                }
                EventType::Evasion => {
                    // Filter out harness probes
                    if let Some(payload) = &log.payload {
                        // Check if payload contains any of the harness probes
                        // The payload typically looks like "Accessed undefined global (via prototype): main"
                        let is_harness_probe =
                            harness_probes.iter().any(|probe| payload.contains(probe));
                        if !is_harness_probe {
                            *api_call_counts.entry("evasion".to_string()).or_insert(0) += 1;
                        }
                    } else {
                        *api_call_counts.entry("evasion".to_string()).or_insert(0) += 1;
                    }
                }
                EventType::Other(s) => {
                    *api_call_counts.entry(s.clone().to_lowercase()).or_insert(0) += 1;
                }
                t => {
                    *api_call_counts
                        .entry(format!("{:?}", t).to_lowercase())
                        .or_insert(0) += 1;
                }
            }

            // Analyze payloads
            if let Some(payload) = &log.payload {
                let entropy = calculate_entropy(payload);
                total_entropy += entropy;
                entropy_count += 1;
                if entropy > max_entropy {
                    max_entropy = entropy;
                }

                // Track expansion (eval/Function)
                if matches!(
                    log.event_type,
                    EventType::Eval | EventType::FunctionConstructor
                ) {
                    total_expansion += payload.len();
                }
            }
        }

        let instruction_density = if result.execution_time_ms > 0 {
            result.instruction_count as f64 / result.execution_time_ms as f64
        } else {
            0.0
        };

        let avg_entropy = if entropy_count > 0 {
            total_entropy / entropy_count as f64
        } else {
            0.0
        };

        let expansion_factor = if input_size > 0 {
            total_expansion as f64 / input_size as f64
        } else {
            0.0
        };

        // Calculate static entropy of the source code itself (detects obfuscated variable names, etc.)
        // For better static detection, calculate entropy of a sample of the input code
        // Take first 1000 chars to avoid performance issues on large files
        let code_sample = if source_code.len() > 1000 {
            &source_code[..1000]
        } else {
            source_code
        };
        let static_entropy = calculate_entropy(code_sample);

        // Start with benign classification, will be upgraded based on behavioral signals
        let mut classification = Classification::Benign;

        // Determine Obfuscation Level (combining static and runtime indicators)
        let obfuscation_level =
            if static_entropy > 6.5 || max_entropy > 7.5 || expansion_factor > 10.0 {
                ObfuscationLevel::High
            } else if static_entropy > 5.5
                || max_entropy > 6.5
                || expansion_factor > 3.0
                || total_expansion > 5000
            {
                ObfuscationLevel::Medium
            } else if static_entropy > 4.8 || max_entropy > 5.0 || total_expansion > 0 {
                ObfuscationLevel::Low
            } else {
                ObfuscationLevel::None
            };

        // If execution didn't complete (resource limit hit), mark as Inconclusive unless already Malicious
        if !result.completed && classification != Classification::Malicious {
            classification = Classification::Inconclusive;
        }

        // Refined Classification Logic: Intent vs Technique
        if classification == Classification::Benign {
            let has_network = api_call_counts.contains_key("network");
            let has_evasion = api_call_counts.contains_key("evasion");
            let has_storage = api_call_counts.contains_key("storage");

            // Malicious: Intentional dangerous behavior combined with obfuscation or high impact
            if (has_network || (has_storage && has_evasion))
                && matches!(
                    obfuscation_level,
                    ObfuscationLevel::Medium | ObfuscationLevel::High
                )
            {
                classification = Classification::Malicious;
            }
            // Suspicious: Behaviors that aren't inherently malicious but suspicious in context
            else if has_network
                || has_evasion
                || matches!(obfuscation_level, ObfuscationLevel::High)
            {
                classification = Classification::Suspicious;
            }
            // Suspicious: Low-level signals paired with any obfuscation
            else if (total_expansion > 1000 || api_call_counts.contains_key("eval"))
                && obfuscation_level != ObfuscationLevel::None
            {
                classification = Classification::Suspicious;
            }
        }

        Self {
            classification,
            obfuscation_level,
            api_call_counts,
            instruction_density,
            max_payload_entropy: max_entropy,
            avg_payload_entropy: avg_entropy,
            total_expansion_bytes: total_expansion,
            expansion_factor,
        }
    }
}

/// Calculate Shannon entropy (bits per character)
pub fn calculate_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let bytes = data.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = bytes.len() as f64;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrumentation::{EventType, LogEntry};
    use crate::sandbox::ExecutionResult;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (predictable)
        let low = calculate_entropy("aaaaa");
        assert!(low < 1.0);

        // Medium entropy (standard code)
        let mid = calculate_entropy("function test() { return 1 + 1; }");
        assert!(mid > 3.0 && mid < 5.0);

        // High entropy (random-looking/obfuscated)
        // Using a mix of diverse characters to generate high entropy
        let high = calculate_entropy("a1!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?");
        assert!(high > 5.0);
    }

    #[test]
    fn test_obfuscation_detection() {
        let result = ExecutionResult {
            completed: true,
            instruction_count: 100,
            execution_time_ms: 10,
            peak_memory_bytes: None,
            error: None,
            return_value: None,
            logs: vec![LogEntry {
                event_type: EventType::Eval,
                payload: Some("a1!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?".repeat(200)),
                timestamp_ms: 0,
            }],
            env: crate::environment::Environment::default(),
            features: BehavioralFeatures::default(),
            analysis: crate::sandbox::AnalysisMetadata::default(),
        };

        let features = BehavioralFeatures::extract(&result, 100, "");
        assert_eq!(features.obfuscation_level, ObfuscationLevel::High);
    }

    #[test]
    fn test_behavioral_classification_upgrade() {
        let mut result = ExecutionResult {
            completed: true,
            instruction_count: 100,
            execution_time_ms: 10,
            peak_memory_bytes: None,
            error: None,
            return_value: None,
            logs: vec![
                LogEntry {
                    event_type: EventType::Eval,
                    payload: Some("a1!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?".repeat(200)),
                    timestamp_ms: 0,
                },
                LogEntry {
                    event_type: EventType::Network,
                    payload: Some("https://evil.com/leak".to_string()),
                    timestamp_ms: 1,
                },
            ],
            env: crate::environment::Environment::default(),
            features: BehavioralFeatures::default(),
            analysis: crate::sandbox::AnalysisMetadata::default(),
        };

        let features = BehavioralFeatures::extract(&result, 100, "");

        // Should be upgraded to Malicious because of Network + (High Obfuscation)
        assert_eq!(features.classification, Classification::Malicious);
    }
}
