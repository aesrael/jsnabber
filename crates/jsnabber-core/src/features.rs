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
    /// Highly likely to be malicious (e.g., high entropy + eval)
    Malicious,
    /// Inconclusive or resource limits hit too early
    Inconclusive,
}

/// Extracted behavioral features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralFeatures {
    /// Overall classification
    pub classification: Classification,

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
    pub fn extract(result: &ExecutionResult, input_size: usize) -> Self {
        let mut api_call_counts = HashMap::new();
        let mut total_entropy = 0.0;
        let mut entropy_count = 0;
        let mut max_entropy = 0.0;
        let mut total_expansion = 0;

        for entry in &result.logs {
            // Count API calls
            let key = match &entry.event_type {
                EventType::Other(s) => s.clone(),
                t => format!("{:?}", t),
            };
            *api_call_counts.entry(key).or_insert(0) += 1;

            // Analyze payloads
            if let Some(payload) = &entry.payload {
                let entropy = calculate_entropy(payload);
                total_entropy += entropy;
                entropy_count += 1;
                if entropy > max_entropy {
                    max_entropy = entropy;
                }

                // Track expansion (eval/Function)
                if matches!(
                    entry.event_type,
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

        let classification = Self::classify_internal(
            &api_call_counts,
            max_entropy,
            expansion_factor,
            instruction_density,
            result.completed,
        );

        Self {
            classification,
            api_call_counts,
            instruction_density,
            max_payload_entropy: max_entropy,
            avg_payload_entropy: avg_entropy,
            total_expansion_bytes: total_expansion,
            expansion_factor,
        }
    }

    fn classify_internal(
        counts: &HashMap<String, usize>,
        max_entropy: f64,
        expansion: f64,
        density: f64,
        completed: bool,
    ) -> Classification {
        // 1. Check for Malicious indicators
        if (max_entropy > 6.8 && expansion > 2.0) || (max_entropy > 7.2) {
            return Classification::Malicious;
        }

        // 2. Check for Suspicious indicators
        let has_eval = counts.contains_key("Eval") || counts.contains_key("FunctionConstructor");
        let has_network = counts.contains_key("Network");

        if (has_eval && max_entropy > 6.0) || (has_eval && has_network) || density > 20000.0 {
            return Classification::Suspicious;
        }

        if has_eval || has_network {
            return Classification::Suspicious;
        }

        // 3. Fallback
        if !completed {
            return Classification::Inconclusive;
        }

        Classification::Benign
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
