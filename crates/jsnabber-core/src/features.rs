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

        let mut classification = result.analysis.static_analysis.classification();

        // If execution didn't complete (resource limit hit), mark as Inconclusive unless already Malicious
        if !result.completed && classification != Classification::Malicious {
            classification = Classification::Inconclusive;
        }

        // If static analysis is benign but we have significant behavioral signals, upgrade to suspicious
        if classification == Classification::Benign {
            if total_expansion > 1000
                || max_entropy > 7.0
                || api_call_counts.contains_key("network")
            {
                classification = Classification::Suspicious;
            } else if total_expansion > 0 || api_call_counts.contains_key("eval") {
                classification = Classification::Suspicious;
            }
        }

        // Highly malicious indicators
        if api_call_counts.contains_key("network") && (total_expansion > 5000 || max_entropy > 7.5)
        {
            classification = Classification::Malicious;
        }

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
