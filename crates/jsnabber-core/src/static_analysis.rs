//! Static analysis - pattern-based detection without execution

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Result of static code analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StaticAnalysis {
    /// Suspicious patterns found in the code
    pub patterns_found: Vec<SuspiciousPattern>,
    /// Overall risk score (0-100)
    pub risk_score: u8,
}

/// A suspicious pattern detected in code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    /// Pattern name (e.g., "eval", "fetch")
    pub name: String,
    /// Severity: "low", "medium", "high"
    pub severity: Severity,
    /// Line numbers where found (1-indexed)
    pub line_numbers: Vec<usize>,
    /// Code snippet showing context (first occurrence)
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl StaticAnalysis {
    /// Analyze JavaScript code for suspicious patterns
    pub fn analyze(code: &str) -> Self {
        let patterns = Self::get_patterns();
        let mut found = Vec::new();

        for (pattern_str, name, severity) in patterns {
            if let Ok(regex) = Regex::new(pattern_str) {
                let mut line_numbers = Vec::new();
                let mut context = String::new();

                for (line_num, line) in code.lines().enumerate() {
                    if regex.is_match(line) {
                        line_numbers.push(line_num + 1); // 1-indexed

                        // Capture first occurrence context
                        if context.is_empty() {
                            context = line.trim().to_string();
                            // Truncate if too long
                            if context.len() > 100 {
                                context.truncate(97);
                                context.push_str("...");
                            }
                        }
                    }
                }

                if !line_numbers.is_empty() {
                    found.push(SuspiciousPattern {
                        name: name.to_string(),
                        severity,
                        line_numbers,
                        context,
                    });
                }
            }
        }

        let risk_score = Self::calculate_risk_score(&found);

        Self {
            patterns_found: found,
            risk_score,
        }
    }

    /// Define suspicious patterns to detect
    fn get_patterns() -> Vec<(&'static str, &'static str, Severity)> {
        vec![
            // High severity - dangerous operations
            (r"eval\s*\(", "eval", Severity::High),
            (r"Function\s*\(", "Function constructor", Severity::High),
            (r"document\.cookie", "cookie access", Severity::High),
            (
                r"localStorage\.getItem",
                "localStorage read",
                Severity::High,
            ),
            (
                r"sessionStorage\.getItem",
                "sessionStorage read",
                Severity::High,
            ),
            (
                r"window\.crypto\.subtle",
                "crypto operations",
                Severity::High,
            ),
            // Medium severity - suspicious operations
            (r"atob\s*\(", "base64 decode", Severity::Medium),
            (r"btoa\s*\(", "base64 encode", Severity::Medium),
            (r"fetch\s*\(", "fetch request", Severity::Medium),
            (r"XMLHttpRequest", "XMLHttpRequest", Severity::Medium),
            (r"WebSocket", "WebSocket", Severity::Medium),
            (r"setTimeout\s*\(", "setTimeout", Severity::Medium),
            (r"setInterval\s*\(", "setInterval", Severity::Medium),
            (r"\.postMessage\s*\(", "postMessage", Severity::Medium),
            (r"importScripts\s*\(", "importScripts", Severity::Medium),
            // Low severity - informational
            (r"navigator\.userAgent", "userAgent access", Severity::Low),
            (r"screen\.", "screen properties", Severity::Low),
            (r"Math\.random\s*\(", "random generation", Severity::Low),
            (r"Date\.now\s*\(", "timestamp access", Severity::Low),
        ]
    }

    /// Calculate overall risk score based on patterns found
    fn calculate_risk_score(patterns: &[SuspiciousPattern]) -> u8 {
        let mut score = 0;

        for pattern in patterns {
            let points = match pattern.severity {
                Severity::High => 30,
                Severity::Medium => 15,
                Severity::Low => 5,
            };

            // Add points, with diminishing returns for multiple occurrences
            let occurrences = pattern.line_numbers.len();
            score += points + (occurrences.saturating_sub(1) * (points / 3));
        }

        // Cap at 100
        score.min(100) as u8
    }

    /// Convert risk score to a categorical classification
    pub fn classification(&self) -> crate::features::Classification {
        if self.risk_score >= 60 {
            crate::features::Classification::Malicious
        } else if self.risk_score >= 20 {
            crate::features::Classification::Suspicious
        } else {
            crate::features::Classification::Benign
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_eval() {
        let code = r#"
            function malicious() {
                eval("alert('xss')");
            }
        "#;

        let analysis = StaticAnalysis::analyze(code);
        assert_eq!(analysis.patterns_found.len(), 1);
        assert_eq!(analysis.patterns_found[0].name, "eval");
        assert_eq!(analysis.patterns_found[0].severity, Severity::High);
        assert!(analysis.risk_score > 0);
    }

    #[test]
    fn test_detect_multiple_patterns() {
        let code = r#"
            eval(atob("base64"));
            fetch("https://evil.com");
        "#;

        let analysis = StaticAnalysis::analyze(code);
        assert!(analysis.patterns_found.len() >= 3); // eval, atob, fetch
        assert!(analysis.risk_score > 50);
    }

    #[test]
    fn test_benign_code() {
        let code = r#"
            function add(a, b) {
                return a + b;
            }
        "#;

        let analysis = StaticAnalysis::analyze(code);
        assert_eq!(analysis.patterns_found.len(), 0);
        assert_eq!(analysis.risk_score, 0);
    }

    #[test]
    fn test_line_numbers() {
        let code = "line 1\neval('x');\nline 3\neval('y');";

        let analysis = StaticAnalysis::analyze(code);
        let eval_pattern = analysis
            .patterns_found
            .iter()
            .find(|p| p.name == "eval")
            .expect("Should find eval");

        assert_eq!(eval_pattern.line_numbers, vec![2, 4]);
    }
}
