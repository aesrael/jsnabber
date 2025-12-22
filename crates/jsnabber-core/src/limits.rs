//! Resource limit enforcement for sandbox execution
//!
//! Provides configurable limits for instruction count, memory usage, and wall-clock time.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Execution limit tier (edge vs backend)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitTier {
    /// Edge tier - strict limits for fast triage (Cloudflare Workers)
    Edge,
    /// Backend tier - relaxed limits for deep analysis
    Backend,
    /// Custom limits
    Custom,
}

/// Resource limits for JavaScript execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLimits {
    /// Maximum number of instructions before termination
    pub max_instructions: u64,

    /// Maximum memory usage in bytes
    pub max_memory_bytes: usize,

    /// Maximum wall-clock execution time
    pub max_wall_time: Duration,

    /// Limit tier
    pub tier: LimitTier,
}

impl ExecutionLimits {
    /// Edge tier limits (Cloudflare Workers constraints)
    ///
    /// - 10M instructions
    /// - 16MB memory
    /// - 50ms wall time // free
    pub fn edge() -> Self {
        Self {
            max_instructions: 10_000_000,
            max_memory_bytes: 16 * 1024 * 1024, // 16MB
            max_wall_time: Duration::from_millis(50),
            tier: LimitTier::Edge,
        }
    }

    /// Backend tier limits (container-based analysis)
    ///
    /// - 100M instructions
    /// - 128MB memory
    /// - 5s wall time
    pub fn backend() -> Self {
        Self {
            max_instructions: 100_000_000,
            max_memory_bytes: 128 * 1024 * 1024, // 128MB
            max_wall_time: Duration::from_secs(5),
            tier: LimitTier::Backend,
        }
    }

    /// Create custom limits
    pub fn custom(max_instructions: u64, max_memory_bytes: usize, max_wall_time: Duration) -> Self {
        Self {
            max_instructions,
            max_memory_bytes,
            max_wall_time,
            tier: LimitTier::Custom,
        }
    }

    /// Validate limits are reasonable
    pub fn validate(&self) -> Result<(), String> {
        if self.max_instructions == 0 {
            return Err("max_instructions must be > 0".to_string());
        }
        if self.max_memory_bytes == 0 {
            return Err("max_memory_bytes must be > 0".to_string());
        }
        if self.max_wall_time.is_zero() {
            return Err("max_wall_time must be > 0".to_string());
        }
        Ok(())
    }
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self::edge()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_limits() {
        let limits = ExecutionLimits::edge();
        assert_eq!(limits.max_instructions, 10_000_000);
        assert_eq!(limits.tier, LimitTier::Edge);
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn test_backend_limits() {
        let limits = ExecutionLimits::backend();
        assert_eq!(limits.max_instructions, 100_000_000);
        assert_eq!(limits.tier, LimitTier::Backend);
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn test_custom_limits() {
        let limits =
            ExecutionLimits::custom(1_000_000, 8 * 1024 * 1024, Duration::from_millis(100));
        assert_eq!(limits.tier, LimitTier::Custom);
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn test_invalid_limits() {
        let limits = ExecutionLimits::custom(0, 1024, Duration::from_millis(100));
        assert!(limits.validate().is_err());
    }
}
