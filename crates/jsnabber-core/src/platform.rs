//! Platform-specific configuration
//!
//! Conditional compilation for WASM vs native targets

use crate::limits::LimitTier;

/// Check if running in WASM environment
#[cfg(target_arch = "wasm32")]
pub const IS_WASM: bool = true;

#[cfg(not(target_arch = "wasm32"))]
pub const IS_WASM: bool = false;

/// Platform name for logging/debugging
#[cfg(target_arch = "wasm32")]
pub const PLATFORM: &str = "wasm32";

#[cfg(not(target_arch = "wasm32"))]
pub const PLATFORM: &str = "native";

/// Get platform-specific default limits tier
#[cfg(target_arch = "wasm32")]
pub fn default_limits_tier() -> LimitTier {
    LimitTier::Edge
}

#[cfg(not(target_arch = "wasm32"))]
pub fn default_limits_tier() -> LimitTier {
    LimitTier::Backend
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        if IS_WASM {
            assert_eq!(PLATFORM, "wasm32");
        } else {
            assert_eq!(PLATFORM, "native");
        }
    }

    #[test]
    fn test_default_limits() {
        let tier = default_limits_tier();
        if IS_WASM {
            assert_eq!(tier, crate::limits::LimitTier::Edge);
        } else {
            assert_eq!(tier, crate::limits::LimitTier::Backend);
        }
    }
}
