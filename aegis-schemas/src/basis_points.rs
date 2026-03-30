//! Basis points newtype — validated integer in [0, 10000].
//!
//! Per D2 and D13: all scores in integer basis points, never floats.
//! 10000 = 100.00%, 8500 = 85.00%, 0 = 0.00%.
//!
//! Rejects values > 10000 at construction and deserialization time.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Maximum valid basis points value (100.00%).
pub const MAX_BASIS_POINTS: u32 = 10_000;

/// A validated basis points value in [0, 10000].
///
/// Cannot be constructed with a value > 10000.
/// Serializes as a plain u32 for wire compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BasisPoints(u32);

impl BasisPoints {
    /// Create a new BasisPoints value, returning None if > 10000.
    pub fn new(value: u32) -> Option<Self> {
        if value > MAX_BASIS_POINTS {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Create a BasisPoints value, clamping to [0, 10000].
    pub fn clamped(value: u32) -> Self {
        Self(value.min(MAX_BASIS_POINTS))
    }

    /// Get the raw u32 value.
    pub fn value(self) -> u32 {
        self.0
    }

    /// Zero basis points.
    pub const ZERO: Self = Self(0);

    /// Maximum basis points (10000 = 100%).
    pub const MAX: Self = Self(MAX_BASIS_POINTS);
}

impl fmt::Display for BasisPoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for BasisPoints {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BasisPoints {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        BasisPoints::new(value).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "basis points value {value} exceeds maximum {MAX_BASIS_POINTS}"
            ))
        })
    }
}

impl Default for BasisPoints {
    fn default() -> Self {
        Self::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_values() {
        assert!(BasisPoints::new(0).is_some());
        assert!(BasisPoints::new(5000).is_some());
        assert!(BasisPoints::new(10000).is_some());
    }

    #[test]
    fn rejects_overflow() {
        assert!(BasisPoints::new(10001).is_none());
        assert!(BasisPoints::new(u32::MAX).is_none());
    }

    #[test]
    fn clamped() {
        assert_eq!(BasisPoints::clamped(99999).value(), 10000);
        assert_eq!(BasisPoints::clamped(5000).value(), 5000);
    }

    #[test]
    fn serde_roundtrip() {
        let bp = BasisPoints::new(8500).unwrap();
        let json = serde_json::to_string(&bp).unwrap();
        assert_eq!(json, "8500");
        let deserialized: BasisPoints = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, bp);
    }

    #[test]
    fn deserialize_rejects_overflow() {
        let result: Result<BasisPoints, _> = serde_json::from_str("10001");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_max_u32() {
        let result: Result<BasisPoints, _> = serde_json::from_str("4294967295");
        assert!(result.is_err());
    }
}
