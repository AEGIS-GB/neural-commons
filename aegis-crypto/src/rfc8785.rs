// RFC 8785 — JSON Canonicalization Scheme (JCS)
// Deterministic JSON serialization for signing (D4)
// Rule: the bytes you sign are the bytes you send

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalizationError {
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
}

/// Canonicalize a serializable value to RFC 8785 JSON bytes.
///
/// RFC 8785 rules:
/// - Object keys sorted lexicographically (by UTF-16 code units)
/// - No insignificant whitespace
/// - Numbers: shortest representation, no trailing zeros
/// - Strings: minimal escaping
/// - No BOM
///
/// The returned bytes are both the signing input AND the wire format.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalizationError> {
    // serde_json with sorted keys gets us most of the way.
    // For full RFC 8785 compliance we need to handle number formatting.
    // TODO: Verify full RFC 8785 compliance with test vectors
    let json_value = serde_json::to_value(value)
        .map_err(|e| CanonicalizationError::SerializationFailed(e.to_string()))?;
    let canonical = canonicalize_value(&json_value)?;
    Ok(canonical.into_bytes())
}

fn canonicalize_value(value: &serde_json::Value) -> Result<String, CanonicalizationError> {
    match value {
        serde_json::Value::Null => Ok("null".to_string()),
        serde_json::Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::String(s) => Ok(serde_json::to_string(s)
            .map_err(|e| CanonicalizationError::SerializationFailed(e.to_string()))?),
        serde_json::Value::Array(arr) => {
            let items: Result<Vec<String>, _> = arr.iter().map(canonicalize_value).collect();
            Ok(format!("[{}]", items?.join(",")))
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort(); // Lexicographic sort (RFC 8785 requires UTF-16 sort order)
            let pairs: Result<Vec<String>, _> = keys
                .iter()
                .map(|k| {
                    let key_json = serde_json::to_string(k)
                        .map_err(|e| CanonicalizationError::SerializationFailed(e.to_string()))?;
                    let val = canonicalize_value(map.get(*k).unwrap())?;
                    Ok(format!("{}:{}", key_json, val))
                })
                .collect();
            Ok(format!("{{{}}}", pairs?.join(",")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sorted_keys() {
        let input = json!({"z": 1, "a": 2});
        let result = canonicalize(&input).unwrap();
        assert_eq!(String::from_utf8(result).unwrap(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn test_no_whitespace() {
        let input = json!({"key": [1, 2, 3]});
        let result = canonicalize(&input).unwrap();
        assert_eq!(String::from_utf8(result).unwrap(), r#"{"key":[1,2,3]}"#);
    }

    #[test]
    fn test_nested_objects_sorted() {
        let input = json!({"b": {"d": 1, "c": 2}, "a": 3});
        let result = canonicalize(&input).unwrap();
        assert_eq!(
            String::from_utf8(result).unwrap(),
            r#"{"a":3,"b":{"c":2,"d":1}}"#
        );
    }
}
