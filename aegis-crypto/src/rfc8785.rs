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
            // RFC 8785 §3.2.3: sort by UTF-16 code units (not UTF-8 bytes)
            keys.sort_by(|a, b| {
                let a_utf16: Vec<u16> = a.encode_utf16().collect();
                let b_utf16: Vec<u16> = b.encode_utf16().collect();
                a_utf16.cmp(&b_utf16)
            });
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

    #[test]
    fn test_utf16_sort_order_non_ascii() {
        // RFC 8785 §3.2.3: keys sorted by UTF-16 code units
        // In UTF-16: 'a' = 0x0061, 'ñ' = 0x00F1, 'z' = 0x007A
        // Correct UTF-16 order: a (0x0061) < z (0x007A) < ñ (0x00F1)
        // UTF-8 byte order would give: a < z < ñ (same for this case)
        let input = json!({"ñ": 3, "a": 1, "z": 2});
        let result = canonicalize(&input).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "{\"a\":1,\"z\":2,\"ñ\":3}");
    }

    #[test]
    fn test_utf16_sort_order_supplementary_plane() {
        // Supplementary plane characters (U+10000+) encode as surrogate pairs in UTF-16
        // U+1D11E (𝄞 MUSICAL SYMBOL G CLEF) = D834 DD1E in UTF-16
        // U+00E9 (é) = 00E9 in UTF-16
        // UTF-16 order: 'a' (0061) < 'é' (00E9) < '𝄞' (D834 DD1E)
        let input = json!({"𝄞": 3, "a": 1, "é": 2});
        let result = canonicalize(&input).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "{\"a\":1,\"é\":2,\"𝄞\":3}");
    }

    #[test]
    fn test_utf16_sort_cjk_keys() {
        // CJK characters: 日 (U+65E5, 65E5 in UTF-16), 本 (U+672C)
        // ASCII 'a' (0x0061) < 日 (0x65E5) < 本 (0x672C)
        let input = json!({"本": 3, "a": 1, "日": 2});
        let result = canonicalize(&input).unwrap();
        let output = String::from_utf8(result).unwrap();
        assert_eq!(output, "{\"a\":1,\"日\":2,\"本\":3}");
    }
}
