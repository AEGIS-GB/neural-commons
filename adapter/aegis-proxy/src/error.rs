//! Proxy error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("upstream connection failed: {0}")]
    UpstreamConnectionFailed(String),

    #[error("request too large: {size} bytes exceeds limit {limit}")]
    RequestTooLarge { size: usize, limit: usize },

    #[error("rate limit exceeded for {client}")]
    RateLimitExceeded { client: String },

    #[error("websocket error: {0}")]
    WebSocketError(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl ProxyError {
    /// Convert to an HTTP status code for error responses.
    pub fn status_code(&self) -> u16 {
        match self {
            ProxyError::UpstreamConnectionFailed(_) => 502,
            ProxyError::RequestTooLarge { .. } => 413,
            ProxyError::RateLimitExceeded { .. } => 429,
            ProxyError::WebSocketError(_) => 502,
            ProxyError::Internal(_) => 500,
        }
    }
}

/// Convert ProxyError into an axum response.
impl axum::response::IntoResponse for ProxyError {
    fn into_response(self) -> axum::response::Response {
        let status = axum::http::StatusCode::from_u16(self.status_code())
            .unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::json!({
            "error": self.to_string(),
        });
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_codes() {
        assert_eq!(
            ProxyError::UpstreamConnectionFailed("timeout".into()).status_code(),
            502
        );
        assert_eq!(
            ProxyError::RequestTooLarge {
                size: 100,
                limit: 50
            }
            .status_code(),
            413
        );
        assert_eq!(
            ProxyError::RateLimitExceeded {
                client: "1.2.3.4".into()
            }
            .status_code(),
            429
        );
        assert_eq!(
            ProxyError::WebSocketError("closed".into()).status_code(),
            502
        );
        assert_eq!(ProxyError::Internal("oops".into()).status_code(), 500);
    }

    #[test]
    fn error_display() {
        let err = ProxyError::RequestTooLarge {
            size: 200,
            limit: 100,
        };
        assert_eq!(
            err.to_string(),
            "request too large: 200 bytes exceeds limit 100"
        );
    }
}
