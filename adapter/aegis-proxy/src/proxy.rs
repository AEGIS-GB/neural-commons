//! Core proxy server — transparent forwarding with middleware hooks.
//!
//! Architecture (corrected per D31):
//!   OpenClaw (bot) → aegis-proxy (axum) → Anthropic API
//!
//! OpenClaw IS the bot. It makes outbound HTTPS calls to LLM providers.
//! The proxy intercepts these outbound calls, inspects them, then forwards
//! to the real Anthropic API. Integration is a single config change:
//!   ~/.openclaw/openclaw.json → baseUrl: "http://127.0.0.1:AEGIS_PORT"
//!
//! The proxy captures request/response data for evidence recording,
//! barrier checks, SLM screening, and vault scanning.
//!
//! In pass-through mode: forward without inspection.
//! In observe-only/enforce mode: run middleware chain before/after forwarding.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use reqwest::Client;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

use crate::anthropic;
use crate::config::{ProxyConfig, ProxyMode};
use crate::error::ProxyError;
use crate::middleware::{self, MiddlewareHooks, RequestInfo, ResponseInfo};

/// Shared application state for the proxy server.
#[derive(Clone)]
pub struct AppState {
    pub config: ProxyConfig,
    pub client: Client,
    pub hooks: Arc<MiddlewareHooks>,
    /// Bot's Ed25519 public key fingerprint (lowercase hex).
    /// Used as rate-limit key per D30 — source IP is meaningless on localhost.
    pub identity_fingerprint: Option<String>,
}

/// Build the axum router for the proxy server.
///
/// Routes:
/// - `/*path` — catch-all that forwards everything to upstream
/// - `/aegis/*` — cognitive bridge routes (handled by cognitive_bridge module)
pub fn build_router(state: AppState) -> Router {
    let body_limit = state.config.max_body_size;

    Router::new()
        // Cognitive bridge routes (aegis tool endpoints)
        .nest("/aegis", crate::cognitive_bridge::routes())
        // Catch-all proxy handler
        .route("/{*path}", any(forward_request))
        .route("/", any(forward_request))
        .layer(RequestBodyLimitLayer::new(body_limit))
        .with_state(state)
}

/// Start the proxy server.
pub async fn start(config: ProxyConfig, hooks: MiddlewareHooks) -> Result<(), ProxyError> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 min for long LLM responses
        .build()
        .map_err(|e| ProxyError::Internal(format!("failed to build HTTP client: {e}")))?;

    let state = AppState {
        config: config.clone(),
        client,
        hooks: Arc::new(hooks),
        identity_fingerprint: None,
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| ProxyError::Internal(format!("failed to bind {}: {e}", config.listen_addr)))?;

    info!(
        listen = %config.listen_addr,
        upstream = %config.upstream_url,
        mode = ?config.mode,
        provider = ?config.provider,
        "aegis proxy starting"
    );

    axum::serve(listener, app)
        .await
        .map_err(|e| ProxyError::Internal(format!("server error: {e}")))?;

    Ok(())
}

/// Catch-all handler that forwards HTTP requests to the upstream LLM provider.
async fn forward_request(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response, ProxyError> {
    let start_time = std::time::Instant::now();

    // Extract request info
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let headers = middleware::extract_headers(req.headers());

    // --- Provider detection (D31-A) ---
    // Phase 1: Anthropic-only. Reject requests without anthropic-version header
    // with a structured 422 error instead of forwarding blindly to Anthropic
    // (which would return a confusing 400 for non-Anthropic request formats).
    if !anthropic::has_anthropic_version_header(&headers) {
        return Ok(anthropic::unsupported_provider_response());
    }

    // Read the request body
    let body_bytes = axum::body::to_bytes(req.into_body(), state.config.max_body_size)
        .await
        .map_err(|e| {
            if e.to_string().contains("length limit") {
                ProxyError::RequestTooLarge {
                    size: 0,
                    limit: state.config.max_body_size,
                }
            } else {
                ProxyError::Internal(format!("failed to read body: {e}"))
            }
        })?;

    let body_hash = middleware::body_hash(&body_bytes);

    // Rate limit key: Ed25519 fingerprint per D30, not source IP.
    // The proxy runs locally — source IP is always 127.0.0.1, which is meaningless.
    let rate_limit_key = state.identity_fingerprint
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let req_info = RequestInfo {
        method: method.to_string(),
        path: path.clone(),
        headers: headers.clone(),
        body_size: body_bytes.len(),
        body_hash,
        source_ip: rate_limit_key,
        timestamp_ms: middleware::now_ms(),
    };

    // --- Parse Anthropic request for SLM screening (BUG 5 fix) ---
    // The SLM needs actual message content, not the raw API payload
    // (which includes model name, max_tokens, etc. that waste SLM tokens).
    let anthropic_req = if !body_bytes.is_empty() {
        anthropic::parse_request(&body_bytes).ok()
    } else {
        None
    };

    // Run pre-request middleware (skip in pass-through mode)
    if state.config.mode != ProxyMode::PassThrough {
        // Evidence hook: on_request
        if let Some(ref evidence) = state.hooks.evidence {
            if let Err(e) = evidence.on_request(&req_info).await {
                warn!("evidence hook error on request: {e}");
            }
        }

        // Barrier hook: check writes
        if let Some(ref barrier) = state.hooks.barrier {
            let decision = barrier.check_write(&req_info).await;
            match decision {
                middleware::BarrierDecision::Block(reason) if state.config.mode == ProxyMode::Enforce => {
                    warn!(path = %path, reason = %reason, "barrier blocked request");
                    return Ok((StatusCode::FORBIDDEN, format!("blocked: {reason}")).into_response());
                }
                middleware::BarrierDecision::Warn(reason) => {
                    info!(path = %path, reason = %reason, "barrier warning");
                }
                middleware::BarrierDecision::Block(reason) => {
                    // observe-only: downgrade block to warn
                    info!(path = %path, reason = %reason, "barrier would block (observe-only)");
                }
                middleware::BarrierDecision::Allow => {}
            }
        }

        // SLM hook: screen parsed Anthropic message content (not raw body)
        if let Some(ref slm) = state.hooks.slm {
            let screen_content = if let Some(ref parsed) = anthropic_req {
                // Extract actual conversation content for SLM analysis
                let payload = anthropic::extract_screen_payload(parsed);
                anthropic::screen_payload_to_string(&payload)
            } else if let Ok(s) = std::str::from_utf8(&body_bytes) {
                // Fallback: use raw body if parsing failed
                s.to_string()
            } else {
                String::new()
            };

            if !screen_content.is_empty() {
                let decision = slm.screen(&screen_content).await;
                match decision {
                    middleware::SlmDecision::Reject(reason) if state.config.mode == ProxyMode::Enforce => {
                        warn!(path = %path, reason = %reason, "SLM rejected request");
                        return Ok((StatusCode::FORBIDDEN, format!("rejected: {reason}")).into_response());
                    }
                    middleware::SlmDecision::Quarantine(reason) => {
                        info!(path = %path, reason = %reason, "SLM quarantine");
                    }
                    middleware::SlmDecision::Reject(reason) => {
                        info!(path = %path, reason = %reason, "SLM would reject (observe-only)");
                    }
                    middleware::SlmDecision::Admit => {}
                }
            }
        }
    }

    // Forward to upstream
    let upstream_url = format!("{}{}{}", state.config.upstream_url, path, query);

    let upstream_req = state.client
        .request(method.clone(), &upstream_url)
        .body(body_bytes.to_vec());

    // Forward relevant headers, skipping hop-by-hop headers.
    // `host` is stripped because the original value is the proxy address (127.0.0.1:AEGIS_PORT).
    // reqwest automatically sets `Host: api.anthropic.com` from the upstream URL — this is correct.
    let skip_headers = ["host", "connection", "transfer-encoding", "content-length"];
    let mut upstream_req = upstream_req;
    for (key, value) in &headers {
        if !skip_headers.contains(&key.as_str()) {
            upstream_req = upstream_req.header(key.as_str(), value.as_str());
        }
    }

    let upstream_resp = upstream_req
        .send()
        .await
        .map_err(|e| ProxyError::UpstreamConnectionFailed(format!("{upstream_url}: {e}")))?;

    let resp_status = upstream_resp.status().as_u16();
    let resp_headers = upstream_resp.headers().clone();

    // --- SSE streaming passthrough (BUG 1 fix) ---
    // For SSE responses (Content-Type: text/event-stream), Anthropic sends events
    // that the bot reads incrementally. The old code called .bytes() which buffers
    // the entire response — the bot never sees events as they arrive.
    // Now we detect SSE and stream chunks through without buffering.
    let is_sse = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    if is_sse {
        // Streaming path: forward SSE chunks as they arrive
        let status = StatusCode::from_u16(resp_status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = Response::builder().status(status);

        // Forward response headers
        for (key, value) in resp_headers.iter() {
            if !skip_headers.contains(&key.as_str()) {
                response = response.header(key, value);
            }
        }

        // Stream the body through. Evidence receipt for streaming responses
        // is recorded asynchronously when the stream completes.
        let byte_stream = upstream_resp.bytes_stream();
        let body = Body::from_stream(byte_stream);

        // Note: post-response evidence hook for SSE is deferred — the stream
        // hasn't been consumed yet. A future iteration will wrap the stream
        // to accumulate a hash and fire the evidence hook on stream end.

        return response.body(body)
            .map_err(|e| ProxyError::Internal(format!("streaming response build error: {e}")));
    }

    // Non-streaming path: buffer and inspect the full response
    let resp_body = upstream_resp.bytes()
        .await
        .map_err(|e| ProxyError::UpstreamConnectionFailed(format!("response body: {e}")))?;

    let duration_ms = start_time.elapsed().as_millis() as u64;

    // Run post-response middleware (skip in pass-through mode)
    if state.config.mode != ProxyMode::PassThrough {
        let resp_info = ResponseInfo {
            status: resp_status,
            body_size: resp_body.len(),
            body_hash: middleware::body_hash(&resp_body),
            duration_ms,
        };

        // Evidence hook: on_response
        if let Some(ref evidence) = state.hooks.evidence {
            if let Err(e) = evidence.on_response(&req_info, &resp_info).await {
                warn!("evidence hook error on response: {e}");
            }
        }

        // Vault hook: scan response
        if let Some(ref vault) = state.hooks.vault {
            if let Ok(body_str) = std::str::from_utf8(&resp_body) {
                let vault_decision = vault.scan(body_str).await;
                if let middleware::VaultDecision::Detected(secrets) = vault_decision {
                    info!(count = secrets.len(), "vault detected credentials in response");
                }
            }
        }
    }

    // Build response
    let status = StatusCode::from_u16(resp_status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = Response::builder().status(status);

    // Forward response headers
    for (key, value) in resp_headers.iter() {
        if !skip_headers.contains(&key.as_str()) {
            response = response.header(key, value);
        }
    }

    response.body(Body::from(resp_body.to_vec()))
        .map_err(|e| ProxyError::Internal(format!("response build error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_router_creates_router() {
        let state = AppState {
            config: ProxyConfig::default(),
            client: Client::new(),
            hooks: Arc::new(MiddlewareHooks::default()),
            identity_fingerprint: None,
        };
        let _router = build_router(state);
        // If it doesn't panic, it works
    }

    #[test]
    fn app_state_with_fingerprint() {
        let state = AppState {
            config: ProxyConfig::default(),
            client: Client::new(),
            hooks: Arc::new(MiddlewareHooks::default()),
            identity_fingerprint: Some("abc123def456".to_string()),
        };
        assert_eq!(state.identity_fingerprint.as_deref(), Some("abc123def456"));
    }
}
