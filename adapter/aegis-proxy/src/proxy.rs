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
use sha2::{Sha256, Digest};
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
    /// Per-identity rate limiter (None in pass-through mode).
    pub rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
}

/// Build the axum router for the proxy server.
///
/// Routes:
/// - `/*path` — catch-all that forwards everything to upstream
/// - `/aegis/*` — cognitive bridge routes (handled by cognitive_bridge module)
/// - Optional: `/{dashboard_path}/*` — dashboard routes (mounted by adapter)
pub fn build_router(state: AppState, dashboard: Option<(String, Router)>) -> Router {
    let body_limit = state.config.max_body_size;

    let mut router = Router::new()
        // Cognitive bridge routes (aegis tool endpoints)
        .nest("/aegis", crate::cognitive_bridge::routes())
        // Catch-all proxy handler
        .route("/{*path}", any(forward_request))
        .route("/", any(forward_request))
        .layer(RequestBodyLimitLayer::new(body_limit))
        .with_state(state);

    // Mount dashboard after with_state — dashboard has its own state (Arc<DashboardSharedState>)
    if let Some((path, dashboard_router)) = dashboard {
        router = router.nest(&path, dashboard_router);
    }

    router
}

/// Start the proxy server.
///
/// `dashboard` is an optional `(path, Router)` to mount the dashboard sub-router.
pub async fn start(
    config: ProxyConfig,
    hooks: MiddlewareHooks,
    dashboard: Option<(String, Router)>,
) -> Result<(), ProxyError> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 min for long LLM responses
        .build()
        .map_err(|e| ProxyError::Internal(format!("failed to build HTTP client: {e}")))?;

    let rate_limiter = if config.mode != ProxyMode::PassThrough {
        Some(Arc::new(crate::rate_limit::RateLimiter::new(
            config.rate_limit_per_minute,
            50, // burst size
        )))
    } else {
        None
    };

    let state = AppState {
        config: config.clone(),
        client,
        hooks: Arc::new(hooks),
        identity_fingerprint: None,
        rate_limiter,
    };

    let app = build_router(state, dashboard);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| ProxyError::Internal(format!("failed to bind {}: {e}", config.listen_addr)))?;

    if config.upstream_url == "https://api.anthropic.com" {
        warn!("Using default upstream (Anthropic). Set 'upstream_url' in config.toml for other providers.");
    }

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
    // Detect provider from request headers. Phase 1 supports Anthropic only.
    // OpenAI requests get a clear error message instead of a confusing 400.
    if !state.config.allow_any_provider {
        let detected_provider = anthropic::detect_provider(&headers);
        if detected_provider != anthropic::DetectedProvider::Anthropic {
            return Ok(anthropic::unsupported_provider_response(detected_provider));
        }
    }

    // --- Rate limiting (C13) ---
    if let Some(ref limiter) = state.rate_limiter {
        let rate_key = state.identity_fingerprint
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        if let Err(retry_after) = limiter.check(&rate_key) {
            let retry_secs = retry_after.ceil() as u64;
            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_secs.to_string())],
                format!("rate limited: retry after {retry_secs}s"),
            ).into_response());
        }
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
    // Detect SSE via Content-Type or chunked Transfer-Encoding.
    let is_sse = resp_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    let is_chunked = resp_headers
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|te| te.contains("chunked"))
        .unwrap_or(false);

    if is_sse || is_chunked {
        let status = StatusCode::from_u16(resp_status)
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = Response::builder().status(status);

        for (key, value) in resp_headers.iter() {
            if !skip_headers.contains(&key.as_str()) {
                response = response.header(key, value);
            }
        }

        // Forward stream through a channel, hashing chunks incrementally.
        let byte_stream = upstream_resp.bytes_stream();
        let (chunk_tx, chunk_rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(32);
        let (evidence_tx, evidence_rx) = tokio::sync::oneshot::channel::<(String, usize)>();

        // Background task: read upstream chunks → hash → forward to client
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut hasher = Sha256::new();
            let mut total: usize = 0;
            let mut stream = std::pin::pin!(byte_stream);

            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        hasher.update(&chunk);
                        total += chunk.len();
                        let result: Result<bytes::Bytes, std::io::Error> = Ok(chunk);
                        if chunk_tx.send(result).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                    Err(e) => {
                        let _ = chunk_tx.send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        ))).await;
                        break;
                    }
                }
            }

            let hash_hex = hex::encode(hasher.finalize());
            let _ = evidence_tx.send((hash_hex, total));
        });

        let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(chunk_rx));

        // Spawn evidence recording task that waits for stream completion.
        if state.config.mode != ProxyMode::PassThrough {
            let evidence_hooks = state.hooks.clone();
            let req_info_clone = req_info.clone();

            tokio::spawn(async move {
                if let Ok((hash_hex, total)) = evidence_rx.await {
                    let duration_ms = start_time.elapsed().as_millis() as u64;
                    let resp_info = ResponseInfo {
                        status: resp_status,
                        body_size: total,
                        body_hash: hash_hex,
                        duration_ms,
                    };

                    if let Some(ref evidence) = evidence_hooks.evidence {
                        if let Err(e) = evidence.on_response(&req_info_clone, &resp_info).await {
                            warn!("evidence hook error on SSE response: {e}");
                        }
                    }
                }
            });
        }

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
            rate_limiter: None,
        };
        let _router = build_router(state, None);
        // If it doesn't panic, it works
    }

    #[test]
    fn app_state_with_fingerprint() {
        let state = AppState {
            config: ProxyConfig::default(),
            client: Client::new(),
            hooks: Arc::new(MiddlewareHooks::default()),
            identity_fingerprint: Some("abc123def456".to_string()),
            rate_limiter: None,
        };
        assert_eq!(state.identity_fingerprint.as_deref(), Some("abc123def456"));
    }
}
