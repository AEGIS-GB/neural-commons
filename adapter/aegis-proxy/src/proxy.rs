//! Core proxy server — transparent forwarding with middleware hooks.
//!
//! Architecture:
//!   Client → aegis-proxy (axum) → Upstream LLM Provider
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

use crate::config::{ProxyConfig, ProxyMode};
use crate::error::ProxyError;
use crate::middleware::{self, MiddlewareHooks, RequestInfo, ResponseInfo};

/// Shared application state for the proxy server.
#[derive(Clone)]
pub struct AppState {
    pub config: ProxyConfig,
    pub client: Client,
    pub hooks: Arc<MiddlewareHooks>,
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
    };

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| ProxyError::Internal(format!("failed to bind {}: {e}", config.listen_addr)))?;

    info!(
        listen = %config.listen_addr,
        upstream = %config.upstream_url,
        mode = ?config.mode,
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
    let source_ip = headers.get("x-forwarded-for")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let req_info = RequestInfo {
        method: method.to_string(),
        path: path.clone(),
        headers: headers.clone(),
        body_size: body_bytes.len(),
        body_hash,
        source_ip,
        timestamp_ms: middleware::now_ms(),
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

        // SLM hook: screen request body
        if let Some(ref slm) = state.hooks.slm {
            if !body_bytes.is_empty() {
                if let Ok(body_str) = std::str::from_utf8(&body_bytes) {
                    let decision = slm.screen(body_str).await;
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
    }

    // Forward to upstream
    let upstream_url = format!("{}{}{}", state.config.upstream_url, path, query);

    let upstream_req = state.client
        .request(method.clone(), &upstream_url)
        .body(body_bytes.to_vec());

    // Forward relevant headers (skip hop-by-hop headers)
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
        };
        let _router = build_router(state);
        // If it doesn't panic, it works
    }
}
