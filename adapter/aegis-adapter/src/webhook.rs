//! Webhook alerter — sends critical alerts to an external URL.
//!
//! When `webhook_url` is configured, a background task subscribes to the
//! dashboard alert broadcast channel and POSTs each alert as JSON.
//! Errors are logged but never block the main pipeline.

use std::time::Duration;

use aegis_dashboard::DashboardAlert;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Webhook alerter that sends `DashboardAlert` payloads to an HTTP endpoint.
pub struct WebhookAlerter {
    url: String,
    client: reqwest::Client,
}

impl WebhookAlerter {
    /// Create a new WebhookAlerter targeting the given URL.
    pub fn new(url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { url, client }
    }

    /// Send a single alert. Logs errors but never fails.
    pub async fn send(&self, alert: &DashboardAlert) {
        match self.client.post(&self.url).json(alert).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    warn!(
                        status = %resp.status(),
                        url = %self.url,
                        "webhook alert returned non-success status"
                    );
                }
            }
            Err(e) => {
                warn!(
                    url = %self.url,
                    error = %e,
                    "webhook alert failed"
                );
            }
        }
    }

    /// Spawn a background task that subscribes to the alert broadcast channel
    /// and forwards each alert to the webhook URL.
    pub fn spawn(self, mut rx: broadcast::Receiver<DashboardAlert>) {
        tokio::spawn(async move {
            info!(url = %self.url, "webhook alerter started");
            loop {
                match rx.recv().await {
                    Ok(alert) => {
                        self.send(&alert).await;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "webhook alerter lagged, skipped alerts");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("webhook alerter shutting down (channel closed)");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_alerter_creation() {
        let alerter = WebhookAlerter::new("https://example.com/webhook".to_string());
        assert_eq!(alerter.url, "https://example.com/webhook");
    }

    #[tokio::test]
    async fn webhook_alerter_handles_unreachable_url() {
        // Sending to a non-routable address should log but not panic
        let alerter = WebhookAlerter::new("http://192.0.2.1:1/webhook".to_string());
        let alert = DashboardAlert {
            ts_ms: 1234567890,
            kind: "test".to_string(),
            message: "test alert".to_string(),
            receipt_seq: 1,
        };
        // This should complete without panicking (timeout will fire)
        alerter.send(&alert).await;
    }
}
