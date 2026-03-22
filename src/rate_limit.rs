//! Per-IP in-memory rate limiter for the Arobi Network API.
//!
//! Uses a sliding window counter approach with DashMap for concurrent access.
//! Read endpoints: 120 requests/minute. Write endpoints: 20 requests/minute.

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header::RETRY_AFTER, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Rate limiter state shared across all requests.
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of IP -> (request count, window start)
    entries: Arc<DashMap<String, (u64, Instant)>>,
    /// Maximum requests per window
    max_requests: u64,
    /// Window duration in seconds
    window_secs: u64,
}

impl RateLimiter {
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            max_requests,
            window_secs,
        }
    }

    /// Check if a request from this IP is allowed. Returns true if allowed.
    fn check(&self, ip: &str) -> bool {
        let now = Instant::now();
        let mut entry = self.entries.entry(ip.to_string()).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        // Reset window if expired
        if now.duration_since(*window_start).as_secs() >= self.window_secs {
            *count = 0;
            *window_start = now;
        }

        if *count >= self.max_requests {
            return false;
        }

        *count += 1;
        true
    }

    /// Spawn a background task to evict stale entries every 60 seconds.
    pub fn spawn_cleanup(self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();
                self.entries.retain(|_, (_, start)| {
                    now.duration_since(*start).as_secs() < self.window_secs * 2
                });
            }
        });
    }
}

/// Axum middleware for rate limiting API requests.
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        return next.run(request).await;
    }

    // Use a global rate limiter: 600 req/min for all endpoints.
    // This accommodates real-time heartbeats while still capping abusive clients.
    static LIMITER: std::sync::OnceLock<RateLimiter> = std::sync::OnceLock::new();
    let limiter = LIMITER.get_or_init(|| {
        let rl = RateLimiter::new(600, 60);
        rl.clone().spawn_cleanup();
        rl
    });

    // Get real IP from Cloudflare or proxy headers
    let ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(',').next())
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    // Bypass rate limit for loopback/LAN clients.
    let is_private = ip
        .parse::<std::net::IpAddr>()
        .map(|addr| match addr {
            std::net::IpAddr::V4(v4) => {
                let octets = v4.octets();
                v4.is_loopback()
                    || octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
        })
        .unwrap_or_else(|_| ip == "127.0.0.1" || ip == "::1");

    if is_private {
        return next.run(request).await;
    }

    if !limiter.check(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, HeaderValue::from_static("15"))],
            "Too many requests",
        )
            .into_response();
    }

    next.run(request).await
}
