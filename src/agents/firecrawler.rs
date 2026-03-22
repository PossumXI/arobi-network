//! Firecrawler Agent — Threat Intelligence Web Crawler
//!
//! Autonomous agent that scrapes cybersecurity advisory sources
//! (CISA, NVD) for threat intelligence relevant to the Arobi Network.
//! Feature-gated behind `firecrawler`.

use chrono::{DateTime, Utc};
use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, Duration};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Threat intelligence types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub id: Uuid,
    pub title: String,
    pub content: String,
    pub url: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub discovered_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    Malware,
    Vulnerability,
    Phishing,
    DataBreach,
    NetworkIntrusion,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerStats {
    pub crawl_count: u64,
    pub cached_intelligence: usize,
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Firecrawler Agent
// ---------------------------------------------------------------------------

pub struct FirecrawlerAgent {
    client: Arc<Client>,
    active: Arc<AtomicBool>,
    crawl_count: Arc<AtomicU64>,
    intelligence_cache: Arc<RwLock<HashMap<Uuid, ThreatIntelligence>>>,
    intelligence_tx: broadcast::Sender<ThreatIntelligence>,
}

impl FirecrawlerAgent {
    pub fn new() -> Self {
        let (intelligence_tx, _) = broadcast::channel(256);
        Self {
            client: Arc::new(
                Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap_or_default(),
            ),
            active: Arc::new(AtomicBool::new(false)),
            crawl_count: Arc::new(AtomicU64::new(0)),
            intelligence_cache: Arc::new(RwLock::new(HashMap::new())),
            intelligence_tx,
        }
    }

    /// Start the background crawler loop.
    pub fn start(&self) {
        if self.active.load(Ordering::Relaxed) {
            return;
        }
        self.active.store(true, Ordering::Relaxed);

        let agent = self.clone();
        tokio::spawn(async move {
            agent.crawler_loop().await;
        });
    }

    async fn crawler_loop(&self) {
        let mut ticker = interval(Duration::from_secs(300)); // every 5 minutes

        while self.active.load(Ordering::Relaxed) {
            ticker.tick().await;

            if let Err(e) = self.crawl_threats().await {
                tracing::warn!("Firecrawler crawl error: {e}");
            }
        }
    }

    /// Crawl threat intelligence sources.
    pub async fn crawl_threats(&self) -> anyhow::Result<()> {
        let sources = vec![
            (
                "https://www.cisa.gov/news-events/cybersecurity-advisories",
                "CISA",
            ),
            ("https://nvd.nist.gov/vuln/search", "NVD"),
        ];

        for (url, source) in sources {
            tracing::debug!("Firecrawler: crawling {source}");

            match self.client.get(url).send().await {
                Ok(response) => {
                    if let Ok(html) = response.text().await {
                        let threats = self.extract_threats(&html, url, source);
                        for threat in threats {
                            self.intelligence_cache
                                .write()
                                .await
                                .insert(threat.id, threat.clone());
                            let _ = self.intelligence_tx.send(threat);
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("Firecrawler: failed to reach {source}: {e}");
                }
            }
        }

        self.crawl_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn extract_threats(&self, html: &str, url: &str, source: &str) -> Vec<ThreatIntelligence> {
        let document = Html::parse_document(html);
        let mut threats = Vec::new();

        match source {
            "CISA" => {
                if let Ok(selector) = Selector::parse("h2 a, h3 a, .c-teaser__title a") {
                    for element in document.select(&selector) {
                        if let Some(title) = element.text().next() {
                            let title = title.trim();
                            if title.is_empty() {
                                continue;
                            }
                            threats.push(ThreatIntelligence {
                                id: Uuid::new_v4(),
                                title: title.to_string(),
                                content: "CISA cybersecurity advisory".into(),
                                url: url.to_string(),
                                threat_type: self.classify_threat(title),
                                severity: self.assess_severity(title),
                                discovered_at: Utc::now(),
                            });
                        }
                    }
                }
            }
            "NVD" => {
                if let Ok(selector) =
                    Selector::parse("[data-testid=vuln-detail-title], .col-lg-9 a strong")
                {
                    for element in document.select(&selector) {
                        if let Some(title) = element.text().next() {
                            let title = title.trim();
                            if title.is_empty() {
                                continue;
                            }
                            threats.push(ThreatIntelligence {
                                id: Uuid::new_v4(),
                                title: title.to_string(),
                                content: "NVD CVE vulnerability".into(),
                                url: url.to_string(),
                                threat_type: ThreatType::Vulnerability,
                                severity: ThreatSeverity::Medium,
                                discovered_at: Utc::now(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        threats
    }

    fn classify_threat(&self, title: &str) -> ThreatType {
        let lower = title.to_lowercase();
        if lower.contains("malware") || lower.contains("trojan") || lower.contains("ransomware") {
            ThreatType::Malware
        } else if lower.contains("phishing") || lower.contains("scam") {
            ThreatType::Phishing
        } else if lower.contains("vulnerability") || lower.contains("cve") {
            ThreatType::Vulnerability
        } else if lower.contains("breach") || lower.contains("leak") {
            ThreatType::DataBreach
        } else if lower.contains("intrusion") || lower.contains("network attack") {
            ThreatType::NetworkIntrusion
        } else {
            ThreatType::Unknown
        }
    }

    fn assess_severity(&self, title: &str) -> ThreatSeverity {
        let lower = title.to_lowercase();
        if lower.contains("critical") || lower.contains("emergency") || lower.contains("urgent") {
            ThreatSeverity::Critical
        } else if lower.contains("high") || lower.contains("severe") || lower.contains("major") {
            ThreatSeverity::High
        } else if lower.contains("medium") || lower.contains("moderate") {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        }
    }

    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<ThreatIntelligence> {
        self.intelligence_tx.subscribe()
    }

    #[allow(dead_code)]
    pub async fn get_stats(&self) -> CrawlerStats {
        CrawlerStats {
            crawl_count: self.crawl_count.load(Ordering::Relaxed),
            cached_intelligence: self.intelligence_cache.read().await.len(),
            active: self.active.load(Ordering::Relaxed),
        }
    }

    #[allow(dead_code)]
    pub fn shutdown(&self) {
        self.active.store(false, Ordering::Relaxed);
        tracing::info!("Firecrawler Agent shutdown");
    }
}

impl Clone for FirecrawlerAgent {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            active: self.active.clone(),
            crawl_count: self.crawl_count.clone(),
            intelligence_cache: self.intelligence_cache.clone(),
            intelligence_tx: self.intelligence_tx.clone(),
        }
    }
}
