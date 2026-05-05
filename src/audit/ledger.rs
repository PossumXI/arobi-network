// Audit Ledger - Immutable record of all AI decisions
// Provides blockchain-backed audit trail for Instinct X Ability decisions

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::RwLock;

/// Source of the AI decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    /// Instinct - Real-time defense orchestration
    Instinct,
    /// Ability - ML/AI knowledge processing
    Ability,
    /// Cortex - Super Brain orchestration layer
    Cortex,
    /// External agent or model
    External(String),
}

/// Type of decision made
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionType {
    /// Defense engagement decision
    DefenseEngage,
    /// Threat assessment
    ThreatAssessment,
    /// Resource allocation
    ResourceAllocation,
    /// Query response
    QueryResponse,
    /// Model inference
    ModelInference,
    /// Training decision
    TrainingDecision,
    /// Ethics validation
    EthicsValidation,
    /// Network routing
    NetworkRouting,
    /// Subsystem command
    SubsystemCommand,
    /// General query
    GeneralQuery,
}

/// Confidence level of the decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Represents a single audit entry for an AI decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this audit entry
    pub entry_id: String,
    /// Timestamp of the decision (ISO 8601)
    pub timestamp: DateTime<Utc>,
    /// Block height when recorded
    pub block_height: u64,
    /// Hash of the previous entry (chain integrity)
    pub previous_hash: String,
    /// Hash of this entry
    pub hash: String,
    /// Source of the decision
    pub source: DecisionSource,
    /// Type of decision
    pub decision_type: DecisionType,
    /// Model/agent that made the decision
    pub model_id: String,
    /// Model version
    pub model_version: String,
    /// Input that led to the decision
    pub input_summary: String,
    /// Full input hash for verification
    pub input_hash: String,
    /// The decision made
    pub decision: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Confidence level classification
    pub confidence_level: ConfidenceLevel,
    /// Reasoning/justification
    pub reasoning: String,
    /// All factors considered
    pub factors: Vec<String>,
    /// Ethics validation result
    pub ethics_validated: bool,
    /// Ethics approval details
    pub ethics_details: Option<String>,
    /// Subsystems involved
    pub subsystems: Vec<String>,
    /// Network context (public/private)
    pub network_context: String,
    /// Requesting wallet/address
    pub requester: Option<String>,
    /// Requester clearance level
    pub clearance_level: Option<String>,
    /// Action taken (if any)
    pub action_taken: Option<String>,
    /// Outcome/result
    pub outcome: Option<String>,
    /// Latency in milliseconds
    pub latency_ms: f64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Digital signature for non-repudiation
    pub signature: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry with computed hashes
    pub fn new(
        block_height: u64,
        previous_hash: String,
        source: DecisionSource,
        decision_type: DecisionType,
        model_id: &str,
        model_version: &str,
        input_summary: &str,
        input_data: &[u8],
        decision: &str,
        confidence: f64,
        reasoning: &str,
        factors: Vec<String>,
        ethics_validated: bool,
        subsystems: Vec<String>,
        network_context: &str,
        latency_ms: f64,
    ) -> Self {
        let timestamp = Utc::now();
        let input_hash = compute_hash(input_data);
        let confidence_level = classify_confidence(confidence);

        let mut entry = Self {
            entry_id: uuid_v4(),
            timestamp,
            block_height,
            previous_hash: previous_hash.clone(),
            hash: String::new(),
            source,
            decision_type,
            model_id: model_id.to_string(),
            model_version: model_version.to_string(),
            input_summary: input_summary.to_string(),
            input_hash,
            decision: decision.to_string(),
            confidence,
            confidence_level,
            reasoning: reasoning.to_string(),
            factors,
            ethics_validated,
            ethics_details: None,
            subsystems,
            network_context: network_context.to_string(),
            requester: None,
            clearance_level: None,
            action_taken: None,
            outcome: None,
            latency_ms,
            metadata: HashMap::new(),
            signature: None,
        };

        // Compute the hash after all fields are set
        entry.hash = entry.compute_hash();

        entry
    }

    /// Compute hash of this entry
    pub fn compute_hash(&self) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(self.entry_id.as_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{}", self.block_height).as_bytes());
        hasher.update(self.previous_hash.as_bytes());
        hasher.update(format!("{:?}", self.source).as_bytes());
        hasher.update(format!("{:?}", self.decision_type).as_bytes());
        hasher.update(self.model_id.as_bytes());
        hasher.update(self.model_version.as_bytes());
        hasher.update(self.input_hash.as_bytes());
        hasher.update(self.decision.as_bytes());
        hasher.update(format!("{}", self.confidence).as_bytes());
        hasher.update(self.reasoning.as_bytes());

        hex::encode(hasher.finalize())
    }

    /// Verify the integrity of this entry
    pub fn verify(&self) -> bool {
        self.hash == self.compute_hash()
    }

    /// Convert to tribunal-friendly format
    pub fn to_tribunal_format(&self) -> TribunalFormat {
        TribunalFormat {
            case_number: self.entry_id.clone(),
            hearing_date: self.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            ai_system: format!("{} v{}", self.model_id, self.model_version),
            decision_source: format!("{:?}", self.source),
            decision_type: format!("{:?}", self.decision_type),
            input_summary: self.input_summary.clone(),
            decision: self.decision.clone(),
            confidence: format!("{:.2}%", self.confidence * 100.0),
            confidence_level: format!("{:?}", self.confidence_level),
            reasoning: self.reasoning.clone(),
            factors_considered: self.factors.clone(),
            ethics_approval: self.ethics_validated,
            ethics_details: self.ethics_details.clone(),
            subsystems_involved: self.subsystems.clone(),
            network: self.network_context.clone(),
            requester: self
                .requester
                .clone()
                .unwrap_or_else(|| "Anonymous".to_string()),
            clearance: self
                .clearance_level
                .clone()
                .unwrap_or_else(|| "None".to_string()),
            action: self
                .action_taken
                .clone()
                .unwrap_or_else(|| "None".to_string()),
            outcome: self
                .outcome
                .clone()
                .unwrap_or_else(|| "Pending".to_string()),
            latency_ms: format!("{:.2}ms", self.latency_ms),
            integrity_verified: self.verify(),
            block_height: self.block_height,
            entry_hash: self.hash.clone(),
            previous_hash: self.previous_hash.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

/// Tribunal-friendly formatted entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TribunalFormat {
    pub case_number: String,
    pub hearing_date: String,
    pub ai_system: String,
    pub decision_source: String,
    pub decision_type: String,
    pub input_summary: String,
    pub decision: String,
    pub confidence: String,
    pub confidence_level: String,
    pub reasoning: String,
    pub factors_considered: Vec<String>,
    pub ethics_approval: bool,
    pub ethics_details: Option<String>,
    pub subsystems_involved: Vec<String>,
    pub network: String,
    pub requester: String,
    pub clearance: String,
    pub action: String,
    pub outcome: String,
    pub latency_ms: String,
    pub integrity_verified: bool,
    pub block_height: u64,
    pub entry_hash: String,
    pub previous_hash: String,
    pub metadata: HashMap<String, String>,
}

/// Main audit ledger
pub struct AuditLedger {
    pub entries: RwLock<Vec<AuditEntry>>,
    latest_hash: RwLock<String>,
    latest_block: RwLock<u64>,
}

impl AuditLedger {
    /// Create a new audit ledger
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            latest_hash: RwLock::new(String::from("0".repeat(64))),
            latest_block: RwLock::new(0),
        }
    }

    /// Record a new decision
    pub fn record_decision(
        &self,
        source: DecisionSource,
        decision_type: DecisionType,
        model_id: &str,
        model_version: &str,
        input_summary: &str,
        input_data: &[u8],
        decision: &str,
        confidence: f64,
        reasoning: &str,
        factors: Vec<String>,
        ethics_validated: bool,
        subsystems: Vec<String>,
        network_context: &str,
        latency_ms: f64,
    ) -> AuditEntry {
        let block_height = {
            let mut block = self.latest_block.write().unwrap();
            *block += 1;
            *block
        };

        let previous_hash = self.latest_hash.read().unwrap().clone();

        let entry = AuditEntry::new(
            block_height,
            previous_hash,
            source,
            decision_type,
            model_id,
            model_version,
            input_summary,
            input_data,
            decision,
            confidence,
            reasoning,
            factors,
            ethics_validated,
            subsystems,
            network_context,
            latency_ms,
        );

        // Update latest hash
        {
            let mut latest = self.latest_hash.write().unwrap();
            *latest = entry.hash.clone();
        }

        // Store entry
        {
            let mut entries = self.entries.write().unwrap();
            entries.push(entry.clone());
        }

        entry
    }

    /// Get entry by ID
    pub fn get_entry(&self, entry_id: &str) -> Option<AuditEntry> {
        let entries = self.entries.read().unwrap();
        entries.iter().find(|e| e.entry_id == entry_id).cloned()
    }

    /// Get entries by source
    pub fn get_entries_by_source(&self, source: &DecisionSource) -> Vec<AuditEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| &e.source == source)
            .cloned()
            .collect()
    }

    /// Get entries by decision type
    pub fn get_entries_by_type(&self, decision_type: &DecisionType) -> Vec<AuditEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| &e.decision_type == decision_type)
            .cloned()
            .collect()
    }

    /// Get entries within time range
    pub fn get_entries_in_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<AuditEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Get all entries for tribunal export
    pub fn get_all_for_tribunal(&self) -> Vec<TribunalFormat> {
        let entries = self.entries.read().unwrap();
        entries.iter().map(|e| e.to_tribunal_format()).collect()
    }

    /// Get total entries count
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Verify entire chain integrity
    pub fn verify_chain(&self) -> bool {
        let entries = self.entries.read().unwrap();
        let mut expected_prev = String::from("0".repeat(64));

        for entry in entries.iter() {
            if entry.previous_hash != expected_prev {
                return false;
            }
            if !entry.verify() {
                return false;
            }
            expected_prev = entry.hash.clone();
        }

        true
    }

    /// Export chain as JSON for forensics
    pub fn export_forensics(&self) -> String {
        let entries = self.entries.read().unwrap();
        serde_json::to_string_pretty(&*entries).unwrap_or_default()
    }
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify confidence level
fn classify_confidence(confidence: f64) -> ConfidenceLevel {
    if confidence >= 0.9 {
        ConfidenceLevel::Critical
    } else if confidence >= 0.75 {
        ConfidenceLevel::High
    } else if confidence >= 0.5 {
        ConfidenceLevel::Medium
    } else {
        ConfidenceLevel::Low
    }
}

/// Compute SHA3-256 hash
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Generate UUID v4
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let random: u128 = rand_simple();
    format!("{:032x}-{:032x}", timestamp, random)
}

/// Simple random number generator
fn rand_simple() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos.wrapping_mul(1103515245).wrapping_add(12345)
}
