// Audit Ledger - Immutable record of all AI decisions
// Provides blockchain-backed audit trail for Instinct X Ability decisions

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::RwLock;

pub const AUDIT_LANE_MIGRATION_ID: &str = "arobi-ledger-lane-v0.3-20260514";

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

/// Explicit audit lane policy for public, private, and sealed 00 evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLane {
    pub lane_id: String,
    pub export_scope: String,
    pub training_policy: String,
    pub retention_class: String,
    pub migration_id: String,
}

impl AuditLane {
    pub fn from_context(network_context: &str, metadata: &HashMap<String, String>) -> Self {
        let requested = metadata
            .get("lane")
            .or_else(|| metadata.get("arobi_lane"))
            .or_else(|| metadata.get("audit_lane"))
            .or_else(|| metadata.get("ability_profile"))
            .or_else(|| metadata.get("classification"))
            .map(String::as_str)
            .unwrap_or(network_context);

        match normalize_audit_lane(requested).as_str() {
            "public" => Self {
                lane_id: "public".to_string(),
                export_scope: "public-redacted".to_string(),
                training_policy: "allowed-redacted".to_string(),
                retention_class: "public-evidence".to_string(),
                migration_id: AUDIT_LANE_MIGRATION_ID.to_string(),
            },
            "zero-zero" => Self {
                lane_id: "zero-zero".to_string(),
                export_scope: "sealed".to_string(),
                training_policy: "blocked".to_string(),
                retention_class: "sealed-evidence".to_string(),
                migration_id: AUDIT_LANE_MIGRATION_ID.to_string(),
            },
            _ => Self {
                lane_id: "private".to_string(),
                export_scope: "operator-audit".to_string(),
                training_policy: "allowed-internal".to_string(),
                retention_class: "audit-evidence".to_string(),
                migration_id: AUDIT_LANE_MIGRATION_ID.to_string(),
            },
        }
    }
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
    /// Derived lane policy for public, private, and zero-zero audit paths.
    pub lane: AuditLane,
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
    #[allow(clippy::too_many_arguments)]
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
        Self::new_with_metadata(
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
            HashMap::new(),
        )
    }

    /// Create a new audit entry with explicit metadata bound into the entry hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_metadata(
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
        metadata: HashMap<String, String>,
    ) -> Self {
        let timestamp = Utc::now();
        let input_hash = compute_hash(input_data);
        let confidence_level = classify_confidence(confidence);
        let lane = AuditLane::from_context(network_context, &metadata);

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
            lane,
            requester: None,
            clearance_level: None,
            action_taken: None,
            outcome: None,
            latency_ms,
            metadata,
            signature: None,
        };

        // Compute the hash after all fields are set
        entry.hash = entry.compute_hash();

        entry
    }

    /// Compute hash of this entry
    pub fn compute_hash(&self) -> String {
        let mut hasher = Keccak256::new();
        hash_field(&mut hasher, "entry_id", self.entry_id.as_bytes());
        hash_field(
            &mut hasher,
            "timestamp",
            self.timestamp.to_rfc3339().as_bytes(),
        );
        hash_field(
            &mut hasher,
            "block_height",
            &self.block_height.to_le_bytes(),
        );
        hash_field(&mut hasher, "previous_hash", self.previous_hash.as_bytes());
        hash_field(
            &mut hasher,
            "source",
            format!("{:?}", self.source).as_bytes(),
        );
        hash_field(
            &mut hasher,
            "decision_type",
            format!("{:?}", self.decision_type).as_bytes(),
        );
        hash_field(&mut hasher, "model_id", self.model_id.as_bytes());
        hash_field(&mut hasher, "model_version", self.model_version.as_bytes());
        hash_field(&mut hasher, "input_summary", self.input_summary.as_bytes());
        hash_field(&mut hasher, "input_hash", self.input_hash.as_bytes());
        hash_field(&mut hasher, "decision", self.decision.as_bytes());
        hash_field(
            &mut hasher,
            "confidence",
            &self.confidence.to_bits().to_le_bytes(),
        );
        hash_field(
            &mut hasher,
            "confidence_level",
            format!("{:?}", self.confidence_level).as_bytes(),
        );
        hash_field(&mut hasher, "reasoning", self.reasoning.as_bytes());
        hash_string_vec(&mut hasher, "factors", &self.factors);
        hash_bool(&mut hasher, "ethics_validated", self.ethics_validated);
        hash_optional_string(
            &mut hasher,
            "ethics_details",
            self.ethics_details.as_deref(),
        );
        hash_string_vec(&mut hasher, "subsystems", &self.subsystems);
        hash_field(
            &mut hasher,
            "network_context",
            self.network_context.as_bytes(),
        );
        hash_lane(&mut hasher, &self.lane);
        hash_optional_string(&mut hasher, "requester", self.requester.as_deref());
        hash_optional_string(
            &mut hasher,
            "clearance_level",
            self.clearance_level.as_deref(),
        );
        hash_optional_string(&mut hasher, "action_taken", self.action_taken.as_deref());
        hash_optional_string(&mut hasher, "outcome", self.outcome.as_deref());
        hash_field(
            &mut hasher,
            "latency_ms",
            &self.latency_ms.to_bits().to_le_bytes(),
        );
        hash_metadata(&mut hasher, &self.metadata);

        hex::encode(hasher.finalize())
    }

    fn compute_legacy_pre_lane_hash(&self) -> String {
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
            lane: self.lane.clone(),
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

/// Upgrade legacy audit entries that were stored before lane policy was hash-bound.
///
/// Callers must mark entries whose serialized form was missing `lane`. Those
/// entries are first checked against the pre-lane hash algorithm, then the
/// entire chain is restamped with the current hash contract so durable startup
/// verification can keep failing closed for genuinely tampered data.
pub fn migrate_legacy_lane_entries(
    mut entries: Vec<(AuditEntry, bool)>,
) -> Result<(Vec<AuditEntry>, bool), String> {
    entries.sort_by_key(|(entry, _)| entry.block_height);

    let has_legacy_entry = entries.iter().any(|(_, missing_lane)| *missing_lane);
    if !has_legacy_entry {
        return Ok((entries.into_iter().map(|(entry, _)| entry).collect(), false));
    }

    let mut original_expected_previous_hash = "0".repeat(64);
    let mut migrated_previous_hash = "0".repeat(64);
    let mut migrated_entries = Vec::with_capacity(entries.len());

    for (mut entry, missing_lane) in entries {
        if entry.previous_hash != original_expected_previous_hash {
            return Err(format!(
                "legacy audit lane migration failed at block {}: previous hash mismatch",
                entry.block_height
            ));
        }

        let original_hash = entry.hash.clone();
        if missing_lane {
            let legacy_hash = entry.compute_legacy_pre_lane_hash();
            if entry.hash != legacy_hash {
                return Err(format!(
                    "legacy audit lane migration failed at block {}: legacy hash mismatch",
                    entry.block_height
                ));
            }
        } else if !entry.verify() {
            return Err(format!(
                "legacy audit lane migration failed at block {}: current hash mismatch",
                entry.block_height
            ));
        }

        original_expected_previous_hash = original_hash;
        entry.previous_hash = migrated_previous_hash;
        entry.hash = entry.compute_hash();
        migrated_previous_hash = entry.hash.clone();
        migrated_entries.push(entry);
    }

    Ok((migrated_entries, true))
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
    pub lane: AuditLane,
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

/// Training-safe audit record for Q data pipelines.
///
/// This intentionally excludes raw input hashes, signatures, requesters,
/// clearances, actions, and outcomes. Public records carry redacted metadata;
/// private records can include non-secret metadata only when explicitly
/// requested. Sealed 00 records are never represented by this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExportRecord {
    pub entry_id: String,
    pub timestamp: DateTime<Utc>,
    pub block_height: u64,
    pub lane: AuditLane,
    pub decision_source: String,
    pub decision_type: String,
    pub model_id: String,
    pub model_version: String,
    pub input_summary: String,
    pub decision: String,
    pub confidence: f64,
    pub confidence_level: ConfidenceLevel,
    pub reasoning: Option<String>,
    pub factors: Vec<String>,
    pub ethics_validated: bool,
    pub subsystems: Vec<String>,
    pub network_context: String,
    pub latency_ms: f64,
    pub integrity_verified: bool,
    pub entry_hash: String,
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
            latest_hash: RwLock::new("0".repeat(64)),
            latest_block: RwLock::new(0),
        }
    }

    /// Rehydrate an audit ledger from durable storage.
    pub fn from_entries(mut entries: Vec<AuditEntry>) -> Self {
        entries.sort_by_key(|entry| entry.block_height);
        let latest_hash = entries
            .last()
            .map(|entry| entry.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let latest_block = entries.last().map(|entry| entry.block_height).unwrap_or(0);

        Self {
            entries: RwLock::new(entries),
            latest_hash: RwLock::new(latest_hash),
            latest_block: RwLock::new(latest_block),
        }
    }

    /// Rehydrate an audit ledger and reject tampered durable entries.
    pub fn try_from_entries(entries: Vec<AuditEntry>) -> Result<Self, String> {
        let ledger = Self::from_entries(entries);
        if ledger.verify_chain() {
            Ok(ledger)
        } else {
            Err("durable audit entry chain verification failed".to_string())
        }
    }

    /// Record a new decision
    #[allow(clippy::too_many_arguments)]
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
        self.record_decision_with_metadata(
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
            HashMap::new(),
        )
    }

    /// Record a new decision with explicit metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn record_decision_with_metadata(
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
        metadata: HashMap<String, String>,
    ) -> AuditEntry {
        let block_height = {
            let mut block = self.latest_block.write().unwrap();
            *block += 1;
            *block
        };

        let previous_hash = self.latest_hash.read().unwrap().clone();

        let entry = AuditEntry::new_with_metadata(
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
            metadata,
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

    /// Roll back the latest entry after a failed durable append.
    pub fn rollback_latest(&self, entry_id: &str) -> bool {
        let mut entries = self.entries.write().unwrap();
        let Some(last) = entries.last() else {
            return false;
        };
        if last.entry_id != entry_id {
            return false;
        }

        entries.pop();
        let latest_hash = entries
            .last()
            .map(|entry| entry.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let latest_block = entries.last().map(|entry| entry.block_height).unwrap_or(0);

        *self.latest_hash.write().unwrap() = latest_hash;
        *self.latest_block.write().unwrap() = latest_block;
        true
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

    /// Get entries by normalized audit lane.
    pub fn get_entries_by_lane(&self, lane_id: &str) -> Vec<AuditEntry> {
        let normalized = normalize_audit_lane(lane_id);
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| e.lane.lane_id == normalized)
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

    /// Export audit evidence into a Q-training-safe corpus.
    ///
    /// Public lane entries are always redacted. Private lane entries require
    /// `include_internal = true`. Sealed 00 entries are blocked regardless of
    /// caller options so public/private integration cannot bleed 00 evidence
    /// into model training data.
    pub fn export_training_corpus(&self, include_internal: bool) -> Vec<TrainingExportRecord> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter_map(|entry| training_record_from_entry(entry, include_internal))
            .collect()
    }

    /// Get total entries count
    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Verify entire chain integrity
    pub fn verify_chain(&self) -> bool {
        let entries = self.entries.read().unwrap();
        let mut expected_prev = "0".repeat(64);

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

fn hash_field(hasher: &mut Keccak256, label: &str, value: &[u8]) {
    hasher.update((label.len() as u64).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn hash_bool(hasher: &mut Keccak256, label: &str, value: bool) {
    hash_field(hasher, label, if value { b"true" } else { b"false" });
}

fn hash_optional_string(hasher: &mut Keccak256, label: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_field(hasher, label, b"some");
            hash_field(hasher, label, value.as_bytes());
        }
        None => hash_field(hasher, label, b"none"),
    }
}

fn hash_string_vec(hasher: &mut Keccak256, label: &str, values: &[String]) {
    hash_field(hasher, label, &(values.len() as u64).to_le_bytes());
    for value in values {
        hash_field(hasher, label, value.as_bytes());
    }
}

fn hash_metadata(hasher: &mut Keccak256, metadata: &HashMap<String, String>) {
    hash_field(
        hasher,
        "metadata_len",
        &(metadata.len() as u64).to_le_bytes(),
    );

    let mut keys: Vec<_> = metadata.keys().collect();
    keys.sort();
    for key in keys {
        hash_field(hasher, "metadata_key", key.as_bytes());
        if let Some(value) = metadata.get(key) {
            hash_field(hasher, "metadata_value", value.as_bytes());
        }
    }
}

fn hash_lane(hasher: &mut Keccak256, lane: &AuditLane) {
    hash_field(hasher, "lane_id", lane.lane_id.as_bytes());
    hash_field(hasher, "lane_export_scope", lane.export_scope.as_bytes());
    hash_field(
        hasher,
        "lane_training_policy",
        lane.training_policy.as_bytes(),
    );
    hash_field(
        hasher,
        "lane_retention_class",
        lane.retention_class.as_bytes(),
    );
    hash_field(hasher, "lane_migration_id", lane.migration_id.as_bytes());
}

fn normalize_audit_lane(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace(['_', ' '], "-");

    match normalized.as_str() {
        "public" | "pub" | "public-network" | "public-lane" | "public-redacted" | "open"
        | "redacted" => "public".to_string(),
        "00" | "0-0" | "zero-zero" | "zerozero" | "private-00" | "mission-control"
        | "mission-control-00" | "sealed" | "classified" | "restricted" | "defense"
        | "defense-grade" => "zero-zero".to_string(),
        lane if lane.ends_with("-00") => "zero-zero".to_string(),
        "private" | "internal" | "operator" | "operator-audit" | "paid" => "private".to_string(),
        _ => "private".to_string(),
    }
}

fn training_record_from_entry(
    entry: &AuditEntry,
    include_internal: bool,
) -> Option<TrainingExportRecord> {
    match entry.lane.training_policy.as_str() {
        "blocked" => return None,
        "allowed-internal" if !include_internal => return None,
        "allowed-redacted" | "allowed-internal" => {}
        _ => return None,
    }

    let is_public_redacted = entry.lane.training_policy == "allowed-redacted";
    let metadata = sanitize_training_metadata(&entry.metadata, is_public_redacted);
    let network_context = if is_public_redacted {
        entry.lane.lane_id.clone()
    } else {
        entry.network_context.clone()
    };

    Some(TrainingExportRecord {
        entry_id: entry.entry_id.clone(),
        timestamp: entry.timestamp,
        block_height: entry.block_height,
        lane: entry.lane.clone(),
        decision_source: format!("{:?}", entry.source),
        decision_type: format!("{:?}", entry.decision_type),
        model_id: entry.model_id.clone(),
        model_version: entry.model_version.clone(),
        input_summary: entry.input_summary.clone(),
        decision: entry.decision.clone(),
        confidence: entry.confidence,
        confidence_level: entry.confidence_level.clone(),
        reasoning: if is_public_redacted {
            None
        } else {
            Some(entry.reasoning.clone())
        },
        factors: entry.factors.clone(),
        ethics_validated: entry.ethics_validated,
        subsystems: entry.subsystems.clone(),
        network_context,
        latency_ms: entry.latency_ms,
        integrity_verified: entry.verify(),
        entry_hash: entry.hash.clone(),
        metadata,
    })
}

fn sanitize_training_metadata(
    metadata: &HashMap<String, String>,
    public_redacted: bool,
) -> HashMap<String, String> {
    metadata
        .iter()
        .filter(|(key, _)| !is_sensitive_training_metadata_key(key))
        .filter(|(key, _)| !public_redacted || is_public_training_metadata_key(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn is_public_training_metadata_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "lane"
            | "arobi_lane"
            | "audit_lane"
            | "source_system"
            | "route"
            | "release"
            | "version"
            | "policy"
            | "category"
            | "environment"
    )
}

fn is_sensitive_training_metadata_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "key",
        "password",
        "credential",
        "classified",
        "clearance",
        "requester",
        "wallet",
        "private",
        "signature",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
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

#[cfg(test)]
mod tribunal_integrity_tests {
    use super::*;

    fn sample_entry(network_context: &str) -> AuditEntry {
        AuditEntry::new(
            1,
            "0".repeat(64),
            DecisionSource::Ability,
            DecisionType::TrainingDecision,
            "q",
            "0.1.0",
            "public status sample",
            b"public status sample",
            "allow-redacted-training",
            0.92,
            "safe public status evidence",
            vec!["lane_policy".to_string()],
            true,
            vec!["laas".to_string()],
            network_context,
            12.5,
        )
    }

    #[test]
    fn audit_hash_binds_lane_and_accountability_fields() {
        let mut entry = sample_entry("public");
        assert!(entry.verify());

        entry.network_context = "00".to_string();
        assert!(
            !entry.verify(),
            "network context tampering must break audit integrity"
        );

        let mut entry = sample_entry("public");
        entry.metadata.insert(
            "training_policy".to_string(),
            "allowed-redacted".to_string(),
        );
        assert!(
            !entry.verify(),
            "metadata added after recording must break audit integrity"
        );

        let mut entry = sample_entry("public");
        entry.requester = Some("AROBI123".to_string());
        assert!(
            !entry.verify(),
            "requester tampering must break audit integrity"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> AuditEntry {
        AuditEntry::new(
            7,
            "0".repeat(64),
            DecisionSource::Cortex,
            DecisionType::NetworkRouting,
            "q-ledger",
            "1.0.0",
            "Route a governed public lane action",
            b"route governed public lane action",
            "allow_with_audit",
            0.92,
            "The action matched the lane policy and had enough confidence.",
            vec!["lane_policy_match".to_string(), "confidence_ok".to_string()],
            true,
            vec!["laas".to_string(), "q".to_string()],
            "public",
            34.5,
        )
    }

    #[test]
    fn audit_entry_verify_detects_tribunal_field_tampering() {
        let mut entry = sample_entry();
        entry.ethics_details = Some("approved by policy governor".to_string());
        entry.requester = Some("founder".to_string());
        entry.clearance_level = Some("admin".to_string());
        entry.action_taken = Some("queued".to_string());
        entry.outcome = Some("accepted".to_string());
        entry
            .metadata
            .insert("lane".to_string(), "public".to_string());
        entry.hash = entry.compute_hash();

        assert!(entry.verify());

        let mut tampered = entry.clone();
        tampered.input_summary = "Changed summary".to_string();
        assert!(!tampered.verify(), "input summary must be hash-bound");

        let mut tampered = entry.clone();
        tampered.factors.push("unrecorded_factor".to_string());
        assert!(!tampered.verify(), "factors must be hash-bound");

        let mut tampered = entry.clone();
        tampered.ethics_validated = false;
        assert!(!tampered.verify(), "ethics result must be hash-bound");

        let mut tampered = entry.clone();
        tampered.ethics_details = Some("changed approval".to_string());
        assert!(!tampered.verify(), "ethics details must be hash-bound");

        let mut tampered = entry.clone();
        tampered.subsystems.push("unlogged_subsystem".to_string());
        assert!(!tampered.verify(), "subsystems must be hash-bound");

        let mut tampered = entry.clone();
        tampered.network_context = "zero-zero".to_string();
        assert!(!tampered.verify(), "network context must be hash-bound");

        let mut tampered = entry.clone();
        tampered.requester = Some("different-requester".to_string());
        assert!(!tampered.verify(), "requester must be hash-bound");

        let mut tampered = entry.clone();
        tampered.clearance_level = Some("elevated".to_string());
        assert!(!tampered.verify(), "clearance must be hash-bound");

        let mut tampered = entry.clone();
        tampered.action_taken = Some("executed".to_string());
        assert!(!tampered.verify(), "action taken must be hash-bound");

        let mut tampered = entry.clone();
        tampered.outcome = Some("changed".to_string());
        assert!(!tampered.verify(), "outcome must be hash-bound");

        let mut tampered = entry.clone();
        tampered.latency_ms = 99.9;
        assert!(!tampered.verify(), "latency must be hash-bound");

        let mut tampered = entry.clone();
        tampered
            .metadata
            .insert("lane".to_string(), "private".to_string());
        assert!(!tampered.verify(), "metadata must be hash-bound");
    }

    #[test]
    fn audit_ledger_verify_chain_detects_stored_entry_metadata_tampering() {
        let ledger = AuditLedger::new();
        ledger.record_decision(
            DecisionSource::Cortex,
            DecisionType::NetworkRouting,
            "q-ledger",
            "1.0.0",
            "Route a governed public lane action",
            b"route governed public lane action",
            "allow_with_audit",
            0.92,
            "The action matched the lane policy and had enough confidence.",
            vec!["lane_policy_match".to_string()],
            true,
            vec!["laas".to_string()],
            "public",
            34.5,
        );

        assert!(ledger.verify_chain());

        {
            let mut entries = ledger.entries.write().unwrap();
            entries[0]
                .metadata
                .insert("lane".to_string(), "zero-zero".to_string());
        }

        assert!(!ledger.verify_chain());
    }

    #[test]
    fn try_from_entries_rejects_tampered_durable_entries() {
        let ledger = AuditLedger::new();
        let mut entry = ledger.record_decision(
            DecisionSource::Cortex,
            DecisionType::NetworkRouting,
            "q-ledger",
            "1.0.0",
            "Load durable audit evidence",
            b"load durable audit evidence",
            "load",
            0.91,
            "Durable audit evidence must verify before node startup.",
            vec!["durable_verify".to_string()],
            true,
            vec!["laas".to_string()],
            "public",
            12.0,
        );
        entry.outcome = Some("tampered-after-write".to_string());

        match AuditLedger::try_from_entries(vec![entry]) {
            Ok(_) => panic!("tampered durable audit entries must be rejected"),
            Err(err) => assert!(err.contains("verification failed")),
        }
    }

    #[test]
    fn audit_lanes_keep_public_private_and_zero_zero_policies_separate() {
        let ledger = AuditLedger::new();

        let public = ledger.record_decision_with_metadata(
            DecisionSource::Cortex,
            DecisionType::NetworkRouting,
            "q-ledger",
            "1.0.0",
            "Route public evidence",
            b"route public evidence",
            "allow_redacted",
            0.91,
            "Public lane can be exported only in redacted form.",
            vec!["public_lane".to_string()],
            true,
            vec!["laas".to_string()],
            "private",
            20.0,
            HashMap::from([("lane".to_string(), "public".to_string())]),
        );

        let zero_zero = ledger.record_decision_with_metadata(
            DecisionSource::Cortex,
            DecisionType::NetworkRouting,
            "q-ledger",
            "1.0.0",
            "Route sealed evidence",
            b"route sealed evidence",
            "seal",
            0.99,
            "00 evidence is retained for audit and blocked from training export.",
            vec!["sealed_lane".to_string()],
            true,
            vec!["laas".to_string()],
            "mission-control-00",
            28.0,
            HashMap::new(),
        );

        assert_eq!(public.lane.lane_id, "public");
        assert_eq!(public.lane.export_scope, "public-redacted");
        assert_eq!(public.lane.training_policy, "allowed-redacted");
        assert_eq!(zero_zero.lane.lane_id, "zero-zero");
        assert_eq!(zero_zero.lane.export_scope, "sealed");
        assert_eq!(zero_zero.lane.training_policy, "blocked");
        assert_eq!(ledger.get_entries_by_lane("public").len(), 1);
        assert_eq!(ledger.get_entries_by_lane("00").len(), 1);
    }

    #[test]
    fn training_export_never_leaks_zero_zero_and_redacts_public_metadata() {
        let ledger = AuditLedger::new();

        let public = ledger.record_decision_with_metadata(
            DecisionSource::Cortex,
            DecisionType::TrainingDecision,
            "q-ledger",
            "1.0.0",
            "Summarize public launch telemetry",
            b"public launch telemetry with internal request context",
            "include_public_signal",
            0.86,
            "Public telemetry is useful but requester data is not training-safe.",
            vec!["public_signal".to_string()],
            true,
            vec!["laas".to_string()],
            "public",
            18.0,
            HashMap::from([
                ("lane".to_string(), "public".to_string()),
                ("source_system".to_string(), "public-status".to_string()),
                ("requester_wallet".to_string(), "AROBI-PRIVATE".to_string()),
                ("api_token".to_string(), "secret-token".to_string()),
            ]),
        );

        let private = ledger.record_decision_with_metadata(
            DecisionSource::Ability,
            DecisionType::ModelInference,
            "q-ledger",
            "1.0.0",
            "Route private operator workflow",
            b"private operator workflow",
            "include_internal_signal",
            0.91,
            "Private operator evidence can train internal Q adapters.",
            vec!["private_signal".to_string()],
            true,
            vec!["laas".to_string(), "q".to_string()],
            "private",
            24.0,
            HashMap::from([
                ("lane".to_string(), "private".to_string()),
                ("route".to_string(), "operator".to_string()),
                ("secret_key".to_string(), "never-export".to_string()),
            ]),
        );

        let zero_zero = ledger.record_decision_with_metadata(
            DecisionSource::Instinct,
            DecisionType::ThreatAssessment,
            "q-ledger",
            "1.0.0",
            "Classified 00 assessment",
            b"classified 00 assessment",
            "seal",
            0.99,
            "00 evidence stays sealed.",
            vec!["sealed_signal".to_string()],
            true,
            vec!["laas".to_string()],
            "00",
            31.0,
            HashMap::from([("lane".to_string(), "00".to_string())]),
        );

        let public_only = ledger.export_training_corpus(false);
        assert_eq!(public_only.len(), 1);
        assert_eq!(public_only[0].entry_id, public.entry_id);
        assert_eq!(public_only[0].lane.training_policy, "allowed-redacted");
        assert_eq!(public_only[0].network_context, "public");
        assert!(!public_only[0].metadata.contains_key("requester_wallet"));
        assert!(!public_only[0].metadata.contains_key("api_token"));
        assert_eq!(
            public_only[0].metadata.get("source_system").unwrap(),
            "public-status"
        );
        assert!(public_only[0].reasoning.is_none());

        let include_internal = ledger.export_training_corpus(true);
        let exported_ids: Vec<_> = include_internal
            .iter()
            .map(|record| record.entry_id.as_str())
            .collect();
        assert!(exported_ids.contains(&public.entry_id.as_str()));
        assert!(exported_ids.contains(&private.entry_id.as_str()));
        assert!(!exported_ids.contains(&zero_zero.entry_id.as_str()));

        let private_record = include_internal
            .iter()
            .find(|record| record.entry_id == private.entry_id)
            .unwrap();
        assert_eq!(private_record.lane.training_policy, "allowed-internal");
        assert_eq!(
            private_record.reasoning.as_deref(),
            Some(private.reasoning.as_str())
        );
        assert_eq!(private_record.metadata.get("route").unwrap(), "operator");
        assert!(!private_record.metadata.contains_key("secret_key"));
    }
}
