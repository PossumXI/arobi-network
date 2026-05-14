// Audit Ledger - Immutable record of all AI decisions
// Provides blockchain-backed audit trail for Instinct X Ability decisions

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

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

/// Per-lane accounting for a training-safe export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrainingExportLaneSummary {
    pub lane_id: String,
    pub export_scope: String,
    pub training_policy: String,
    pub retention_class: String,
    pub source_total: usize,
    pub exported_total: usize,
    pub skipped_total: usize,
    pub blocked_total: usize,
    pub integrity_failed_blocked: usize,
    pub public_reasoning_redacted: usize,
    pub metadata_keys_removed: usize,
}

/// Aggregate export evidence for Q-training corpus generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrainingExportManifest {
    pub schema_version: u32,
    pub migration_id: String,
    pub include_internal: bool,
    pub source_total: usize,
    pub exported_total: usize,
    pub public_exported: usize,
    pub private_exported: usize,
    pub private_skipped: usize,
    pub zero_zero_blocked: usize,
    pub integrity_failed_blocked: usize,
    pub public_reasoning_redacted: usize,
    pub metadata_keys_removed: usize,
    pub lane_summaries: Vec<TrainingExportLaneSummary>,
}

/// Training-safe export bundle for Q data pipelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingCorpusExport {
    pub manifest: TrainingExportManifest,
    pub records: Vec<TrainingExportRecord>,
}

/// Main audit ledger
pub struct AuditLedger {
    pub entries: RwLock<Vec<AuditEntry>>,
    latest_hash: RwLock<String>,
    latest_block: RwLock<u64>,
    append_lock: Mutex<()>,
}

impl AuditLedger {
    /// Create a new audit ledger
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            latest_hash: RwLock::new("0".repeat(64)),
            latest_block: RwLock::new(0),
            append_lock: Mutex::new(()),
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
            append_lock: Mutex::new(()),
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
        let _append_guard = self.append_lock.lock().unwrap();
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
        let _append_guard = self.append_lock.lock().unwrap();
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
        self.export_training_corpus_with_manifest(include_internal)
            .records
    }

    pub fn export_training_corpus_with_manifest(
        &self,
        include_internal: bool,
    ) -> TrainingCorpusExport {
        let entries = self.entries.read().unwrap();
        let mut records = Vec::new();
        let mut public_lane = TrainingExportLaneCounters::default();
        let mut private_lane = TrainingExportLaneCounters::default();
        let mut zero_zero_lane = TrainingExportLaneCounters::default();
        let mut manifest = TrainingExportManifest {
            schema_version: 2,
            migration_id: AUDIT_LANE_MIGRATION_ID.to_string(),
            include_internal,
            source_total: entries.len(),
            exported_total: 0,
            public_exported: 0,
            private_exported: 0,
            private_skipped: 0,
            zero_zero_blocked: 0,
            integrity_failed_blocked: 0,
            public_reasoning_redacted: 0,
            metadata_keys_removed: 0,
            lane_summaries: Vec::new(),
        };

        for entry in entries.iter() {
            let lane_counters = match entry.lane.lane_id.as_str() {
                "public" => &mut public_lane,
                "zero-zero" => &mut zero_zero_lane,
                _ => &mut private_lane,
            };
            lane_counters.source_total += 1;

            if !entry.verify() {
                manifest.integrity_failed_blocked += 1;
                lane_counters.integrity_failed_blocked += 1;
                lane_counters.blocked_total += 1;
                continue;
            }

            match entry.lane.training_policy.as_str() {
                "blocked" => {
                    manifest.zero_zero_blocked += 1;
                    lane_counters.blocked_total += 1;
                    continue;
                }
                "allowed-internal" if !include_internal => {
                    manifest.private_skipped += 1;
                    lane_counters.skipped_total += 1;
                    continue;
                }
                "allowed-redacted" | "allowed-internal" => {}
                _ => {
                    lane_counters.blocked_total += 1;
                    continue;
                }
            }

            let is_public_redacted = entry.lane.training_policy == "allowed-redacted";
            if is_public_redacted && !entry.reasoning.is_empty() {
                manifest.public_reasoning_redacted += 1;
                lane_counters.public_reasoning_redacted += 1;
            }

            if let Some(record) = training_record_from_entry(entry, include_internal) {
                let metadata_keys_removed =
                    entry.metadata.len().saturating_sub(record.metadata.len());
                manifest.metadata_keys_removed += metadata_keys_removed;
                lane_counters.metadata_keys_removed += metadata_keys_removed;
                match record.lane.lane_id.as_str() {
                    "public" => manifest.public_exported += 1,
                    "private" => manifest.private_exported += 1,
                    _ => {}
                }
                lane_counters.exported_total += 1;
                records.push(record);
            }
        }

        manifest.exported_total = records.len();
        manifest.lane_summaries = vec![
            training_lane_summary("public", &public_lane),
            training_lane_summary("private", &private_lane),
            training_lane_summary("zero-zero", &zero_zero_lane),
        ];
        TrainingCorpusExport { manifest, records }
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

#[derive(Debug, Default)]
struct TrainingExportLaneCounters {
    source_total: usize,
    exported_total: usize,
    skipped_total: usize,
    blocked_total: usize,
    integrity_failed_blocked: usize,
    public_reasoning_redacted: usize,
    metadata_keys_removed: usize,
}

fn training_lane_summary(
    lane_id: &str,
    counters: &TrainingExportLaneCounters,
) -> TrainingExportLaneSummary {
    let lane = AuditLane::from_context(lane_id, &HashMap::new());
    TrainingExportLaneSummary {
        lane_id: lane.lane_id,
        export_scope: lane.export_scope,
        training_policy: lane.training_policy,
        retention_class: lane.retention_class,
        source_total: counters.source_total,
        exported_total: counters.exported_total,
        skipped_total: counters.skipped_total,
        blocked_total: counters.blocked_total,
        integrity_failed_blocked: counters.integrity_failed_blocked,
        public_reasoning_redacted: counters.public_reasoning_redacted,
        metadata_keys_removed: counters.metadata_keys_removed,
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
        .filter(|(key, value)| is_training_metadata_value_safe(key, value, public_redacted))
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
            | "modality"
            | "vision_task"
            | "object_classes"
            | "object_count"
            | "person_count"
            | "safety_signal"
            | "safety_signal_confidence"
            | "body_language_signal"
            | "vision_privacy_policy"
    )
}

fn is_training_metadata_value_safe(key: &str, value: &str, public_redacted: bool) -> bool {
    let normalized_key = key.to_ascii_lowercase();
    let mut normalized_value = value.trim().to_ascii_lowercase();

    // This exact policy label is intentionally allowed in public vision exports.
    // Remove it before scanning for identity markers so policy text does not
    // block itself.
    for allowed_identity_policy in [
        "no_persistent_identity",
        "no-persistent-identity",
        "no persistent identity",
        "non_persistent_identity",
        "non-persistent-identity",
        "non persistent identity",
    ] {
        normalized_value = normalized_value.replace(allowed_identity_policy, "");
    }

    let unsafe_secret_markers = [
        "secret",
        "token=",
        "api_token",
        "api-key",
        "api_key",
        "password",
        "credential",
        "classified",
        "clearance",
        "requester",
        "wallet",
        "private key",
        "signature",
    ];
    if unsafe_secret_markers
        .iter()
        .any(|marker| normalized_value.contains(marker))
    {
        return false;
    }

    if !public_redacted {
        return true;
    }

    let unsafe_public_identity_markers = [
        "face_embedding",
        "face embedding",
        "facial_recognition",
        "facial recognition",
        "biometric",
        "embedding vector",
        "license_plate",
        "license plate",
        "plate_number",
        "plate number",
        "persistent_subject",
        "subject_id",
        "subject id",
        "subject_name",
        "subject name",
        "person_id",
        "person id",
        "person_name",
        "person name",
        "tracking_id",
        "tracking id",
        "identity_embedding",
        "identified as",
    ];
    if unsafe_public_identity_markers
        .iter()
        .any(|marker| normalized_value.contains(marker))
    {
        return false;
    }

    let unsafe_accusatory_markers = [
        "bad_actor",
        "bad actor",
        "criminal",
        "suspect",
        "suspicious",
        "hostile",
        "target",
        "perpetrator",
    ];
    if matches!(
        normalized_key.as_str(),
        "safety_signal" | "body_language_signal" | "vision_task"
    ) && unsafe_accusatory_markers
        .iter()
        .any(|marker| normalized_value.contains(marker))
    {
        return false;
    }

    true
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
        "face",
        "facial",
        "biometric",
        "embedding",
        "license_plate",
        "plate_number",
        "persistent_subject",
        "subject_id",
        "subject_name",
        "person_id",
        "person_name",
        "tracking_id",
        "identity",
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

    #[test]
    fn concurrent_record_decision_preserves_hash_chain() {
        let ledger = std::sync::Arc::new(AuditLedger::new());
        let workers = 12;
        let records_per_worker = 20;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(workers));

        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let ledger = ledger.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for index in 0..records_per_worker {
                        ledger.record_decision_with_metadata(
                            DecisionSource::Ability,
                            DecisionType::TrainingDecision,
                            "q-ledger",
                            "3.2.6",
                            &format!("Concurrent LaaS audit event {worker}-{index}"),
                            format!("concurrent-laas-audit-event-{worker}-{index}").as_bytes(),
                            "record-for-training-export",
                            0.88,
                            "Concurrent audit writes must preserve one canonical hash chain.",
                            vec!["concurrency_guard".to_string(), "laas".to_string()],
                            true,
                            vec!["laas".to_string(), "q".to_string()],
                            if worker % 2 == 0 { "public" } else { "private" },
                            11.0,
                            HashMap::from([("worker".to_string(), worker.to_string())]),
                        );
                    }
                })
            })
            .collect();

        for handle in handles {
            handle
                .join()
                .expect("concurrent audit append worker panicked");
        }

        assert_eq!(ledger.len(), workers * records_per_worker);
        assert!(ledger.verify_chain());

        let entries = ledger.entries.read().unwrap();
        let mut previous_hash = "0".repeat(64);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.block_height, (index + 1) as u64);
            assert_eq!(entry.previous_hash, previous_hash);
            previous_hash = entry.hash.clone();
        }
    }

    #[test]
    fn training_export_manifest_accounts_for_redaction_and_tamper_blocks() {
        let ledger = AuditLedger::new();
        let public = ledger.record_decision_with_metadata(
            DecisionSource::Ability,
            DecisionType::TrainingDecision,
            "q-ledger",
            "1.0.0",
            "Public export candidate",
            b"public export candidate",
            "allow-redacted-training",
            0.91,
            "Public reasoning must not be sent to default training exports.",
            vec!["public_policy".to_string()],
            true,
            vec!["laas".to_string()],
            "public",
            15.0,
            HashMap::from([
                ("source_system".to_string(), "qline".to_string()),
                ("api_token".to_string(), "redacted".to_string()),
            ]),
        );

        let private = ledger.record_decision_with_metadata(
            DecisionSource::Cortex,
            DecisionType::NetworkRouting,
            "q-ledger",
            "1.0.0",
            "Private export candidate",
            b"private export candidate",
            "allow-internal-training",
            0.88,
            "Private reasoning can be exported only when internal export is explicit.",
            vec!["operator_policy".to_string()],
            true,
            vec!["laas".to_string()],
            "private",
            24.0,
            HashMap::from([
                ("route".to_string(), "operator".to_string()),
                ("secret_key".to_string(), "redacted".to_string()),
            ]),
        );

        ledger.record_decision_with_metadata(
            DecisionSource::Instinct,
            DecisionType::ThreatAssessment,
            "q-ledger",
            "1.0.0",
            "Sealed export candidate",
            b"sealed export candidate",
            "block-training",
            0.97,
            "Sealed evidence must never enter the training corpus.",
            vec!["sealed_policy".to_string()],
            true,
            vec!["laas".to_string(), "zero-zero".to_string()],
            "mission-control-00",
            31.0,
            HashMap::new(),
        );

        let tampered = ledger.record_decision_with_metadata(
            DecisionSource::Ability,
            DecisionType::TrainingDecision,
            "q-ledger",
            "1.0.0",
            "Tampered public export candidate",
            b"tampered public export candidate",
            "allow-redacted-training",
            0.9,
            "This entry will be tampered after recording.",
            vec!["tamper_policy".to_string()],
            true,
            vec!["laas".to_string()],
            "public",
            18.0,
            HashMap::new(),
        );

        {
            let mut entries = ledger.entries.write().unwrap();
            let entry = entries
                .iter_mut()
                .find(|entry| entry.entry_id == tampered.entry_id)
                .unwrap();
            entry.decision = "tampered-after-recording".to_string();
        }

        let export = ledger.export_training_corpus_with_manifest(true);
        assert_eq!(export.manifest.schema_version, 2);
        assert_eq!(export.manifest.migration_id, AUDIT_LANE_MIGRATION_ID);
        assert!(export.manifest.include_internal);
        assert_eq!(export.manifest.source_total, 4);
        assert_eq!(export.manifest.exported_total, 2);
        assert_eq!(export.manifest.public_exported, 1);
        assert_eq!(export.manifest.private_exported, 1);
        assert_eq!(export.manifest.zero_zero_blocked, 1);
        assert_eq!(export.manifest.integrity_failed_blocked, 1);
        assert_eq!(export.manifest.public_reasoning_redacted, 1);
        assert_eq!(export.manifest.metadata_keys_removed, 2);

        let public_summary = export
            .manifest
            .lane_summaries
            .iter()
            .find(|summary| summary.lane_id == "public")
            .unwrap();
        assert_eq!(public_summary.export_scope, "public-redacted");
        assert_eq!(public_summary.training_policy, "allowed-redacted");
        assert_eq!(public_summary.retention_class, "public-evidence");
        assert_eq!(public_summary.source_total, 2);
        assert_eq!(public_summary.exported_total, 1);
        assert_eq!(public_summary.blocked_total, 1);
        assert_eq!(public_summary.integrity_failed_blocked, 1);

        let private_summary = export
            .manifest
            .lane_summaries
            .iter()
            .find(|summary| summary.lane_id == "private")
            .unwrap();
        assert_eq!(private_summary.source_total, 1);
        assert_eq!(private_summary.exported_total, 1);
        assert_eq!(private_summary.skipped_total, 0);

        let zero_zero_summary = export
            .manifest
            .lane_summaries
            .iter()
            .find(|summary| summary.lane_id == "zero-zero")
            .unwrap();
        assert_eq!(zero_zero_summary.export_scope, "sealed");
        assert_eq!(zero_zero_summary.training_policy, "blocked");
        assert_eq!(zero_zero_summary.source_total, 1);
        assert_eq!(zero_zero_summary.exported_total, 0);
        assert_eq!(zero_zero_summary.blocked_total, 1);

        let exported_ids: Vec<_> = export
            .records
            .iter()
            .map(|record| record.entry_id.as_str())
            .collect();
        assert!(exported_ids.contains(&public.entry_id.as_str()));
        assert!(exported_ids.contains(&private.entry_id.as_str()));
        assert!(!exported_ids.contains(&tampered.entry_id.as_str()));
    }

    #[test]
    fn public_training_export_keeps_safe_vision_metadata_and_blocks_identity_fields() {
        let ledger = AuditLedger::new();
        let public = ledger.record_decision_with_metadata(
            DecisionSource::Ability,
            DecisionType::ModelInference,
            "q-vision",
            "3.2.6",
            "Public safety vision event with non-identifying telemetry",
            b"redacted-frame-digest",
            "route-to-human-review",
            0.86,
            "The event should be represented as aggregate safety telemetry, not identity data.",
            vec![
                "vision_policy".to_string(),
                "human_review_required".to_string(),
            ],
            true,
            vec!["q-vision".to_string(), "laas".to_string()],
            "public",
            42.0,
            HashMap::from([
                ("source_system".to_string(), "q-vision".to_string()),
                ("modality".to_string(), "vision".to_string()),
                ("vision_task".to_string(), "object_detection".to_string()),
                (
                    "object_classes".to_string(),
                    "person,vehicle,backpack".to_string(),
                ),
                ("object_count".to_string(), "3".to_string()),
                ("person_count".to_string(), "1".to_string()),
                ("safety_signal".to_string(), "possible_fall".to_string()),
                ("safety_signal_confidence".to_string(), "0.82".to_string()),
                (
                    "body_language_signal".to_string(),
                    "distress_posture".to_string(),
                ),
                (
                    "vision_privacy_policy".to_string(),
                    "no_persistent_identity".to_string(),
                ),
                ("face_embedding".to_string(), "blocked".to_string()),
                ("biometric_template".to_string(), "blocked".to_string()),
                ("license_plate".to_string(), "blocked".to_string()),
                ("persistent_subject_id".to_string(), "blocked".to_string()),
            ]),
        );

        let export = ledger.export_training_corpus_with_manifest(false);
        assert_eq!(export.records.len(), 1);
        assert_eq!(export.records[0].entry_id, public.entry_id);

        let metadata = &export.records[0].metadata;
        assert_eq!(metadata.get("modality").map(String::as_str), Some("vision"));
        assert_eq!(
            metadata.get("vision_task").map(String::as_str),
            Some("object_detection")
        );
        assert_eq!(metadata.get("object_count").map(String::as_str), Some("3"));
        assert_eq!(metadata.get("person_count").map(String::as_str), Some("1"));
        assert_eq!(
            metadata.get("safety_signal").map(String::as_str),
            Some("possible_fall")
        );
        assert_eq!(
            metadata.get("body_language_signal").map(String::as_str),
            Some("distress_posture")
        );
        assert_eq!(
            metadata.get("vision_privacy_policy").map(String::as_str),
            Some("no_persistent_identity")
        );
        assert!(!metadata.contains_key("face_embedding"));
        assert!(!metadata.contains_key("biometric_template"));
        assert!(!metadata.contains_key("license_plate"));
        assert!(!metadata.contains_key("persistent_subject_id"));
        assert_eq!(export.manifest.metadata_keys_removed, 4);
    }

    #[test]
    fn public_training_export_removes_identity_and_accusatory_vision_values() {
        let ledger = AuditLedger::new();
        ledger.record_decision_with_metadata(
            DecisionSource::Ability,
            DecisionType::ModelInference,
            "q-vision",
            "3.2.8",
            "Public safety vision event with unsafe adapter metadata values",
            b"redacted-frame-digest",
            "route-to-human-review",
            0.81,
            "The event should preserve aggregate safety context without identity or accusation labels.",
            vec![
                "vision_policy".to_string(),
                "human_review_required".to_string(),
            ],
            true,
            vec!["q-vision".to_string(), "laas".to_string()],
            "public",
            39.0,
            HashMap::from([
                ("modality".to_string(), "vision".to_string()),
                (
                    "vision_task".to_string(),
                    "object_detection with face_embedding".to_string(),
                ),
                ("object_count".to_string(), "3".to_string()),
                ("person_count".to_string(), "1".to_string()),
                ("safety_signal".to_string(), "bad_actor".to_string()),
                (
                    "body_language_signal".to_string(),
                    "John Doe looks suspicious".to_string(),
                ),
                (
                    "vision_privacy_policy".to_string(),
                    "no_persistent_identity license_plate ABC123".to_string(),
                ),
            ]),
        );

        let export = ledger.export_training_corpus_with_manifest(false);
        assert_eq!(export.records.len(), 1);

        let metadata = &export.records[0].metadata;
        assert_eq!(metadata.get("modality").map(String::as_str), Some("vision"));
        assert_eq!(metadata.get("object_count").map(String::as_str), Some("3"));
        assert_eq!(metadata.get("person_count").map(String::as_str), Some("1"));
        assert!(!metadata.contains_key("vision_task"));
        assert!(!metadata.contains_key("safety_signal"));
        assert!(!metadata.contains_key("body_language_signal"));
        assert!(!metadata.contains_key("vision_privacy_policy"));
        assert_eq!(export.manifest.metadata_keys_removed, 4);
    }

    #[test]
    fn internal_training_export_removes_secret_values_from_allowed_keys() {
        let ledger = AuditLedger::new();
        ledger.record_decision_with_metadata(
            DecisionSource::Ability,
            DecisionType::TrainingDecision,
            "q-training",
            "3.2.8",
            "Private training audit event with unsafe value text",
            b"private-training-digest",
            "allow-internal-training",
            0.88,
            "Internal exports still cannot carry secret-looking values into Q training.",
            vec!["operator_audit".to_string()],
            true,
            vec!["laas".to_string(), "q-training".to_string()],
            "private",
            31.0,
            HashMap::from([
                ("route".to_string(), "operator".to_string()),
                (
                    "source_system".to_string(),
                    "benchmark api_token=should_not_export".to_string(),
                ),
                (
                    "category".to_string(),
                    "service credential bootstrap".to_string(),
                ),
            ]),
        );

        let export = ledger.export_training_corpus_with_manifest(true);
        assert_eq!(export.records.len(), 1);

        let metadata = &export.records[0].metadata;
        assert_eq!(metadata.get("route").map(String::as_str), Some("operator"));
        assert!(!metadata.contains_key("source_system"));
        assert!(!metadata.contains_key("category"));
        assert_eq!(export.manifest.metadata_keys_removed, 2);
    }
}
