//! Job scheduler — matches compute jobs to capable workers,
//! handles assignment, and verifies results via redundant execution.

use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{info, warn};

use super::types::*;

/// Scheduler manages job lifecycle: submission → assignment → execution → verification.
pub struct Scheduler {
    /// All known node capabilities indexed by address.
    capabilities: RwLock<HashMap<String, NodeCapability>>,
    /// Active jobs indexed by job_id.
    jobs: RwLock<HashMap<String, ComputeJob>>,
    /// Worker bids indexed by job_id.
    bids: RwLock<HashMap<String, Vec<WorkerBid>>>,
    /// Completed job count.
    completed_count: std::sync::atomic::AtomicU64,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            capabilities: RwLock::new(HashMap::new()),
            jobs: RwLock::new(HashMap::new()),
            bids: RwLock::new(HashMap::new()),
            completed_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    // ── Capability Registration ───────────────────────────────────────────

    /// Register or update a node's capabilities.
    pub fn register_capability(&self, cap: NodeCapability) {
        info!(
            "Compute node registered: {} ({} cores, {} MB RAM)",
            &cap.node_address[..12.min(cap.node_address.len())],
            cap.cpu_cores,
            cap.ram_mb,
        );
        self.capabilities
            .write()
            .insert(cap.node_address.clone(), cap);
    }

    /// Get all registered capabilities.
    pub fn list_capabilities(&self) -> Vec<NodeCapability> {
        self.capabilities.read().values().cloned().collect()
    }

    /// Get capability for a specific node.
    pub fn get_capability(&self, address: &str) -> Option<NodeCapability> {
        self.capabilities.read().get(address).cloned()
    }

    /// Number of registered compute nodes.
    pub fn node_count(&self) -> usize {
        self.capabilities.read().len()
    }

    // ── Job Submission ────────────────────────────────────────────────────

    /// Submit a new compute job.
    pub fn submit_job(&self, job: ComputeJob) -> Result<String, String> {
        let job_id = job.job_id.clone();

        if self.jobs.read().contains_key(&job_id) {
            return Err(format!("Job {job_id} already exists"));
        }

        info!("Compute job submitted: {}", &job_id[..16.min(job_id.len())]);
        self.jobs.write().insert(job_id.clone(), job);
        Ok(job_id)
    }

    /// Get a job by ID.
    pub fn get_job(&self, job_id: &str) -> Option<ComputeJob> {
        self.jobs.read().get(job_id).cloned()
    }

    /// List all jobs.
    pub fn list_jobs(&self) -> Vec<ComputeJob> {
        self.jobs.read().values().cloned().collect()
    }

    // ── Worker Bidding ────────────────────────────────────────────────────

    /// Worker submits a bid to execute a job.
    pub fn submit_bid(&self, bid: WorkerBid) -> Result<(), String> {
        // Verify job exists and is pending
        let jobs = self.jobs.read();
        let job = jobs
            .get(&bid.job_id)
            .ok_or_else(|| format!("Job {} not found", bid.job_id))?;

        if job.status != JobStatus::Pending {
            return Err(format!("Job {} is not pending", bid.job_id));
        }

        // Verify worker meets requirements
        let caps = self.capabilities.read();
        let cap = caps
            .get(&bid.worker)
            .ok_or_else(|| format!("Worker {} not registered", bid.worker))?;

        if !self.meets_requirements(cap, &job.requirements) {
            return Err("Worker does not meet job requirements".to_string());
        }

        drop(jobs);
        drop(caps);

        self.bids
            .write()
            .entry(bid.job_id.clone())
            .or_default()
            .push(bid);

        Ok(())
    }

    /// Select workers for a job from the available bids.
    /// Selects the `redundancy` lowest bidders with sufficient reputation.
    pub fn assign_workers(&self, job_id: &str) -> Result<Vec<String>, String> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("Job {} not found", job_id))?;

        if job.status != JobStatus::Pending {
            return Err(format!("Job {} is not pending", job_id));
        }

        let bids = self.bids.read();
        let job_bids = bids
            .get(job_id)
            .ok_or_else(|| format!("No bids for job {}", job_id))?;

        if job_bids.len() < job.requirements.redundancy as usize {
            return Err(format!(
                "Need {} bids, only have {}",
                job.requirements.redundancy,
                job_bids.len()
            ));
        }

        // Sort by bid amount (lowest first), filter by reputation
        let mut eligible: Vec<&WorkerBid> = job_bids
            .iter()
            .filter(|b| b.reputation_score >= job.requirements.min_reputation)
            .collect();
        eligible.sort_by_key(|b| b.bid_aura);

        let selected: Vec<String> = eligible
            .iter()
            .take(job.requirements.redundancy as usize)
            .map(|b| b.worker.clone())
            .collect();

        job.assigned_workers = selected.clone();
        job.status = JobStatus::Assigned;

        info!(
            "Job {} assigned to {} workers",
            &job_id[..16.min(job_id.len())],
            selected.len()
        );

        Ok(selected)
    }

    // ── Result Submission & Verification ──────────────────────────────────

    /// Worker submits a result for a job.
    pub fn submit_result(&self, job_id: &str, result: WorkerResult) -> Result<(), String> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("Job {} not found", job_id))?;

        // Verify worker was assigned
        if !job.assigned_workers.contains(&result.worker) {
            return Err(format!(
                "Worker {} not assigned to job {}",
                result.worker, job_id
            ));
        }

        job.results.push(result);
        job.status = JobStatus::Verifying;

        // Check if we have enough results for verification
        if job.results.len() >= job.requirements.redundancy as usize {
            self.verify_results(job);
        }

        Ok(())
    }

    /// Verify results via majority consensus on result_hash.
    fn verify_results(&self, job: &mut ComputeJob) {
        let mut hash_counts: HashMap<&str, usize> = HashMap::new();

        for result in &job.results {
            *hash_counts.entry(&result.result_hash).or_insert(0) += 1;
        }

        // Find majority hash
        let majority_threshold = (job.requirements.redundancy as usize + 1) / 2;
        let majority = hash_counts
            .iter()
            .find(|(_, &count)| count >= majority_threshold);

        match majority {
            Some((hash, count)) => {
                info!(
                    "Job {} verified: {}/{} workers agree (hash {})",
                    &job.job_id[..16.min(job.job_id.len())],
                    count,
                    job.results.len(),
                    &hash[..16.min(hash.len())]
                );
                job.status = JobStatus::Completed;
                self.completed_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            None => {
                warn!(
                    "Job {} disputed: no majority agreement among {} results",
                    &job.job_id[..16.min(job.job_id.len())],
                    job.results.len()
                );
                job.status = JobStatus::Disputed;
            }
        }
    }

    // ── Marketplace Stats ─────────────────────────────────────────────────

    /// Get network-wide compute marketplace statistics.
    pub fn marketplace_stats(&self) -> MarketplaceStats {
        let caps = self.capabilities.read();
        let jobs = self.jobs.read();

        MarketplaceStats {
            total_nodes: caps.len() as u64,
            total_cpu_cores: caps.values().map(|c| c.cpu_cores as u64).sum(),
            total_gpu_nodes: caps.values().filter(|c| c.gpu.is_some()).count() as u64,
            total_ram_mb: caps.values().map(|c| c.ram_mb).sum(),
            active_jobs: jobs
                .values()
                .filter(|j| matches!(j.status, JobStatus::Running | JobStatus::Assigned))
                .count() as u64,
            completed_jobs: self
                .completed_count
                .load(std::sync::atomic::Ordering::Relaxed),
            total_aura_spent: 0, // tracked via blockchain transactions
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────

    fn meets_requirements(&self, cap: &NodeCapability, req: &JobRequirements) -> bool {
        if cap.cpu_cores < req.min_cpu_cores {
            return false;
        }
        if cap.ram_mb < req.min_ram_mb {
            return false;
        }
        if req.requires_gpu && cap.gpu.is_none() {
            return false;
        }
        if req.requires_gpu {
            if let Some(ref gpu) = cap.gpu {
                if gpu.vram_mb < req.min_gpu_vram_mb {
                    return false;
                }
            }
        }
        if cap.reputation_score < req.min_reputation {
            return false;
        }
        true
    }
}
