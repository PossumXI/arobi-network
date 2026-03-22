//! ComputeScheduler Agent — manages the distributed compute marketplace.
//!
//! Evaluates incoming job requests, manages the execution queue,
//! dispatches jobs to local sandbox, and reports results.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

use crate::compute::reputation::ReputationOracle;
use crate::compute::sandbox::ComputeSandbox;
use crate::compute::scheduler::Scheduler;
use crate::compute::types::*;

/// Events emitted by the ComputeScheduler agent.
#[derive(Debug, Clone)]
pub enum ComputeEvent {
    JobSubmitted(String),
    JobAssigned(String, Vec<String>),
    JobCompleted(String),
    JobFailed(String, String),
    JobDisputed(String),
    WorkerRegistered(String),
}

/// Configuration for the ComputeScheduler agent.
pub struct ComputeSchedulerConfig {
    /// Whether this node should accept and execute compute jobs.
    pub accept_jobs: bool,
    /// Maximum concurrent jobs this node will execute.
    pub max_concurrent_jobs: usize,
}

impl Default for ComputeSchedulerConfig {
    fn default() -> Self {
        Self {
            accept_jobs: true,
            max_concurrent_jobs: 4,
        }
    }
}

/// ComputeScheduler agent — coordinates job scheduling, execution, and verification.
pub struct ComputeSchedulerAgent {
    scheduler: Arc<Scheduler>,
    reputation: Arc<ReputationOracle>,
    sandbox: Arc<ComputeSandbox>,
    #[allow(dead_code)]
    config: ComputeSchedulerConfig,
    running: AtomicBool,
    event_tx: broadcast::Sender<ComputeEvent>,
}

impl ComputeSchedulerAgent {
    pub fn new(
        scheduler: Arc<Scheduler>,
        reputation: Arc<ReputationOracle>,
        config: ComputeSchedulerConfig,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            scheduler,
            reputation,
            sandbox: Arc::new(ComputeSandbox::new()),
            config,
            running: AtomicBool::new(false),
            event_tx,
        }
    }

    /// Start the agent background tasks.
    pub fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        info!("ComputeScheduler Agent started");
    }

    /// Stop the agent.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("ComputeScheduler Agent stopped");
    }

    /// Get a reference to the scheduler.
    pub fn scheduler(&self) -> &Arc<Scheduler> {
        &self.scheduler
    }

    /// Get a reference to the reputation oracle.
    pub fn reputation(&self) -> &Arc<ReputationOracle> {
        &self.reputation
    }

    /// Get a reference to the sandbox.
    pub fn sandbox(&self) -> &Arc<ComputeSandbox> {
        &self.sandbox
    }

    /// Subscribe to compute events.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<ComputeEvent> {
        self.event_tx.subscribe()
    }

    /// Register this node's compute capabilities.
    pub fn register_node(&self, cap: NodeCapability) {
        let addr = cap.node_address.clone();
        self.scheduler.register_capability(cap);
        let _ = self.event_tx.send(ComputeEvent::WorkerRegistered(addr));
    }

    /// Submit a new compute job.
    pub fn submit_job(&self, job: ComputeJob) -> Result<String, String> {
        let job_id = job.job_id.clone();
        self.scheduler.submit_job(job)?;
        let _ = self
            .event_tx
            .send(ComputeEvent::JobSubmitted(job_id.clone()));
        Ok(job_id)
    }

    /// Worker bids on a job.
    pub fn submit_bid(&self, bid: WorkerBid) -> Result<(), String> {
        self.scheduler.submit_bid(bid)
    }

    /// Assign workers to a job from collected bids.
    pub fn assign_workers(&self, job_id: &str) -> Result<Vec<String>, String> {
        let workers = self.scheduler.assign_workers(job_id)?;
        let _ = self.event_tx.send(ComputeEvent::JobAssigned(
            job_id.to_string(),
            workers.clone(),
        ));
        Ok(workers)
    }

    /// Execute a job locally in the sandbox (for this node as a worker).
    pub async fn execute_local(&self, job_id: &str) -> Result<WorkerResult, String> {
        let job = self
            .scheduler
            .get_job(job_id)
            .ok_or_else(|| format!("Job {} not found", job_id))?;

        let result = self
            .sandbox
            .execute(&job.task)
            .await
            .map_err(|e| e.to_string())?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(WorkerResult {
            worker: String::new(), // caller fills in
            output_file_id: None,
            output_data: Some(result.output),
            execution_time_ms: result.execution_time_ms,
            cpu_time_ms: result.execution_time_ms,
            peak_memory_mb: result.peak_memory_mb,
            result_hash: result.result_hash,
            submitted_at: now,
        })
    }

    /// Submit a worker result and trigger verification.
    pub fn submit_result(&self, job_id: &str, result: WorkerResult) -> Result<(), String> {
        let worker = result.worker.clone();
        let exec_time = result.execution_time_ms;
        self.scheduler.submit_result(job_id, result)?;

        // Update reputation based on job status
        if let Some(job) = self.scheduler.get_job(job_id) {
            match job.status {
                JobStatus::Completed => {
                    self.reputation.record_success(&worker, exec_time);
                    let _ = self
                        .event_tx
                        .send(ComputeEvent::JobCompleted(job_id.to_string()));
                }
                JobStatus::Disputed => {
                    self.reputation.record_dispute(&worker);
                    let _ = self
                        .event_tx
                        .send(ComputeEvent::JobDisputed(job_id.to_string()));
                }
                JobStatus::Failed(ref reason) => {
                    self.reputation.record_failure(&worker);
                    let _ = self
                        .event_tx
                        .send(ComputeEvent::JobFailed(job_id.to_string(), reason.clone()));
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Get marketplace statistics.
    pub fn marketplace_stats(&self) -> MarketplaceStats {
        self.scheduler.marketplace_stats()
    }

    /// Whether the agent is running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}
