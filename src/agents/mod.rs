//! AI Agents Module
//!
//! Autonomous agents for transaction validation, anomaly detection,
//! and threat intelligence gathering on the Arobi Network.

#[allow(dead_code)]
pub mod compute_scheduler;
#[cfg(feature = "firecrawler")]
pub mod firecrawler;
#[allow(dead_code)]
pub mod inference_router;
pub mod records_keeper;
#[allow(dead_code)]
pub mod reputation_oracle;
#[allow(dead_code)]
pub mod storage_keeper;
#[allow(dead_code)]
pub mod tool_executor;
#[allow(dead_code)]
pub mod training_coordinator;

pub use compute_scheduler::ComputeSchedulerAgent;
#[cfg(feature = "firecrawler")]
pub use firecrawler::FirecrawlerAgent;
pub use inference_router::InferenceRouterAgent;
pub use records_keeper::{RecordsKeeperAgent, RecordsKeeperConfig};
pub use reputation_oracle::ReputationOracleAgent;
pub use storage_keeper::StorageKeeperAgent;
pub use tool_executor::ToolExecutorAgent;
pub use training_coordinator::TrainingCoordinatorAgent;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

use crate::mempool::Mempool;
use crate::store::Store;

// ---------------------------------------------------------------------------
// Agent events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum AgentEvent {
    AgentStarted(String),
    AgentStopped(String),
    AgentError(String, String),
}

// ---------------------------------------------------------------------------
// Agent Manager
// ---------------------------------------------------------------------------

/// Coordinates all AI agents on the node.
pub struct AgentManager {
    records_keeper: Option<Arc<RecordsKeeperAgent>>,
    storage_keeper: Option<Arc<StorageKeeperAgent>>,
    compute_scheduler: Option<Arc<ComputeSchedulerAgent>>,
    reputation_oracle: Option<Arc<ReputationOracleAgent>>,
    inference_router: Option<Arc<InferenceRouterAgent>>,
    training_coordinator: Option<Arc<TrainingCoordinatorAgent>>,
    tool_executor: Option<Arc<ToolExecutorAgent>>,
    #[cfg(feature = "firecrawler")]
    firecrawler: Option<Arc<FirecrawlerAgent>>,
    event_tx: broadcast::Sender<AgentEvent>,
}

impl AgentManager {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            records_keeper: None,
            storage_keeper: None,
            compute_scheduler: None,
            reputation_oracle: None,
            inference_router: None,
            training_coordinator: None,
            tool_executor: None,
            #[cfg(feature = "firecrawler")]
            firecrawler: None,
            event_tx,
        }
    }

    /// Initialize and start all agents.
    pub async fn initialize(&mut self, store: Arc<Store>, _mempool: Arc<Mempool>) -> Result<()> {
        // Records Keeper Agent
        let rk = RecordsKeeperAgent::new(store.clone(), RecordsKeeperConfig::default());
        rk.start();
        self.records_keeper = Some(Arc::new(rk));
        let _ = self
            .event_tx
            .send(AgentEvent::AgentStarted("RecordsKeeper".into()));
        info!("Records Keeper Agent started");

        // Firecrawler Agent
        #[cfg(feature = "firecrawler")]
        {
            let fc = FirecrawlerAgent::new();
            fc.start();
            self.firecrawler = Some(Arc::new(fc));
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStarted("Firecrawler".into()));
            info!("Firecrawler Agent started");
        }

        info!("Agent Manager initialized — all agents active");
        Ok(())
    }

    /// Initialize and start the StorageKeeper agent (called separately since it
    /// requires additional ArobiFS components).
    pub fn initialize_storage_keeper(&mut self, agent: StorageKeeperAgent) {
        agent.start();
        self.storage_keeper = Some(Arc::new(agent));
        let _ = self
            .event_tx
            .send(AgentEvent::AgentStarted("StorageKeeper".into()));
        info!("StorageKeeper Agent registered with AgentManager");
    }

    /// Initialize and start the ComputeScheduler agent.
    pub fn initialize_compute_scheduler(&mut self, agent: ComputeSchedulerAgent) {
        agent.start();
        self.compute_scheduler = Some(Arc::new(agent));
        let _ = self
            .event_tx
            .send(AgentEvent::AgentStarted("ComputeScheduler".into()));
        info!("ComputeScheduler Agent registered with AgentManager");
    }

    /// Initialize and start the ReputationOracle agent.
    pub fn initialize_reputation_oracle(&mut self, agent: ReputationOracleAgent) {
        agent.start();
        self.reputation_oracle = Some(Arc::new(agent));
        let _ = self
            .event_tx
            .send(AgentEvent::AgentStarted("ReputationOracle".into()));
        info!("ReputationOracle Agent registered with AgentManager");
    }

    /// Initialize and start the InferenceRouter agent.
    pub fn initialize_inference_router(&mut self, agent: Arc<InferenceRouterAgent>) {
        agent.start();
        self.inference_router = Some(agent);
        let _ = self
            .event_tx
            .send(AgentEvent::AgentStarted("InferenceRouter".into()));
        info!("InferenceRouter Agent registered with AgentManager");
    }

    /// Initialize and start the TrainingCoordinator agent.
    pub fn initialize_training_coordinator(&mut self, agent: Arc<TrainingCoordinatorAgent>) {
        agent.start();
        self.training_coordinator = Some(agent);
        let _ = self
            .event_tx
            .send(AgentEvent::AgentStarted("TrainingCoordinator".into()));
        info!("TrainingCoordinator Agent registered with AgentManager");
    }

    /// Initialize the ToolExecutor agent.
    pub fn initialize_tool_executor(&mut self, agent: Arc<ToolExecutorAgent>) {
        self.tool_executor = Some(agent);
        let _ = self
            .event_tx
            .send(AgentEvent::AgentStarted("ToolExecutor".into()));
        info!("ToolExecutor Agent registered with AgentManager");
    }

    #[allow(dead_code)]
    pub fn get_records_keeper(&self) -> Option<&Arc<RecordsKeeperAgent>> {
        self.records_keeper.as_ref()
    }

    #[allow(dead_code)]
    pub fn get_storage_keeper(&self) -> Option<&Arc<StorageKeeperAgent>> {
        self.storage_keeper.as_ref()
    }

    #[allow(dead_code)]
    pub fn get_compute_scheduler(&self) -> Option<&Arc<ComputeSchedulerAgent>> {
        self.compute_scheduler.as_ref()
    }

    #[allow(dead_code)]
    pub fn get_reputation_oracle(&self) -> Option<&Arc<ReputationOracleAgent>> {
        self.reputation_oracle.as_ref()
    }

    #[allow(dead_code)]
    pub fn get_inference_router(&self) -> Option<&Arc<InferenceRouterAgent>> {
        self.inference_router.as_ref()
    }

    #[cfg(feature = "firecrawler")]
    #[allow(dead_code)]
    pub fn get_firecrawler(&self) -> Option<&Arc<FirecrawlerAgent>> {
        self.firecrawler.as_ref()
    }

    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.event_tx.subscribe()
    }

    #[allow(dead_code)]
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(rk) = &self.records_keeper {
            rk.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("RecordsKeeper".into()));
        }

        if let Some(sk) = &self.storage_keeper {
            sk.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("StorageKeeper".into()));
        }

        if let Some(cs) = &self.compute_scheduler {
            cs.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("ComputeScheduler".into()));
        }

        if let Some(ro) = &self.reputation_oracle {
            ro.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("ReputationOracle".into()));
        }

        if let Some(ir) = &self.inference_router {
            ir.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("InferenceRouter".into()));
        }

        if let Some(tc) = &self.training_coordinator {
            tc.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("TrainingCoordinator".into()));
        }

        if let Some(te) = &self.tool_executor {
            te.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("ToolExecutor".into()));
        }

        #[cfg(feature = "firecrawler")]
        if let Some(fc) = &self.firecrawler {
            fc.shutdown();
            let _ = self
                .event_tx
                .send(AgentEvent::AgentStopped("Firecrawler".into()));
        }

        info!("Agent Manager shutdown complete");
        Ok(())
    }
}
