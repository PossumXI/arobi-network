//! ToolExecutor Agent — sandboxed tool execution for Autonomo agents.
//!
//! Provides real-world capabilities: shell execution, file I/O,
//! web fetch, PDF/Excel processing, web search, code execution,
//! and per-agent knowledge storage via sled.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

/// Tool definition exposed via API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Result of a tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub task_id: String,
    pub tool_name: String,
    pub success: bool,
    pub result: serde_json::Value,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

/// Deny list of commands that must never execute.
const SHELL_DENY_LIST: &[&str] = &[
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "dd if=",
    "format",
    ":(){",
    "fork",
    "shutdown",
    "reboot",
    "halt",
    "passwd",
    "chmod 777",
    "net user",
    "reg delete",
];

/// Maximum output size from any tool: 1 MiB.
const MAX_OUTPUT_SIZE: usize = 1_048_576;

/// Maximum shell execution timeout: 30 seconds.
const MAX_SHELL_TIMEOUT_MS: u64 = 30_000;

const TOOL_POLICY_VENV_ONLY_ENV: &str = "AROBI_TOOL_VENV_ONLY";
const TOOL_POLICY_VENV_PATH_ENV: &str = "AROBI_TOOL_VENV_PATH";
const TOOL_POLICY_ALLOWED_ROOTS_ENV: &str = "AROBI_TOOL_ALLOWED_ROOTS";

/// Runtime policy for tool execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRuntimePolicy {
    pub venv_only: bool,
    pub venv_path: Option<String>,
    pub allowed_roots: Vec<String>,
}

/// ToolExecutor agent — manages tool execution for AI agents.
pub struct ToolExecutorAgent {
    /// sled database for knowledge storage.
    db: sled::Db,
    /// Active tasks being tracked.
    running_tasks: Arc<DashMap<String, ToolResult>>,
    /// Runtime execution policy.
    runtime_policy: ToolRuntimePolicy,
    /// Canonical allow-list of working directories.
    allowed_root_paths: Vec<PathBuf>,
    /// Canonical virtual environment root, when configured/detected.
    venv_root_path: Option<PathBuf>,
}

impl ToolExecutorAgent {
    pub fn new(db: sled::Db) -> Self {
        let (runtime_policy, allowed_root_paths, venv_root_path) = Self::load_runtime_policy();
        if runtime_policy.venv_only && venv_root_path.is_none() {
            warn!(
                "Tool executor policy requires virtualenv, but none was found. Set {TOOL_POLICY_VENV_PATH_ENV}."
            );
        }
        Self {
            db,
            running_tasks: Arc::new(DashMap::new()),
            runtime_policy,
            allowed_root_paths,
            venv_root_path,
        }
    }

    /// List all available tools.
    pub fn list_tools(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "shell_execute".into(),
                description: "Execute a shell command with timeout and working directory".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "Shell command to execute" },
                        "working_dir": { "type": "string", "description": "Working directory (optional)" },
                        "timeout_ms": { "type": "integer", "description": "Timeout in milliseconds (max 30000)" }
                    },
                    "required": ["command"]
                }),
            },
            ToolDefinition {
                name: "file_read".into(),
                description: "Read contents of a file".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path to read" },
                        "max_bytes": { "type": "integer", "description": "Maximum bytes to read" }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "file_write".into(),
                description: "Write content to a file".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "File path to write" },
                        "content": { "type": "string", "description": "Content to write" },
                        "append": { "type": "boolean", "description": "Append instead of overwrite" }
                    },
                    "required": ["path", "content"]
                }),
            },
            ToolDefinition {
                name: "web_fetch".into(),
                description: "Fetch content from a URL via HTTP GET or POST".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "description": "URL to fetch" },
                        "method": { "type": "string", "enum": ["GET", "POST"], "description": "HTTP method" },
                        "body": { "type": "string", "description": "Request body for POST" },
                        "headers": { "type": "object", "description": "Custom HTTP headers" },
                        "extract": { "type": "string", "enum": ["text", "json", "html_text"], "description": "Response extraction mode" }
                    },
                    "required": ["url"]
                }),
            },
            ToolDefinition {
                name: "web_search".into(),
                description: "Search the web via DuckDuckGo instant answer API".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "pdf_extract".into(),
                description: "Extract text content from a PDF file".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Path to PDF file" }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "csv_write".into(),
                description: "Generate a CSV file from structured data".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Output file path" },
                        "headers": { "type": "array", "items": { "type": "string" }, "description": "Column headers" },
                        "rows": { "type": "array", "items": { "type": "array" }, "description": "Data rows" }
                    },
                    "required": ["path", "headers", "rows"]
                }),
            },
            ToolDefinition {
                name: "code_execute".into(),
                description:
                    "Execute a code snippet (Python or JavaScript) in a sandboxed subprocess".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "language": { "type": "string", "enum": ["python", "javascript", "node"], "description": "Programming language" },
                        "code": { "type": "string", "description": "Code to execute" },
                        "timeout_ms": { "type": "integer", "description": "Timeout in milliseconds" }
                    },
                    "required": ["language", "code"]
                }),
            },
            ToolDefinition {
                name: "knowledge_store".into(),
                description: "Store a knowledge chunk in the agent's persistent knowledge base"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "key": { "type": "string", "description": "Knowledge key" },
                        "content": { "type": "string", "description": "Knowledge content" },
                        "metadata": { "type": "object", "description": "Optional metadata" }
                    },
                    "required": ["key", "content"]
                }),
            },
            ToolDefinition {
                name: "knowledge_query".into(),
                description: "Query the agent's knowledge base by key prefix or content search"
                    .into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Search query (matches key prefix or content substring)" }
                    },
                    "required": ["query"]
                }),
            },
        ]
    }

    pub fn runtime_policy_snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "venv_only": self.runtime_policy.venv_only,
            "venv_path": self.runtime_policy.venv_path,
            "allowed_roots": self.runtime_policy.allowed_roots,
            "controls": {
                "venv_env": TOOL_POLICY_VENV_PATH_ENV,
                "venv_only_env": TOOL_POLICY_VENV_ONLY_ENV,
                "allowed_roots_env": TOOL_POLICY_ALLOWED_ROOTS_ENV,
            }
        })
    }

    fn load_runtime_policy() -> (ToolRuntimePolicy, Vec<PathBuf>, Option<PathBuf>) {
        let venv_only = Self::read_env_bool(TOOL_POLICY_VENV_ONLY_ENV, true);
        let mut allowed_root_paths = Self::parse_allowed_roots_from_env();

        if let Ok(cwd) = std::env::current_dir() {
            if let Some(normalized) = Self::normalize_existing_path(cwd) {
                Self::push_unique_path(&mut allowed_root_paths, normalized);
            }
        }

        let configured_venv = std::env::var(TOOL_POLICY_VENV_PATH_ENV)
            .ok()
            .and_then(Self::normalize_existing_path);
        let detected_venv = if configured_venv.is_none() {
            Self::detect_venv_root()
        } else {
            None
        };
        let venv_root_path = configured_venv.or(detected_venv);

        let runtime_policy = ToolRuntimePolicy {
            venv_only,
            venv_path: venv_root_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            allowed_roots: allowed_root_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
        };

        (runtime_policy, allowed_root_paths, venv_root_path)
    }

    fn read_env_bool(name: &str, default_value: bool) -> bool {
        match std::env::var(name) {
            Ok(value) => matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ),
            Err(_) => default_value,
        }
    }

    fn parse_allowed_roots_from_env() -> Vec<PathBuf> {
        let mut roots = Vec::new();
        let raw = match std::env::var(TOOL_POLICY_ALLOWED_ROOTS_ENV) {
            Ok(v) => v,
            Err(_) => return roots,
        };

        for entry in raw
            .split(';')
            .flat_map(|segment| segment.split(','))
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            if let Some(path) = Self::normalize_existing_path(entry) {
                Self::push_unique_path(&mut roots, path);
            }
        }

        roots
    }

    fn detect_venv_root() -> Option<PathBuf> {
        if let Ok(current) = std::env::var("VIRTUAL_ENV") {
            if let Some(path) = Self::normalize_existing_path(current) {
                return Some(path);
            }
        }

        let cwd = std::env::current_dir().ok()?;
        for candidate in [cwd.join(".venv"), cwd.join("venv")] {
            if let Some(path) = Self::normalize_existing_path(candidate) {
                return Some(path);
            }
        }
        None
    }

    fn normalize_existing_path<P: AsRef<Path>>(input: P) -> Option<PathBuf> {
        let path = input.as_ref();
        if !path.exists() {
            return None;
        }
        path.canonicalize().ok()
    }

    fn push_unique_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
        let candidate_key = Self::path_key(&candidate);
        if !paths
            .iter()
            .any(|existing| Self::path_key(existing) == candidate_key)
        {
            paths.push(candidate);
        }
    }

    fn path_key(path: &Path) -> String {
        let normalized = path.to_string_lossy().replace('\\', "/");
        if cfg!(target_os = "windows") {
            normalized.to_ascii_lowercase()
        } else {
            normalized
        }
    }

    fn resolve_working_dir(&self, requested: Option<&str>) -> Result<PathBuf, String> {
        let base = match requested {
            Some(raw) if !raw.trim().is_empty() => PathBuf::from(raw),
            _ => self
                .allowed_root_paths
                .first()
                .cloned()
                .or_else(|| std::env::current_dir().ok())
                .ok_or("Unable to determine working directory")?,
        };

        let canonical = base
            .canonicalize()
            .map_err(|e| format!("Invalid working_dir '{}': {e}", base.display()))?;

        if !self.allowed_root_paths.is_empty()
            && !self
                .allowed_root_paths
                .iter()
                .any(|root| canonical.starts_with(root))
        {
            return Err(format!(
                "working_dir '{}' is outside allowed roots",
                canonical.display()
            ));
        }

        Ok(canonical)
    }

    fn resolve_venv_bin_dir(&self) -> Result<PathBuf, String> {
        let venv_root = self.venv_root_path.as_ref().ok_or_else(|| {
            format!(
                "Virtual environment is required by policy. Configure {TOOL_POLICY_VENV_PATH_ENV}."
            )
        })?;
        let bin_dir = if cfg!(target_os = "windows") {
            venv_root.join("Scripts")
        } else {
            venv_root.join("bin")
        };
        if !bin_dir.exists() {
            return Err(format!(
                "Virtual environment bin directory not found: {}",
                bin_dir.display()
            ));
        }
        Ok(bin_dir)
    }

    fn resolve_venv_python(&self) -> Result<PathBuf, String> {
        let bin_dir = self.resolve_venv_bin_dir()?;
        let candidates: Vec<PathBuf> = if cfg!(target_os = "windows") {
            vec![bin_dir.join("python.exe")]
        } else {
            vec![bin_dir.join("python"), bin_dir.join("python3")]
        };
        for candidate in candidates {
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(format!(
            "Python interpreter not found in virtual environment: {}",
            bin_dir.display()
        ))
    }

    fn python_program(&self) -> Result<OsString, String> {
        if self.runtime_policy.venv_only {
            return Ok(self.resolve_venv_python()?.into_os_string());
        }
        Ok(OsString::from("python"))
    }

    fn apply_runtime_env(&self, cmd: &mut tokio::process::Command) -> Result<(), String> {
        if !self.runtime_policy.venv_only {
            return Ok(());
        }

        let venv_root = self.venv_root_path.as_ref().ok_or_else(|| {
            format!(
                "Virtual environment is required by policy. Configure {TOOL_POLICY_VENV_PATH_ENV}."
            )
        })?;
        let bin_dir = self.resolve_venv_bin_dir()?;

        cmd.env("VIRTUAL_ENV", venv_root);
        let existing_path = std::env::var_os("PATH").unwrap_or_default();
        let mut segments = Vec::new();
        segments.push(bin_dir);
        segments.extend(std::env::split_paths(&existing_path));
        if let Ok(joined) = std::env::join_paths(segments) {
            cmd.env("PATH", joined);
        }

        Ok(())
    }

    /// Execute a tool by name with parameters.
    pub async fn execute(
        &self,
        tool_name: &str,
        parameters: serde_json::Value,
        agent_wallet: &str,
        timeout_ms: u64,
    ) -> serde_json::Value {
        let task_seed = format!(
            "{tool_name}:{agent_wallet}:{}",
            chrono::Utc::now().timestamp_millis()
        );
        let task_hash = blake3::hash(task_seed.as_bytes()).to_hex();
        let task_id = format!("task_{}", &task_hash[..16]);

        let start = std::time::Instant::now();

        let result = match tool_name {
            "shell_execute" => self.exec_shell(&parameters, timeout_ms).await,
            "file_read" => self.exec_file_read(&parameters).await,
            "file_write" => self.exec_file_write(&parameters).await,
            "web_fetch" => self.exec_web_fetch(&parameters, timeout_ms).await,
            "web_search" => self.exec_web_search(&parameters).await,
            "pdf_extract" => self.exec_pdf_extract(&parameters).await,
            "csv_write" => self.exec_csv_write(&parameters).await,
            "code_execute" => self.exec_code(&parameters, timeout_ms).await,
            "knowledge_store" => {
                let key = parameters.get("key").and_then(|v| v.as_str()).unwrap_or("");
                let content = parameters
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let metadata = parameters
                    .get("metadata")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                self.knowledge_store(agent_wallet, key, content, &metadata);
                Ok(serde_json::json!({ "stored": true, "key": key }))
            }
            "knowledge_query" => {
                let query = parameters
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let results = self.knowledge_query(agent_wallet, query);
                Ok(serde_json::json!({ "results": results }))
            }
            _ => Err(format!("Unknown tool: {tool_name}")),
        };

        let elapsed = start.elapsed().as_millis() as u64;
        let (success, result_val, error) = match result {
            Ok(val) => (true, val, None),
            Err(e) => (false, serde_json::Value::Null, Some(e)),
        };

        let tool_result = ToolResult {
            task_id: task_id.clone(),
            tool_name: tool_name.to_string(),
            success,
            result: result_val.clone(),
            execution_time_ms: elapsed,
            error: error.clone(),
        };
        self.running_tasks.insert(task_id.clone(), tool_result);

        info!("Tool {tool_name} executed in {elapsed}ms (success={success})");

        serde_json::json!({
            "task_id": task_id,
            "success": success,
            "result": result_val,
            "execution_time_ms": elapsed,
            "error": error,
        })
    }

    // ── Shell execution ─────────────────────────────────────────────────────

    async fn exec_shell(
        &self,
        params: &serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, String> {
        let command = params
            .get("command")
            .and_then(|v| v.as_str())
            .ok_or("command parameter required")?;
        let working_dir = params.get("working_dir").and_then(|v| v.as_str());
        let timeout = timeout_ms.min(MAX_SHELL_TIMEOUT_MS);
        let exec_dir = self.resolve_working_dir(working_dir)?;

        // Security: check deny list
        let cmd_lower = command.to_lowercase();
        for denied in SHELL_DENY_LIST {
            if cmd_lower.contains(denied) {
                return Err(format!(
                    "Command denied by security policy: contains '{denied}'"
                ));
            }
        }

        let mut cmd = if cfg!(target_os = "windows") {
            let mut c = tokio::process::Command::new("cmd");
            c.args(["/C", command]);
            c
        } else {
            let mut c = tokio::process::Command::new("sh");
            c.args(["-c", command]);
            c
        };

        cmd.current_dir(&exec_dir);
        self.apply_runtime_env(&mut cmd)?;

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn process: {e}"))?;

        let output = tokio::time::timeout(
            std::time::Duration::from_millis(timeout),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| format!("Command timed out after {timeout}ms"))?
        .map_err(|e| format!("Command execution failed: {e}"))?;

        let stdout =
            String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(MAX_OUTPUT_SIZE)])
                .to_string();
        let stderr =
            String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(MAX_OUTPUT_SIZE)])
                .to_string();

        Ok(serde_json::json!({
            "exit_code": output.status.code(),
            "stdout": stdout,
            "stderr": stderr,
            "working_dir": exec_dir.to_string_lossy(),
            "venv_enforced": self.runtime_policy.venv_only,
        }))
    }

    // ── File operations ─────────────────────────────────────────────────────

    async fn exec_file_read(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("path parameter required")?;
        let max_bytes = params
            .get("max_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(MAX_OUTPUT_SIZE as u64) as usize;

        let data = tokio::fs::read(path)
            .await
            .map_err(|e| format!("Failed to read file: {e}"))?;

        let content = String::from_utf8_lossy(&data[..data.len().min(max_bytes)]).to_string();
        Ok(serde_json::json!({
            "path": path,
            "size": data.len(),
            "content": content,
            "truncated": data.len() > max_bytes,
        }))
    }

    async fn exec_file_write(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("path parameter required")?;
        let content = params
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or("content parameter required")?;
        let append = params
            .get("append")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if append {
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .await
                .map_err(|e| format!("Failed to open file: {e}"))?;
            file.write_all(content.as_bytes())
                .await
                .map_err(|e| format!("Failed to write file: {e}"))?;
        } else {
            tokio::fs::write(path, content)
                .await
                .map_err(|e| format!("Failed to write file: {e}"))?;
        }

        Ok(serde_json::json!({
            "path": path,
            "bytes_written": content.len(),
            "append": append,
        }))
    }

    // ── Web operations ──────────────────────────────────────────────────────

    async fn exec_web_fetch(
        &self,
        params: &serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, String> {
        let url = params
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or("url parameter required")?;
        let method = params
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        let extract = params
            .get("extract")
            .and_then(|v| v.as_str())
            .unwrap_or("text");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms.min(30_000)))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

        let response = match method.to_uppercase().as_str() {
            "POST" => {
                let body = params.get("body").and_then(|v| v.as_str()).unwrap_or("");
                client
                    .post(url)
                    .header("Content-Type", "application/json")
                    .body(body.to_string())
                    .send()
                    .await
            }
            _ => client.get(url).send().await,
        }
        .map_err(|e| format!("HTTP request failed: {e}"))?;

        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response body: {e}"))?;

        let content = match extract {
            "json" => match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(v) => v,
                Err(_) => serde_json::json!(body),
            },
            "html_text" => {
                // Strip HTML tags (simple regex-free approach)
                let text = body
                    .split('<')
                    .filter_map(|s| s.split_once('>').map(|(_, text)| text))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                serde_json::json!(text[..text.len().min(MAX_OUTPUT_SIZE)])
            }
            _ => serde_json::json!(body[..body.len().min(MAX_OUTPUT_SIZE)]),
        };

        Ok(serde_json::json!({
            "url": url,
            "status": status,
            "content": content,
        }))
    }

    async fn exec_web_search(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let query = params
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or("query parameter required")?;

        // DuckDuckGo instant answer API (no key needed)
        let url = format!(
            "https://api.duckduckgo.com/?q={}&format=json&no_html=1&skip_disambig=1",
            urlencoding::encode(query)
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("HTTP client error: {e}"))?;

        let resp = client
            .get(&url)
            .header("User-Agent", "ArobiNetwork/1.0")
            .send()
            .await
            .map_err(|e| format!("Search request failed: {e}"))?;

        let body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read search response: {e}"))?;

        let json: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or(serde_json::json!({"AbstractText": "", "RelatedTopics": []}));

        let abstract_text = json
            .get("AbstractText")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let abstract_source = json
            .get("AbstractSource")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let abstract_url = json
            .get("AbstractURL")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let related: Vec<serde_json::Value> = json
            .get("RelatedTopics")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .take(5)
                    .filter_map(|item| {
                        let text = item.get("Text")?.as_str()?;
                        let url = item.get("FirstURL")?.as_str()?;
                        Some(serde_json::json!({ "text": text, "url": url }))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(serde_json::json!({
            "query": query,
            "abstract": abstract_text,
            "source": abstract_source,
            "url": abstract_url,
            "related": related,
        }))
    }

    // ── Document processing ─────────────────────────────────────────────────

    async fn exec_pdf_extract(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("path parameter required")?;

        // Use external tool (pdftotext) if available, otherwise read raw bytes
        let mut cmd = if cfg!(target_os = "windows") {
            let mut c = tokio::process::Command::new("cmd");
            c.args(["/C", &format!("type \"{}\"", path)]);
            c
        } else {
            let mut c = tokio::process::Command::new("pdftotext");
            c.args([path, "-"]);
            c
        };

        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        match tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output()).await {
            Ok(Ok(output)) => {
                let text = String::from_utf8_lossy(&output.stdout).to_string();
                Ok(serde_json::json!({
                    "path": path,
                    "text": text[..text.len().min(MAX_OUTPUT_SIZE)],
                    "bytes": output.stdout.len(),
                }))
            }
            Ok(Err(e)) => Err(format!("PDF extraction failed: {e}")),
            Err(_) => Err("PDF extraction timed out".to_string()),
        }
    }

    async fn exec_csv_write(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("path parameter required")?;
        let headers = params
            .get("headers")
            .and_then(|v| v.as_array())
            .ok_or("headers parameter required")?;
        let rows = params
            .get("rows")
            .and_then(|v| v.as_array())
            .ok_or("rows parameter required")?;

        let mut csv_content = String::new();

        // Write headers
        let header_line: Vec<String> = headers
            .iter()
            .filter_map(|v| v.as_str().map(escape_csv))
            .collect();
        csv_content.push_str(&header_line.join(","));
        csv_content.push('\n');

        // Write rows
        for row in rows {
            if let Some(cells) = row.as_array() {
                let row_line: Vec<String> = cells
                    .iter()
                    .map(|v| match v {
                        serde_json::Value::String(s) => escape_csv(s),
                        other => escape_csv(&other.to_string()),
                    })
                    .collect();
                csv_content.push_str(&row_line.join(","));
                csv_content.push('\n');
            }
        }

        tokio::fs::write(path, &csv_content)
            .await
            .map_err(|e| format!("Failed to write CSV: {e}"))?;

        Ok(serde_json::json!({
            "path": path,
            "rows_written": rows.len(),
            "columns": headers.len(),
            "bytes": csv_content.len(),
        }))
    }

    // ── Code execution ──────────────────────────────────────────────────────

    async fn exec_code(
        &self,
        params: &serde_json::Value,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, String> {
        let language = params
            .get("language")
            .and_then(|v| v.as_str())
            .ok_or("language parameter required")?;
        let code = params
            .get("code")
            .and_then(|v| v.as_str())
            .ok_or("code parameter required")?;
        let working_dir = params.get("working_dir").and_then(|v| v.as_str());
        let timeout = timeout_ms.min(MAX_SHELL_TIMEOUT_MS);
        let exec_dir = self.resolve_working_dir(working_dir)?;

        // Write code to temp file and execute
        let (program, ext): (OsString, &str) = match language {
            "python" => (self.python_program()?, "py"),
            "javascript" | "node" => (OsString::from("node"), "js"),
            _ => return Err(format!("Unsupported language: {language}")),
        };

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!(
            "arobi_exec_{}.{ext}",
            chrono::Utc::now().timestamp_millis()
        ));

        tokio::fs::write(&temp_file, code)
            .await
            .map_err(|e| format!("Failed to write temp file: {e}"))?;

        let mut cmd = tokio::process::Command::new(program);
        cmd.arg(temp_file.to_str().unwrap_or(""));
        cmd.current_dir(&exec_dir);
        self.apply_runtime_env(&mut cmd)?;
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(timeout), cmd.output()).await;

        // Clean up temp file
        let _ = tokio::fs::remove_file(&temp_file).await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(
                    &output.stdout[..output.stdout.len().min(MAX_OUTPUT_SIZE)],
                )
                .to_string();
                let stderr = String::from_utf8_lossy(
                    &output.stderr[..output.stderr.len().min(MAX_OUTPUT_SIZE)],
                )
                .to_string();
                Ok(serde_json::json!({
                    "language": language,
                    "exit_code": output.status.code(),
                    "stdout": stdout,
                    "stderr": stderr,
                    "working_dir": exec_dir.to_string_lossy(),
                    "venv_enforced": self.runtime_policy.venv_only,
                }))
            }
            Ok(Err(e)) => Err(format!("Code execution failed: {e}")),
            Err(_) => Err(format!("Code execution timed out after {timeout}ms")),
        }
    }

    // ── Knowledge base (per-agent sled trees) ───────────────────────────────

    /// Store a knowledge chunk in the agent's namespaced sled tree.
    pub fn knowledge_store(
        &self,
        wallet: &str,
        key: &str,
        content: &str,
        metadata: &serde_json::Value,
    ) {
        let tree_name = format!("agent_kb_{wallet}");
        match self.db.open_tree(&tree_name) {
            Ok(tree) => {
                let entry = serde_json::json!({
                    "key": key,
                    "content": content,
                    "metadata": metadata,
                    "stored_at": chrono::Utc::now().to_rfc3339(),
                });
                if let Ok(json) = serde_json::to_vec(&entry) {
                    let _ = tree.insert(key.as_bytes(), json);
                    info!(
                        "Knowledge stored for {}: key={key}",
                        &wallet[..12.min(wallet.len())]
                    );
                }
            }
            Err(e) => warn!("Failed to open knowledge tree for {wallet}: {e}"),
        }
    }

    /// Query knowledge base by key prefix or content substring.
    pub fn knowledge_query(&self, wallet: &str, query: &str) -> Vec<serde_json::Value> {
        let tree_name = format!("agent_kb_{wallet}");
        let tree = match self.db.open_tree(&tree_name) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        // First try prefix scan
        for entry in tree.scan_prefix(query.as_bytes()) {
            if let Ok((_, val)) = entry {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&val) {
                    results.push(json);
                }
            }
            if results.len() >= 20 {
                break;
            }
        }

        // If prefix scan found nothing, do content search
        if results.is_empty() {
            for entry in tree.iter() {
                if let Ok((_, val)) = entry {
                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&val) {
                        let content = json.get("content").and_then(|v| v.as_str()).unwrap_or("");
                        let key = json.get("key").and_then(|v| v.as_str()).unwrap_or("");
                        if content.to_lowercase().contains(&query_lower)
                            || key.to_lowercase().contains(&query_lower)
                        {
                            results.push(json);
                        }
                    }
                }
                if results.len() >= 20 {
                    break;
                }
            }
        }

        results
    }

    /// Shut down the tool executor.
    pub fn shutdown(&self) {
        info!("ToolExecutor Agent stopped");
    }
}

/// Escape a CSV field (wrap in quotes if contains comma, quote, or newline).
fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
