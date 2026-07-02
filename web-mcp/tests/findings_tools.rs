//! Integration tests for `verify_finding_status`/`record_finding_status`, and
//! `run_security_scan`'s wiring into the findings store: spawn the real binary, run a scan
//! to populate a finding, then drive the durable-status tools against the real MCP
//! protocol. Phase 1/2's tool handlers still read from a batch-built, never-mutated
//! `Workspace` (see `crate::index`), so these tests can't exercise the "underlying
//! vulnerability actually got fixed on disk" lifecycle end to end yet — that's covered at
//! the store level by `store::findings`'s own unit tests instead; what's tested here is
//! the real wiring: finding ids are stable across repeated scans, and status set via
//! `record_finding_status` survives being seen again by a later scan.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

const SYSTEM_CALL_RULE: &str = r#"
rule "test-system-call" {
    severity: critical
    languages: [c, cpp]
    message: "call to system()"
    tags: ["test"]
    find n: Call where n.callee_name() in ["system"]
}
"#;

fn write_fixture(dir: &Path) {
    std::fs::write(
        dir.join("vulnerable.cpp"),
        "void run(const char* cmd) { system(cmd); }\n",
    )
    .unwrap();
}

struct TestServer {
    child: Child,
    writer: tokio::process::ChildStdin,
    reader: BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}

impl TestServer {
    async fn spawn(root: &Path) -> anyhow::Result<Self> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_web-mcp"))
            .arg("--root")
            .arg(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let writer = child.stdin.take().expect("child stdin");
        let reader = BufReader::new(child.stdout.take().expect("child stdout"));
        let mut server = Self {
            child,
            writer,
            reader,
            next_id: 1,
        };

        server
            .send(&json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "findings-tools-test", "version": "0.0.0" }
                }
            }))
            .await?;
        server.read_response_for_id(0).await?;
        server
            .send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await?;
        Ok(server)
    }

    async fn call_tool(&mut self, name: &str, arguments: Value) -> anyhow::Result<Value> {
        let result = self.call_tool_raw(name, arguments).await?;
        assert_ne!(
            result.get("isError").and_then(Value::as_bool),
            Some(true),
            "tools/call({name}) returned an error result: {result:#}"
        );
        let text = content_text(&result)
            .unwrap_or_else(|| panic!("tools/call({name}) had no text content block: {result:#}"));
        Ok(serde_json::from_str(&text)?)
    }

    async fn call_tool_raw(&mut self, name: &str, arguments: Value) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }))
        .await?;
        let response = self.read_response_for_id(id).await?;
        Ok(response
            .get("result")
            .unwrap_or_else(|| panic!("tools/call({name}) had no result: {response:#}"))
            .clone())
    }

    async fn send(&mut self, message: &Value) -> anyhow::Result<()> {
        send_json(&mut self.writer, message).await
    }

    async fn read_response_for_id(&mut self, expected_id: u64) -> anyhow::Result<Value> {
        read_response_for_id(&mut self.reader, expected_id).await
    }

    async fn shutdown(mut self) {
        drop(self.writer);
        let _ = tokio::time::timeout(Duration::from_secs(2), self.child.wait()).await;
        if self.child.id().is_some() {
            let _ = self.child.kill().await;
        }
    }
}

async fn scan_and_get_one_finding(server: &mut TestServer) -> Value {
    let result = server
        .call_tool(
            "run_security_scan",
            json!({
                "scope": "workspace",
                "rule_source": SYSTEM_CALL_RULE
            }),
        )
        .await
        .unwrap();
    let findings = result["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{findings:#?}");
    findings[0].clone()
}

#[tokio::test]
async fn a_scan_reports_the_finding_as_open_with_a_stable_finding_id() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let first = scan_and_get_one_finding(&mut server).await;
    assert_eq!(first["status"], "open");
    let finding_id = first["finding_id"].as_str().unwrap().to_string();
    assert!(!finding_id.is_empty());

    let second = scan_and_get_one_finding(&mut server).await;
    assert_eq!(
        second["finding_id"], finding_id,
        "the same underlying finding must fingerprint identically across scans"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn verify_finding_status_reflects_what_the_scan_recorded() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let finding = scan_and_get_one_finding(&mut server).await;
    let finding_id = finding["finding_id"].as_str().unwrap();

    let status = server
        .call_tool("verify_finding_status", json!({ "finding_id": finding_id }))
        .await?;
    assert_eq!(status["status"], "open");
    assert_eq!(status["first_seen_revision"], 1);
    assert_eq!(status["rule_id"], "test-system-call");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn suppressing_a_finding_survives_being_seen_again_by_a_later_scan() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let finding = scan_and_get_one_finding(&mut server).await;
    let finding_id = finding["finding_id"].as_str().unwrap().to_string();

    let recorded = server
        .call_tool(
            "record_finding_status",
            json!({ "finding_id": finding_id, "status": "suppressed" }),
        )
        .await?;
    assert_eq!(recorded["status"], "suppressed");

    // Re-scan: the same finding must still surface (it's still structurally present) but
    // stay suppressed rather than being reset back to open.
    let rescanned = scan_and_get_one_finding(&mut server).await;
    assert_eq!(rescanned["finding_id"], finding_id);
    assert_eq!(rescanned["status"], "suppressed");

    let status = server
        .call_tool("verify_finding_status", json!({ "finding_id": finding_id }))
        .await?;
    assert_eq!(status["status"], "suppressed");
    assert_eq!(
        status["last_seen_revision"], 2,
        "last_seen_revision must advance even while suppressed"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn verify_finding_status_errors_for_an_unknown_id() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "verify_finding_status",
            json!({ "finding_id": "never-seen" }),
        )
        .await?;
    assert_eq!(result.get("isError").and_then(Value::as_bool), Some(true));

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn record_finding_status_errors_for_an_unsupported_status_value() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let finding = scan_and_get_one_finding(&mut server).await;
    let finding_id = finding["finding_id"].as_str().unwrap().to_string();

    let result = server
        .call_tool_raw(
            "record_finding_status",
            json!({ "finding_id": finding_id, "status": "bogus" }),
        )
        .await?;
    assert_eq!(result.get("isError").and_then(Value::as_bool), Some(true));

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn record_finding_status_errors_for_a_finding_never_seen_by_a_scan() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "record_finding_status",
            json!({ "finding_id": "never-seen", "status": "fixed" }),
        )
        .await?;
    assert_eq!(result.get("isError").and_then(Value::as_bool), Some(true));

    server.shutdown().await;
    Ok(())
}

fn content_text(result: &Value) -> Option<String> {
    result
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|block| block.get("text"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

async fn send_json<W>(writer: &mut W, message: &Value) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let serialized = serde_json::to_string(message)?;
    writer.write_all(serialized.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn read_response_for_id<R>(
    reader: &mut BufReader<R>,
    expected_id: u64,
) -> anyhow::Result<Value>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + READ_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("timed out waiting for response id {expected_id}");
        }
        let mut line = String::new();
        let read = tokio::time::timeout(remaining, reader.read_line(&mut line)).await??;
        if read == 0 {
            anyhow::bail!("child closed stdout before responding to id {expected_id}");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        if value.get("id").and_then(Value::as_u64) == Some(expected_id) {
            return Ok(value);
        }
    }
}
