//! Integration tests for `dfg_reaches`/`query`: spawn the real binary against a small
//! fixture repo, drive it over real stdio pipes, and assert on the actual `tools/call`
//! JSON-RPC responses — hand-verified expected answers.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// `helper` has a direct param-to-return dataflow edge (`y` at line 1 col 27 flows to
/// the return expression at line 1 col 34); `unrelated` shares no dataflow with it.
fn write_fixture(dir: &Path) {
    std::fs::write(
        dir.join("flow.cpp"),
        "int helper(int y) { return y; }\nint unrelated() { return 5; }\n",
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
                    "clientInfo": { "name": "dataflow-tools-test", "version": "0.0.0" }
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

#[tokio::test]
async fn dfg_reaches_true_for_param_to_return_flow() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    // `y` (the parameter identifier) at line 1, column 15 (0-based) flows to the
    // returned identifier `y` at line 1, column 27.
    let result = server
        .call_tool(
            "dfg_reaches",
            json!({
                "from": { "file": "flow.cpp", "line": 1, "column": 15 },
                "to": { "file": "flow.cpp", "line": 1, "column": 27 }
            }),
        )
        .await?;
    assert_eq!(result["reaches"], true, "{result:#}");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dfg_reaches_false_for_unrelated_positions() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    // The literal `5` in `unrelated()` (line 2, column 25) is a real AST/DFG node in the
    // same file, but has no dataflow relationship to `helper`'s param `y`.
    let result = server
        .call_tool(
            "dfg_reaches",
            json!({
                "from": { "file": "flow.cpp", "line": 1, "column": 15 },
                "to": { "file": "flow.cpp", "line": 2, "column": 25 }
            }),
        )
        .await?;
    assert_eq!(result["reaches"], false, "{result:#}");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dfg_reaches_rejects_cross_file_queries() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "dfg_reaches",
            json!({
                "from": { "file": "flow.cpp", "line": 1, "column": 15 },
                "to": { "file": "other.cpp", "line": 1, "column": 0 }
            }),
        )
        .await?;
    assert_eq!(
        result.get("isError").and_then(Value::as_bool),
        Some(true),
        "{result:#?}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn query_runs_an_adhoc_rule_and_returns_findings() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "query",
            json!({
                "rule_source": "rule \"any-fn\" { severity: info find n: MethodDef }"
            }),
        )
        .await?;
    let findings = result["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert!(findings.iter().all(|f| f["rule_id"] == "any-fn"));

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn query_reports_compile_error_for_invalid_rule_source() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "query",
            json!({ "rule_source": "not a valid rule at all {{{" }),
        )
        .await?;
    assert_eq!(
        result.get("isError").and_then(Value::as_bool),
        Some(true),
        "{result:#?}"
    );

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
