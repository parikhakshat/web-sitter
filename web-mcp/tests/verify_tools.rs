//! Integration tests for `verify_edge`/`explain_path`/`taint_path`: spawn the real binary
//! against small fixture repos and assert on the actual `tools/call` JSON-RPC responses.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// a_fn -> b_fn -> c_fn, a three-level chain across three files.
fn write_callgraph_fixture(dir: &Path) {
    std::fs::write(dir.join("c.cpp"), "int c_fn() { return 1; }\n").unwrap();
    std::fs::write(
        dir.join("b.cpp"),
        "int c_fn();\nint b_fn() { return c_fn(); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("a.cpp"),
        "int b_fn();\nint a_fn() { return b_fn(); }\n",
    )
    .unwrap();
}

fn write_dataflow_fixture(dir: &Path) {
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
                    "clientInfo": { "name": "verify-tools-test", "version": "0.0.0" }
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
async fn verify_edge_calls_true_for_a_direct_call() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_callgraph_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "verify_edge",
            json!({ "kind": "calls", "from": "b_fn", "to": "c_fn" }),
        )
        .await?;
    assert_eq!(result["exists"], true, "{result:#}");
    assert_eq!(result["witness"], json!(["cpp:b_fn", "cpp:c_fn"]));

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn verify_edge_calls_false_for_a_transitive_only_relationship() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_callgraph_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "verify_edge",
            json!({ "kind": "calls", "from": "a_fn", "to": "c_fn" }),
        )
        .await?;
    assert_eq!(
        result["exists"], false,
        "a_fn does not directly call c_fn: {result:#}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn verify_edge_reaches_true_for_a_transitive_relationship() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_callgraph_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "verify_edge",
            json!({ "kind": "reaches", "from": "a_fn", "to": "c_fn" }),
        )
        .await?;
    assert_eq!(result["exists"], true, "{result:#}");
    assert_eq!(
        result["witness"],
        json!(["cpp:a_fn", "cpp:b_fn", "cpp:c_fn"])
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn verify_edge_rejects_unsupported_kind() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_callgraph_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "verify_edge",
            json!({ "kind": "dominates", "from": "a_fn", "to": "c_fn" }),
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
async fn explain_path_returns_hops_with_locations() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_callgraph_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "explain_path",
            json!({ "kind": "reaches", "from": "a_fn", "to": "c_fn" }),
        )
        .await?;
    let hops = result["hops"].as_array().expect("hops array");
    assert_eq!(hops.len(), 3, "{hops:#?}");
    assert_eq!(hops[0]["symbol_id"], "cpp:a_fn");
    assert_eq!(hops[1]["symbol_id"], "cpp:b_fn");
    assert_eq!(hops[2]["symbol_id"], "cpp:c_fn");
    for hop in hops {
        assert!(hop["file"].as_str().unwrap().ends_with(".cpp"));
        assert!(hop["line"].as_u64().unwrap() > 0);
    }

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn explain_path_errors_when_no_path_exists() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_callgraph_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "explain_path",
            json!({ "kind": "reaches", "from": "c_fn", "to": "a_fn" }),
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
async fn taint_path_returns_the_edge_chain_for_param_to_return_flow() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_dataflow_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "taint_path",
            json!({
                "from": { "file": "flow.cpp", "line": 1, "column": 15 },
                "to": { "file": "flow.cpp", "line": 1, "column": 27 }
            }),
        )
        .await?;
    assert_eq!(result["reaches"], true, "{result:#}");
    let edges = result["edges"].as_array().expect("edges array");
    assert!(!edges.is_empty(), "{edges:#?}");
    assert_eq!(edges[0]["variable"], "y");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn taint_path_false_for_unrelated_positions() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_dataflow_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "taint_path",
            json!({
                "from": { "file": "flow.cpp", "line": 1, "column": 15 },
                "to": { "file": "flow.cpp", "line": 2, "column": 25 }
            }),
        )
        .await?;
    assert_eq!(result["reaches"], false, "{result:#}");
    assert!(result["edges"].as_array().unwrap().is_empty());

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
