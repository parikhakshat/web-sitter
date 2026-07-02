//! Integration tests for `find_definition`/`find_references`/`symbol_summary`: spawn the
//! real binary against a small fixture repo, drive it over real stdio pipes, and assert
//! on the actual `tools/call` JSON-RPC responses — hand-verified expected answers, per
//! the Phase 1 test plan in `docs/mcp-server-design.md`.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A small fixture repo with one cross-file call and one intra-file (recursive) call,
/// covering both reference-resolution paths `find_references` has to handle.
fn write_fixture(dir: &Path) {
    std::fs::write(dir.join("callee.cpp"), "int helper(int y) { return y; }\n").unwrap();
    std::fs::write(
        dir.join("caller.cpp"),
        "int caller(int x) { return helper(x); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("recursive.cpp"),
        "int fact(int n) { if (n <= 1) return 1; return n * fact(n - 1); }\n",
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
                    "clientInfo": { "name": "lookup-tools-test", "version": "0.0.0" }
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

    /// Like `call_tool`, but doesn't assert success — for tests exercising the
    /// `CallToolResult::error(...)` path (an unresolvable symbol, for instance).
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
async fn find_definition_locates_a_known_function() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool("find_definition", json!({ "symbol": "helper" }))
        .await?;
    let definitions = result["definitions"].as_array().expect("definitions array");
    assert_eq!(definitions.len(), 1, "{definitions:#?}");
    assert_eq!(definitions[0]["line"], 1);
    assert!(
        definitions[0]["file"]
            .as_str()
            .unwrap()
            .ends_with("callee.cpp")
    );
    assert_eq!(definitions[0]["symbol_id"], "cpp:helper");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn find_definition_returns_empty_for_unknown_symbol() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool("find_definition", json!({ "symbol": "does_not_exist" }))
        .await?;
    assert_eq!(result["definitions"].as_array().unwrap().len(), 0);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn find_references_finds_the_cross_file_call_site() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool("find_references", json!({ "symbol": "helper" }))
        .await?;
    assert_eq!(result["symbol_id"], "cpp:helper");
    let references = result["references"].as_array().expect("references array");
    assert_eq!(references.len(), 1, "{references:#?}");
    assert!(
        references[0]["file"]
            .as_str()
            .unwrap()
            .ends_with("caller.cpp")
    );
    assert_eq!(references[0]["line"], 1);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn find_references_finds_the_intra_file_recursive_call() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool("find_references", json!({ "symbol": "fact" }))
        .await?;
    let references = result["references"].as_array().expect("references array");
    assert_eq!(references.len(), 1, "{references:#?}");
    assert!(
        references[0]["file"]
            .as_str()
            .unwrap()
            .ends_with("recursive.cpp")
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn symbol_summary_reports_taint_return_effect() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    // `helper` directly returns its param: web-sitter's interprocedural pass should
    // record TaintReturn(0) for it.
    let result = server
        .call_tool("symbol_summary", json!({ "symbol": "helper" }))
        .await?;
    assert_eq!(result["symbol_id"], "cpp:helper");
    let effects = result["param_effects"]
        .as_array()
        .expect("param_effects array");
    assert!(
        effects
            .iter()
            .any(|e| e.as_str().unwrap().contains("taints return")),
        "{effects:#?}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn symbol_summary_reports_error_for_unknown_symbol() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw("symbol_summary", json!({ "symbol": "does_not_exist" }))
        .await?;
    assert_eq!(
        result.get("isError").and_then(Value::as_bool),
        Some(true),
        "{result:#?}"
    );
    let text = content_text(&result).expect("error result must carry a text content block");
    assert!(text.contains("does_not_exist"), "{text}");

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
