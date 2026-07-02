//! End-to-end test for the file-watcher → `LiveIndex` wiring (task: "wire live updates
//! into the server"): spawn the real binary, confirm a symbol that doesn't exist yet is
//! genuinely not found, write a new file containing it to disk *after* the server has
//! started, and confirm a tool call picks it up without restarting the server — the
//! actual user-visible behavior this wiring exists to deliver. Also covers modifying an
//! existing file and a new cross-file call becoming visible in the call graph.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Debounce is 100ms server-side; give a comfortable margin for the watcher event, the
/// reparse, and the rebuild to actually land before a tool call would see it.
const POLL_TIMEOUT: Duration = Duration::from_secs(10);

struct TestServer {
    child: Child,
    writer: tokio::process::ChildStdin,
    reader: BufReader<tokio::process::ChildStdout>,
    next_id: u64,
    // Kept alive for the server's lifetime: the cache dir the watcher-driven server
    // writes redb state into. Deliberately a *separate* tempdir from `root`, not a
    // subdirectory of it — the watcher watches `root` recursively with no extension
    // filter, so a cache dir nested inside it would generate spurious watch events for
    // the server's own redb writes.
    _cache_dir: tempfile::TempDir,
}

impl TestServer {
    async fn spawn(root: &Path) -> anyhow::Result<Self> {
        let cache_dir = tempfile::tempdir()?;
        let mut child = Command::new(env!("CARGO_BIN_EXE_web-mcp"))
            .arg("--root")
            .arg(root)
            .arg("--cache-dir")
            .arg(cache_dir.path())
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
            _cache_dir: cache_dir,
        };

        server
            .send(&json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "live-updates-test", "version": "0.0.0" }
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

/// Repeatedly call `find_definition` for `symbol` until it returns at least one
/// definition or `POLL_TIMEOUT` elapses — live updates land asynchronously (real
/// filesystem event -> debounce -> reparse -> rebuild), not instantaneously.
async fn wait_for_definition(server: &mut TestServer, symbol: &str) -> Value {
    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        let result = server
            .call_tool("find_definition", json!({ "symbol": symbol }))
            .await
            .unwrap();
        let definitions = result["definitions"].as_array().unwrap();
        if !definitions.is_empty() {
            return result;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("'{symbol}' never became visible within {POLL_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_new_file_written_after_startup_becomes_visible_to_find_definition() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("existing.cpp"),
        "int existing() { return 1; }\n",
    )
    .unwrap();
    let mut server = TestServer::spawn(dir.path()).await?;

    // Sanity check: the symbol genuinely doesn't exist yet.
    let before = server
        .call_tool("find_definition", json!({ "symbol": "brand_new_fn" }))
        .await?;
    assert!(before["definitions"].as_array().unwrap().is_empty());

    // The actual live-update event: a new file appears on disk after the server started.
    std::fs::write(
        dir.path().join("new_file.cpp"),
        "int brand_new_fn() { return 42; }\n",
    )
    .unwrap();

    let after = wait_for_definition(&mut server, "brand_new_fn").await;
    let definitions = after["definitions"].as_array().unwrap();
    assert_eq!(definitions.len(), 1, "{definitions:#?}");
    assert!(
        definitions[0]["file"]
            .as_str()
            .unwrap()
            .ends_with("new_file.cpp"),
        "{definitions:#?}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_new_cross_file_call_becomes_visible_in_get_callers() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("callee.cpp"),
        "int helper(int y) { return y; }\n",
    )
    .unwrap();
    let mut server = TestServer::spawn(dir.path()).await?;

    // No callers yet — caller.cpp doesn't exist.
    let before = server
        .call_tool("get_callers", json!({ "symbol": "helper" }))
        .await?;
    assert!(before["nodes"].as_array().unwrap().is_empty());

    std::fs::write(
        dir.path().join("caller.cpp"),
        "int caller() { return helper(1); }\n",
    )
    .unwrap();

    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        let result = server
            .call_tool("get_callers", json!({ "symbol": "helper" }))
            .await?;
        let nodes = result["nodes"].as_array().unwrap();
        if nodes.iter().any(|n| n["symbol_id"] == "cpp:caller") {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("cpp:caller never became visible as a caller of helper within {POLL_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn modifying_an_existing_file_is_reflected_in_symbol_summary() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("a.cpp");
    std::fs::write(&file, "int a(int x) { return x; }\n").unwrap();
    let mut server = TestServer::spawn(dir.path()).await?;

    // Establish the file is indexed before mutating it.
    wait_for_definition(&mut server, "a").await;

    // Rewrite the file with a different signature.
    std::fs::write(&file, "int a(int x, int y) { return x + y; }\n").unwrap();

    let deadline = tokio::time::Instant::now() + POLL_TIMEOUT;
    loop {
        let result = server
            .call_tool("symbol_summary", json!({ "symbol": "a" }))
            .await?;
        if let Some(sig) = result["signature"].as_str()
            && sig.contains('y')
        {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("modified signature never showed up within {POLL_TIMEOUT:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

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
