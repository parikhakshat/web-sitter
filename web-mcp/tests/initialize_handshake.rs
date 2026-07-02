//! Integration test: spawn the real `web-mcp` binary as a subprocess (real stdio pipes,
//! not an in-process transport) and complete the MCP `initialize` handshake against it —
//! the smallest possible proof that the rmcp stdio transport wiring in `main.rs`/
//! `server.rs` actually works end to end, not just that it compiles.

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn completes_initialize_handshake_over_real_stdio() -> anyhow::Result<()> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_web-mcp"))
        .arg("--root")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;

    let mut writer = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    send_json(
        &mut writer,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "web-mcp-integration-test", "version": "0.0.0" }
            }
        }),
    )
    .await?;

    let response = read_response_for_id(&mut reader, 1).await?;
    let result = response
        .get("result")
        .expect("initialize response must have a result");

    assert_eq!(
        result
            .get("serverInfo")
            .and_then(|si| si.get("name"))
            .and_then(Value::as_str),
        Some("web-mcp"),
        "serverInfo.name must identify this server: {result:#}"
    );
    assert!(
        result
            .get("capabilities")
            .and_then(|c| c.get("tools"))
            .is_some(),
        "tools capability must be advertised even with an empty tool registry: {result:#}"
    );

    send_json(
        &mut writer,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await?;

    // A `tools/list` call against the empty Phase-1 registry must succeed with an empty
    // list, not error — this is the contract later tool-adding tasks build on.
    send_json(
        &mut writer,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    )
    .await?;
    let list_response = read_response_for_id(&mut reader, 2).await?;
    let tools = list_response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .expect("tools/list must return a tools array");
    assert!(
        tools.is_empty(),
        "Phase-1 skeleton has no tools yet: {tools:?}"
    );

    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    if child.id().is_some() {
        let _ = child.kill().await;
    }
    Ok(())
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
