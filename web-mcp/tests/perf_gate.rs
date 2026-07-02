//! Coarse perf-regression gate (task 21's CI-gate requirement): spawn the real binary
//! against a synthetic multi-file fixture sized to catch a catastrophic algorithmic
//! regression (e.g. an accidentally-quadratic pass over `Workspace::files`), and assert
//! cold-start indexing completes within a generous wall-clock ceiling.
//!
//! Deliberately not a `criterion` micro-benchmark with statistical regression thresholds:
//! shared CI runners have too much variance for a tight threshold to be anything but
//! flaky. The ceiling here (60s for 300 files) is loose by several times observed local
//! run time (~13s) — it exists to catch "someone introduced an O(n²) loop and indexing
//! now takes 10 minutes," not to track routine performance drift. Tracking drift precisely
//! is exactly what a `criterion` suite is for and is better run locally/on dedicated
//! hardware than gated in shared CI (left as a documented follow-up, not implemented
//! here).

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

const READ_TIMEOUT: Duration = Duration::from_secs(120);
/// Loose on purpose — see module docs. Local runs of this fixture complete in well under
/// 5s; this is roughly a 10x margin, not a tight bound.
const COLD_START_CEILING: Duration = Duration::from_secs(60);
const FILE_COUNT: usize = 300;
const FUNCTIONS_PER_FILE: usize = 5;

fn write_synthetic_fixture(dir: &Path) {
    for file_idx in 0..FILE_COUNT {
        let mut source = String::new();
        for fn_idx in 0..FUNCTIONS_PER_FILE {
            // Every function calls the previous one in the same file, and (for every file
            // after the first) the last function of the previous file — real call-graph
            // and cross-file-edge shape, not just isolated leaf functions, so this
            // exercises `build_cross_file_edges`/`ReverseSymbolIndex::build` too, not just
            // parsing.
            if fn_idx == 0 && file_idx > 0 {
                source.push_str(&format!(
                    "int f{file_idx}_{fn_idx}() {{ return f{prev_file}_{prev_fn}(); }}\n",
                    prev_file = file_idx - 1,
                    prev_fn = FUNCTIONS_PER_FILE - 1
                ));
            } else if fn_idx == 0 {
                source.push_str(&format!("int f{file_idx}_{fn_idx}() {{ return 0; }}\n"));
            } else {
                source.push_str(&format!(
                    "int f{file_idx}_{fn_idx}() {{ return f{file_idx}_{prev_fn}(); }}\n",
                    prev_fn = fn_idx - 1
                ));
            }
        }
        std::fs::write(dir.join(format!("file_{file_idx}.cpp")), source).unwrap();
    }
}

#[tokio::test]
async fn cold_start_indexing_of_a_synthetic_multi_file_workspace_completes_within_the_ceiling()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_synthetic_fixture(dir.path());

    let started = Instant::now();

    let mut child = Command::new(env!("CARGO_BIN_EXE_web-mcp"))
        .arg("--root")
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut writer = child.stdin.take().expect("child stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("child stdout"));

    send_json(
        &mut writer,
        &json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "perf-gate-test", "version": "0.0.0" }
            }
        }),
    )
    .await?;
    read_response_for_id(&mut reader, 0).await?;
    send_json(
        &mut writer,
        &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    )
    .await?;

    // A real tool call round-trip confirms indexing (which happens synchronously before
    // the server starts serving) actually completed, not just that the process launched.
    send_json(
        &mut writer,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "find_definition",
                "arguments": { "symbol": "f0_0" }
            }
        }),
    )
    .await?;
    read_response_for_id(&mut reader, 1).await?;

    let elapsed = started.elapsed();

    drop(writer);
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    if child.id().is_some() {
        let _ = child.kill().await;
    }

    assert!(
        elapsed < COLD_START_CEILING,
        "cold start of a {FILE_COUNT}-file workspace took {elapsed:?}, over the \
         {COLD_START_CEILING:?} regression-gate ceiling"
    );

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
