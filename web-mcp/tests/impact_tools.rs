//! Integration tests for `impact_of_change`: spawn the real binary against a small
//! fixture repo (a_fn -> b_fn -> c_fn), propose edits to the middle function, and assert
//! on the reported changed symbols and blast radius.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

fn write_fixture(dir: &Path) {
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
                    "clientInfo": { "name": "impact-tools-test", "version": "0.0.0" }
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
async fn modifying_b_fn_reports_it_changed_and_a_fn_in_the_blast_radius() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "impact_of_change",
            json!({
                "file": "b.cpp",
                "new_source": "int c_fn();\nint b_fn() { return c_fn() + 1; }\n"
            }),
        )
        .await?;

    let changed = result["changed_symbols"]
        .as_array()
        .expect("changed_symbols array");
    assert_eq!(changed.len(), 1, "{changed:#?}");
    assert_eq!(changed[0]["symbol_id"], "cpp:b_fn");
    assert_eq!(changed[0]["change_kind"], "modified");

    let blast: Vec<&str> = result["blast_radius"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(blast.contains(&"cpp:b_fn"), "{blast:?}");
    assert!(blast.contains(&"cpp:a_fn"), "{blast:?}");
    assert!(
        !blast.contains(&"cpp:c_fn"),
        "c_fn is a callee, not a caller: {blast:?}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn no_op_edit_reports_no_changed_symbols() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "impact_of_change",
            json!({
                "file": "b.cpp",
                "new_source": "int c_fn();\nint b_fn() { return c_fn(); }\n"
            }),
        )
        .await?;
    let changed = result["changed_symbols"]
        .as_array()
        .expect("changed_symbols array");
    assert!(changed.is_empty(), "{changed:#?}");
    assert!(result["blast_radius"].as_array().unwrap().is_empty());

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn adding_a_new_function_reports_it_as_added_with_no_blast_radius() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "impact_of_change",
            json!({
                "file": "c.cpp",
                "new_source": "int c_fn() { return 1; }\nint new_fn() { return 2; }\n"
            }),
        )
        .await?;
    let changed = result["changed_symbols"]
        .as_array()
        .expect("changed_symbols array");
    assert_eq!(changed.len(), 1, "{changed:#?}");
    assert_eq!(changed[0]["symbol_id"], "cpp:new_fn");
    assert_eq!(changed[0]["change_kind"], "added");
    assert!(
        result["blast_radius"].as_array().unwrap().is_empty(),
        "a brand-new function has no existing callers"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn removing_c_fn_reports_it_removed_with_its_callers_in_the_blast_radius()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "impact_of_change",
            json!({ "file": "c.cpp", "new_source": "" }),
        )
        .await?;
    let changed = result["changed_symbols"]
        .as_array()
        .expect("changed_symbols array");
    assert_eq!(changed.len(), 1, "{changed:#?}");
    assert_eq!(changed[0]["symbol_id"], "cpp:c_fn");
    assert_eq!(changed[0]["change_kind"], "removed");

    let blast: Vec<&str> = result["blast_radius"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(blast.contains(&"cpp:c_fn"), "{blast:?}");
    assert!(
        blast.contains(&"cpp:b_fn"),
        "b_fn calls the removed c_fn: {blast:?}"
    );
    assert!(
        blast.contains(&"cpp:a_fn"),
        "a_fn transitively calls c_fn: {blast:?}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn reports_error_for_unindexed_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "impact_of_change",
            json!({ "file": "does_not_exist.cpp", "new_source": "int x() { return 1; }" }),
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
