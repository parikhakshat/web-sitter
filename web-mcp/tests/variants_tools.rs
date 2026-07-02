//! Integration tests for `find_variants`/`explain_variant`: spawn the real binary against
//! a fixture repo with several instances of the same dangerous call, point `find_variants`
//! at one of them, and assert the generalized query finds the others through the actual
//! MCP protocol.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

fn write_fixture(dir: &Path) {
    std::fs::create_dir(dir.join("src")).unwrap();
    std::fs::create_dir(dir.join("other")).unwrap();
    // Example instance: line 1, the system() call starts at column 30.
    std::fs::write(
        dir.join("src/example.cpp"),
        "void run(const char* cmd) { system(cmd); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src/variant.cpp"),
        "void run2(const char* user_input) { system(user_input); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("other/also_variant.cpp"),
        "void run3(const char* c) { system(c); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src/unrelated.cpp"),
        "int add(int a, int b) { return a + b; }\n",
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
                    "clientInfo": { "name": "variants-tools-test", "version": "0.0.0" }
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
async fn find_variants_finds_other_instances_of_the_same_call_across_the_workspace()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    // Column 30 is where `system(cmd)` starts in "void run(const char* cmd) { system(cmd); }".
    let result = server
        .call_tool(
            "find_variants",
            json!({
                "location": { "file": "src/example.cpp", "line": 1, "column": 28 },
                "scope": "workspace"
            }),
        )
        .await?;

    assert_eq!(result["anchor_callees"], json!(["system"]));
    let matches = result["matches"].as_array().unwrap();
    let files: std::collections::BTreeSet<&str> = matches
        .iter()
        .map(|m| m["file"].as_str().unwrap())
        .collect();
    assert!(
        files.iter().any(|f| f.ends_with("example.cpp")),
        "{files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with("variant.cpp")),
        "{files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with("also_variant.cpp")),
        "{files:?}"
    );
    assert!(
        !files.iter().any(|f| f.ends_with("unrelated.cpp")),
        "unrelated.cpp has no system() call: {files:?}"
    );

    let example_match = matches
        .iter()
        .find(|m| m["file"].as_str().unwrap().ends_with("example.cpp"))
        .unwrap();
    assert_eq!(example_match["is_example"], true);
    let variant_match = matches
        .iter()
        .find(|m| {
            m["file"].as_str().unwrap().ends_with("variant.cpp")
                && !m["file"].as_str().unwrap().ends_with("also_variant.cpp")
        })
        .unwrap();
    assert_eq!(variant_match["is_example"], false);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn find_variants_directory_scope_excludes_files_outside_it() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "find_variants",
            json!({
                "location": { "file": "src/example.cpp", "line": 1, "column": 28 },
                "scope": "directory",
                "path": "src"
            }),
        )
        .await?;

    let files: Vec<&str> = result["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["file"].as_str().unwrap())
        .collect();
    assert!(
        files.iter().all(|f| !f.contains("other")),
        "other/also_variant.cpp is out of scope: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with("variant.cpp")),
        "{files:?}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn explain_variant_returns_evidence_for_a_match() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let found = server
        .call_tool(
            "find_variants",
            json!({
                "location": { "file": "src/example.cpp", "line": 1, "column": 28 },
                "scope": "workspace"
            }),
        )
        .await?;
    let variant_match = found["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| {
            m["file"].as_str().unwrap().ends_with("variant.cpp")
                && !m["file"].as_str().unwrap().ends_with("also_variant.cpp")
        })
        .unwrap();
    let match_id = variant_match["match_id"].as_str().unwrap().to_string();

    let explained = server
        .call_tool("explain_variant", json!({ "match_id": match_id }))
        .await?;
    assert_eq!(explained["callee"], "system");
    assert!(
        explained["enclosing_symbol"]
            .as_str()
            .unwrap()
            .contains("run2"),
        "{explained:#}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn find_variants_errors_when_location_is_not_a_call() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "find_variants",
            json!({
                "location": { "file": "src/unrelated.cpp", "line": 1, "column": 1 },
                "scope": "workspace"
            }),
        )
        .await?;
    assert_eq!(result.get("isError").and_then(Value::as_bool), Some(true));

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn explain_variant_errors_for_a_malformed_match_id() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw("explain_variant", json!({ "match_id": "not-a-real-id" }))
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
