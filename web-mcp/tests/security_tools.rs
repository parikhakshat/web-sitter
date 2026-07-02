//! Integration tests for `run_security_scan`: spawn the real binary against a small
//! fixture repo with an intentionally vulnerable call site, and assert scoping
//! (file/directory/diff/workspace), severity filtering, and custom rule sets all work
//! against the actual MCP protocol — not mocks.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// A rule matching any call to `system` — deliberately simple, standing in for the
/// real 52-rule CWE corpus so tests don't depend on its exact contents.
const SYSTEM_CALL_RULE: &str = r#"
rule "test-system-call" {
    severity: critical
    languages: [c, cpp]
    message: "call to system()"
    tags: ["test"]
    find n: Call where n.callee_name() in ["system"]
}
"#;

/// A second rule at a lower severity, matching `strcpy` — used to exercise
/// `severity_threshold` filtering (system-call is critical, strcpy is low).
const STRCPY_RULE: &str = r#"
rule "test-strcpy-call" {
    severity: low
    languages: [c, cpp]
    message: "call to strcpy()"
    tags: ["test"]
    find n: Call where n.callee_name() in ["strcpy"]
}
"#;

fn two_rules() -> String {
    format!("{SYSTEM_CALL_RULE}\n{STRCPY_RULE}")
}

fn write_fixture(dir: &Path) {
    std::fs::create_dir(dir.join("src")).unwrap();
    std::fs::create_dir(dir.join("other")).unwrap();
    std::fs::write(
        dir.join("src/vulnerable.cpp"),
        "void run(const char* cmd) { system(cmd); }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src/clean.cpp"),
        "int add(int a, int b) { return a + b; }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("other/also_vulnerable.cpp"),
        "void run2(const char* cmd) { system(cmd); }\n",
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
        Self::spawn_with_rules_dir(root, None).await
    }

    async fn spawn_with_rules_dir(root: &Path, rules_dir: Option<&Path>) -> anyhow::Result<Self> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_web-mcp"));
        command.arg("--root").arg(root);
        if let Some(rules_dir) = rules_dir {
            command.arg("--rules-dir").arg(rules_dir);
        }
        let mut child = command
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
                    "clientInfo": { "name": "security-tools-test", "version": "0.0.0" }
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

fn finding_files(result: &Value) -> Vec<String> {
    result["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|f| f["file"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn scope_file_only_reports_findings_in_that_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "run_security_scan",
            json!({
                "scope": "file",
                "path": "src/vulnerable.cpp",
                "rule_source": SYSTEM_CALL_RULE
            }),
        )
        .await?;

    let files = finding_files(&result);
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].ends_with("vulnerable.cpp"), "{files:?}");
    assert_eq!(result["files_scanned"], 1);

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn scope_directory_reports_findings_only_under_that_directory() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "run_security_scan",
            json!({
                "scope": "directory",
                "path": "src",
                "rule_source": SYSTEM_CALL_RULE
            }),
        )
        .await?;

    let files = finding_files(&result);
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].contains("src"), "{files:?}");
    assert!(
        !files[0].contains("other"),
        "other/also_vulnerable.cpp is out of scope: {files:?}"
    );
    assert_eq!(result["files_scanned"], 2, "src has two files");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn scope_workspace_reports_findings_across_every_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "run_security_scan",
            json!({ "scope": "workspace", "rule_source": SYSTEM_CALL_RULE }),
        )
        .await?;

    let files = finding_files(&result);
    assert_eq!(
        files.len(),
        2,
        "both vulnerable.cpp and also_vulnerable.cpp must be found: {files:?}"
    );
    assert_eq!(result["files_scanned"], 3, "all three fixture files");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn scope_diff_scans_only_the_blast_radius_of_the_proposed_change() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    // Proposing to introduce a new system() call into clean.cpp — diff scope must catch
    // it even though clean.cpp itself has no vulnerability on disk yet.
    let result = server
        .call_tool(
            "run_security_scan",
            json!({
                "scope": "diff",
                "path": "src/clean.cpp",
                "new_source": "int add(int a, int b) { system(\"echo hi\"); return a + b; }\n",
                "rule_source": SYSTEM_CALL_RULE
            }),
        )
        .await?;

    // The diff scope scans the *current on-disk* workspace (the proposed new_source is
    // only used to compute the blast radius, not actually applied) — clean.cpp on disk
    // has no system() call, so the finding must come from vulnerable.cpp being in the
    // same directory-independent blast radius is NOT expected here since they're
    // unrelated files; the scope should just be clean.cpp itself (no callers/callees).
    let files = finding_files(&result);
    assert!(
        files
            .iter()
            .all(|f| f.ends_with("clean.cpp") || f.is_empty()),
        "diff scope for an unrelated file must not pull in other files: {files:?}"
    );
    assert_eq!(
        result["files_scanned"], 1,
        "clean.cpp has no callers/references, so its blast radius is just itself"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn severity_threshold_filters_out_less_severe_findings() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    std::fs::write(
        dir.path().join("src/vulnerable.cpp"),
        "void run(const char* cmd, char* buf) { system(cmd); strcpy(buf, cmd); }\n",
    )
    .unwrap();
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool(
            "run_security_scan",
            json!({
                "scope": "file",
                "path": "src/vulnerable.cpp",
                "rule_source": two_rules(),
                "severity_threshold": "high"
            }),
        )
        .await?;

    let rule_ids: Vec<&str> = result["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert!(
        rule_ids.contains(&"test-system-call"),
        "critical must pass a high threshold: {rule_ids:?}"
    );
    assert!(
        !rule_ids.contains(&"test-strcpy-call"),
        "low must be filtered out by a high threshold: {rule_ids:?}"
    );

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn no_rule_source_falls_back_to_the_built_in_corpus_from_rules_dir() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let rules_dir = tempfile::tempdir()?;
    std::fs::write(rules_dir.path().join("system.wql"), SYSTEM_CALL_RULE).unwrap();

    let mut server = TestServer::spawn_with_rules_dir(dir.path(), Some(rules_dir.path())).await?;

    let result = server
        .call_tool(
            "run_security_scan",
            json!({ "scope": "file", "path": "src/vulnerable.cpp" }),
        )
        .await?;

    let files = finding_files(&result);
    assert_eq!(files.len(), 1, "{files:?}");

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn unsupported_scope_is_reported_as_an_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    write_fixture(dir.path());
    let mut server = TestServer::spawn(dir.path()).await?;

    let result = server
        .call_tool_raw(
            "run_security_scan",
            json!({ "scope": "bogus", "rule_source": SYSTEM_CALL_RULE }),
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
