//! The [`CommandRunner`] seam: how the state machine actually shells out to the
//! on-device `uci` / `wifi` / `/etc/init.d/*` binaries — and how tests observe
//! the EXACT argv + order WITHOUT executing anything.
//!
//! Every invocation is explicit argv via [`tokio::process::Command`] — NEVER
//! `sh -c` (guardrail). The production [`ProcessRunner`] spawns the child; the
//! test [`RecordingRunner`] records `(program, args)` tuples and returns a
//! scripted result, so a unit test can assert the whole batch/reload sequence.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use portcullis_types::ProvisionError;

/// Runs a single external command with explicit argv (no shell). Returns
/// `Ok(stdout_bytes)` on a zero exit, `Err(Apply)` otherwise. The state machine
/// funnels ALL of `uci` / `wifi` / init-script work through this one method so
/// the whole side-effecting surface is a single mockable seam.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args` and no stdin. Non-zero exit → `Err`.
    async fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, ProvisionError>;

    /// Run `program` with `args`, feeding `stdin` on the child's standard input
    /// (the P3 device-metering path pipes an `nft -j -f -` document this way).
    /// Non-zero exit → `Err`. The default forwards to [`run`](Self::run) and
    /// IGNORES `stdin` (so existing runners and mocks keep working unchanged); the
    /// production [`ProcessRunner`] overrides it to actually pipe the bytes.
    async fn run_stdin(
        &self,
        program: &str,
        args: &[&str],
        _stdin: &[u8],
    ) -> Result<Vec<u8>, ProvisionError> {
        self.run(program, args).await
    }
}

/// Production runner: `tokio::process::Command` with explicit argv, output
/// captured. A non-zero exit or a spawn failure maps to [`ProvisionError::Apply`]
/// (fail-OPEN semantics are handled by the caller, which rolls back).
#[derive(Clone, Debug, Default)]
pub struct ProcessRunner;

#[async_trait]
impl CommandRunner for ProcessRunner {
    async fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, ProvisionError> {
        use std::process::Stdio;
        use tokio::process::Command;

        // Explicit argv only — NO `sh -c`. `args` is a slice of already-split
        // tokens; the shell is never invoked, so nothing here is word-split or
        // glob-expanded.
        let out = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| ProvisionError::Apply(format!("spawn {program}: {e}")))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(ProvisionError::Apply(format!(
                "{program} {} exited {:?}: {}",
                args.join(" "),
                out.status.code(),
                stderr.trim()
            )));
        }
        Ok(out.stdout)
    }

    async fn run_stdin(
        &self,
        program: &str,
        args: &[&str],
        stdin: &[u8],
    ) -> Result<Vec<u8>, ProvisionError> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        // Explicit argv only — NO `sh -c`. The payload is written to the child's
        // stdin (e.g. `nft -j -f -`), never interpolated into the command line.
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ProvisionError::Apply(format!("spawn {program}: {e}")))?;

        if let Some(mut sink) = child.stdin.take() {
            sink.write_all(stdin)
                .await
                .map_err(|e| ProvisionError::Apply(format!("write stdin to {program}: {e}")))?;
            // Drop closes the pipe so the child sees EOF.
            drop(sink);
        }

        let out = child
            .wait_with_output()
            .await
            .map_err(|e| ProvisionError::Apply(format!("wait {program}: {e}")))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(ProvisionError::Apply(format!(
                "{program} {} exited {:?}: {}",
                args.join(" "),
                out.status.code(),
                stderr.trim()
            )));
        }
        Ok(out.stdout)
    }
}

/// One recorded invocation: the program and its argv (owned, for assertions).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    pub program: String,
    pub args: Vec<String>,
}

/// A scripted response the [`RecordingRunner`] returns for a matching command.
type Responder = Arc<dyn Fn(&str, &[&str]) -> Result<Vec<u8>, ProvisionError> + Send + Sync>;

/// Test runner: records every invocation (in order) and returns a scripted
/// result, WITHOUT executing anything. The default responder returns empty
/// stdout / success, so a test only scripts the commands it wants to fail
/// (e.g. make `network reload` fail to exercise rollback).
#[derive(Clone)]
pub struct RecordingRunner {
    calls: Arc<Mutex<Vec<Invocation>>>,
    responder: Responder,
}

impl Default for RecordingRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RecordingRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingRunner")
            .field("calls", &self.calls.lock().map(|c| c.len()).unwrap_or(0))
            .finish()
    }
}

impl RecordingRunner {
    /// A runner where every command succeeds with empty stdout.
    pub fn new() -> Self {
        RecordingRunner {
            calls: Arc::new(Mutex::new(Vec::new())),
            responder: Arc::new(|_p, _a| Ok(Vec::new())),
        }
    }

    /// A runner with a custom responder: `f(program, args)` decides the result
    /// (used to simulate `uci show` output for snapshots, or a failing reload).
    pub fn with_responder<F>(f: F) -> Self
    where
        F: Fn(&str, &[&str]) -> Result<Vec<u8>, ProvisionError> + Send + Sync + 'static,
    {
        RecordingRunner {
            calls: Arc::new(Mutex::new(Vec::new())),
            responder: Arc::new(f),
        }
    }

    /// All invocations recorded so far, in order.
    pub fn calls(&self) -> Vec<Invocation> {
        self.calls.lock().expect("runner mutex poisoned").clone()
    }

    /// Just the `(program, joined-args)` pairs — convenient for order assertions.
    pub fn flat(&self) -> Vec<(String, String)> {
        self.calls()
            .into_iter()
            .map(|i| (i.program, i.args.join(" ")))
            .collect()
    }
}

#[async_trait]
impl CommandRunner for RecordingRunner {
    async fn run(&self, program: &str, args: &[&str]) -> Result<Vec<u8>, ProvisionError> {
        self.calls.lock().expect("runner mutex poisoned").push(Invocation {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });
        (self.responder)(program, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_runner_records_in_order_and_defaults_to_success() {
        let r = RecordingRunner::new();
        r.run("uci", &["set", "a=b"]).await.unwrap();
        r.run("uci", &["commit", "network"]).await.unwrap();
        assert_eq!(
            r.flat(),
            vec![
                ("uci".to_string(), "set a=b".to_string()),
                ("uci".to_string(), "commit network".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn recording_runner_responder_can_fail_a_specific_command() {
        let r = RecordingRunner::with_responder(|prog, args| {
            if prog == "/etc/init.d/network" && args == ["reload"] {
                Err(ProvisionError::Apply("network reload boom".into()))
            } else {
                Ok(Vec::new())
            }
        });
        assert!(r.run("uci", &["commit", "network"]).await.is_ok());
        assert!(r.run("/etc/init.d/network", &["reload"]).await.is_err());
    }

    #[tokio::test]
    async fn process_runner_maps_missing_binary_to_apply_error() {
        let r = ProcessRunner;
        let err = r.run("/nonexistent/portcullis-test-uci", &["show"]).await.unwrap_err();
        assert!(matches!(err, ProvisionError::Apply(_)));
    }
}
