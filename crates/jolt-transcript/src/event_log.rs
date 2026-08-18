//! Opt-in Fiat-Shamir event logger for transcript-grammar extraction.
//!
//! When the `KISHU_EVENT_LOG` environment variable names a file, every
//! [`crate::DigestTranscript`] operation appends one JSON line to it:
//! transcript instance, global sequence number, operation kind, payload
//! length, a hex prefix of the payload, and the first non-transcript stack
//! frame (file:line) that issued the call. Used to machine-emit the
//! event-level wire map of a prover/verifier run; disabled (and free apart
//! from one branch) when the variable is unset.

use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

static INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);
static SEQ_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Longest payload prefix captured per event, in bytes. 64 bytes covers the
/// full 32-byte labels/field elements and identifies longer payloads.
const PREFIX_LEN: usize = 64;

fn log_file() -> Option<&'static Mutex<std::fs::File>> {
    static FILE: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
    FILE.get_or_init(|| {
        let path = std::env::var("KISHU_EVENT_LOG").ok()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        Some(Mutex::new(file))
    })
    .as_ref()
}

/// Allocates the next transcript instance id (0 when logging is disabled,
/// where the id is never read).
pub(crate) fn next_instance() -> u64 {
    if log_file().is_none() {
        return 0;
    }
    INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Records one transcript event. No-op unless `KISHU_EVENT_LOG` is set.
/// `payload_digest` is a collision-resistant digest of the FULL payload
/// (computed by the caller with its own hash type), so stream-symmetry
/// comparisons establish byte identity, not 64-byte-prefix equality.
#[expect(
    clippy::format_collect,
    reason = "opt-in diagnostics logger; clarity over the write!-fold idiom"
)]
pub(crate) fn record(instance: u64, kind: &str, payload: &[u8], payload_digest: &[u8]) {
    let Some(file) = log_file() else { return };
    let seq = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    let caller = caller_frame();
    let prefix_len = payload.len().min(PREFIX_LEN);
    let hex: String = payload
        .iter()
        .take(prefix_len)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let digest_hex: String = payload_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let line = format!(
        "{{\"seq\":{seq},\"inst\":{instance},\"kind\":\"{kind}\",\"len\":{},\"data\":\"{hex}\",\"digest\":\"{digest_hex}\",\"caller\":\"{}\"}}\n",
        payload.len(),
        caller.replace('\\', "/").replace('"', "'"),
    );
    if let Ok(mut file) = file.lock() {
        // best-effort: the event log is opt-in diagnostics
        drop(file.write_all(line.as_bytes()));
    }
}

/// The first stack frame outside this crate and the standard library,
/// formatted `path:line`. Backtrace resolution is slow; acceptable for
/// opt-in grammar extraction runs.
fn caller_frame() -> String {
    if std::env::var("KISHU_EVENT_CALLERS").is_ok_and(|v| v == "0") {
        return String::new();
    }
    let backtrace = std::backtrace::Backtrace::force_capture();
    let text = backtrace.to_string();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let Some(path) = trimmed.strip_prefix("at ") else {
            continue;
        };
        if path.contains("jolt-transcript/src")
            || path.contains("/rustc/")
            || path.contains("/library/std/")
            || path.contains("/library/core/")
            || path.contains("backtrace")
        {
            continue;
        }
        // Strip the column suffix; keep path:line.
        let path = path.trim_end();
        return match path.rfind(':') {
            Some(idx)
                if path
                    .get(idx + 1..)
                    .is_some_and(|s| s.chars().all(|c| c.is_ascii_digit())) =>
            {
                path.get(..idx).unwrap_or(path).to_string()
            }
            _ => path.to_string(),
        };
    }
    String::new()
}
