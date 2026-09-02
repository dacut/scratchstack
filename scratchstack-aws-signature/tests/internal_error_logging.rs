//! `internal_service_error!` is a macro, not a function, so that the log entry is attributed to
//! the code that failed. A function would log every internal failure in the workspace against a
//! single line inside this crate, which breaks `RUST_LOG` filtering by module as well as the
//! file and line in the record.
//!
//! This lives in `tests/` rather than beside the macro because it installs a global logger, and
//! only one can be installed per process.

use {
    log::{Level, LevelFilter, Metadata, Record},
    scratchstack_aws_signature::{SignatureError, internal_service_error},
    scratchstack_core::ProvideRequestId,
    std::sync::{Mutex, OnceLock},
};

/// Where the last record came from, and what it said.
struct Captured {
    module: Option<String>,
    file: Option<String>,
    message: String,
}

fn captured() -> &'static Mutex<Vec<Captured>> {
    static CAPTURED: OnceLock<Mutex<Vec<Captured>>> = OnceLock::new();
    CAPTURED.get_or_init(|| Mutex::new(Vec::new()))
}

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Error
    }

    fn log(&self, record: &Record) {
        captured().lock().unwrap().push(Captured {
            module: record.module_path().map(str::to_string),
            file: record.file().map(str::to_string),
            message: record.args().to_string(),
        });
    }

    fn flush(&self) {}
}

static CAPTURE: Capture = Capture;

#[test]
fn internal_failures_log_where_they_happened_and_return_nothing() {
    log::set_logger(&CAPTURE).expect("no other logger is installed in this test binary");
    log::set_max_level(LevelFilter::Error);

    let plain: SignatureError = internal_service_error!("connection to {} failed", "db-1");
    let with_id: SignatureError = internal_service_error!("req-abc"; "query failed: {}", "SELECT pw FROM creds");

    let records = captured().lock().unwrap();
    assert_eq!(records.len(), 2, "each invocation logs exactly once");

    // Attributed to this file, not to the crate that defines the macro.
    for record in records.iter() {
        assert_eq!(record.module.as_deref(), Some("internal_error_logging"), "module: {:?}", record.module);
        assert_eq!(
            record.file.as_deref(),
            Some("scratchstack-aws-signature/tests/internal_error_logging.rs"),
            "file: {:?}",
            record.file
        );
    }

    // The detail reaches the log ...
    assert_eq!(records[0].message, "Internal service error: connection to db-1 failed");
    assert_eq!(records[1].message, "req-abc: Internal service error: query failed: SELECT pw FROM creds");

    // ... and nowhere else. The returned errors carry the fixed message and, at most, a request id.
    for e in [&plain, &with_id] {
        assert_eq!(e.to_string(), "Internal Service Error");
        assert_eq!(e.error_code(), "InternalFailure");
        assert!(!format!("{e:?}").contains("db-1"));
        assert!(!format!("{e:?}").contains("SELECT"));
    }
    assert_eq!(ProvideRequestId::request_id(&plain), None);
    assert_eq!(ProvideRequestId::request_id(&with_id), Some("req-abc"));
}
