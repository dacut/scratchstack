//! The `sensitive-logging` gate belongs to the crate that invokes the macros, not to
//! `scratchstack-core` where they are defined: enabling it for one crate must not switch on
//! another crate's records. This test asserts that this crate's records appear exactly when
//! *this crate's* feature is on, and is meant to be run under three feature selections:
//!
//! * none -- the records are absent;
//! * `--features sensitive-logging` -- the records are present;
//! * `--features scratchstack-aspen/sensitive-logging` -- another crate's opt-in, so the
//!   records are still absent. This is the case a gate shared through `scratchstack-core`
//!   would fail.
//!
//! It installs a global logger, and only one can be installed per process, so it lives in
//! `tests/` on its own.

use {
    chrono::{DateTime, Utc},
    log::{LevelFilter, Metadata, Record},
    scratchstack_aws_signature::{
        GetSigningKeyRequest, GetSigningKeyResponse, NoSignedHeaderRequirements, SignatureError, SignatureOptions,
        service_for_signing_key_fn, sigv4_validate_request,
    },
    scratchstack_core::{RequestId, http::Request},
    std::sync::{Mutex, OnceLock},
};

fn captured() -> &'static Mutex<Vec<String>> {
    static CAPTURED: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    CAPTURED.get_or_init(|| Mutex::new(Vec::new()))
}

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        captured().lock().unwrap().push(record.args().to_string());
    }

    fn flush(&self) {}
}

async fn get_signing_key(_: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError> {
    unreachable!("the request below never gets as far as the signing key")
}

#[tokio::test]
async fn sensitive_records_follow_this_crates_feature() {
    log::set_logger(&Capture).expect("no other logger is installed in this process");
    log::set_max_level(LevelFilter::Trace);

    // Canonicalization -- which traces the canonical request under sensitive logging -- runs
    // before the missing Authorization header is reported.
    let request = Request::builder()
        .method("GET")
        .uri("/")
        .extension(RequestId::new())
        .header("host", "example.amazonaws.com")
        .body(())
        .expect("request is well-formed");
    let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
    let server_timestamp = DateTime::<Utc>::from_timestamp(1_440_938_160, 0).expect("fixed timestamp is valid");
    let result = sigv4_validate_request(
        request,
        "us-east-1",
        "example",
        &mut get_signing_key_svc,
        server_timestamp,
        &NoSignedHeaderRequirements,
        SignatureOptions::default(),
    )
    .await;
    assert!(matches!(result, Err(SignatureError::MissingAuthenticationToken(_))), "{result:?}");

    let records = captured().lock().unwrap();
    let emitted = records.iter().any(|message| message.starts_with("Created canonical request"));
    assert_eq!(
        emitted,
        cfg!(feature = "sensitive-logging"),
        "sensitive records must follow this crate's own feature; captured: {records:?}"
    );
}
