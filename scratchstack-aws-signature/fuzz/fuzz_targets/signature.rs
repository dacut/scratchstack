//! Fuzzes `sigv4_validate_request` with arbitrary requests and validation settings.
//!
//! Every validation outcome is acceptable -- a fuzzed request is not going to be well signed --
//! so the target is looking for panics and hangs in canonicalization, header and query-string
//! parsing, and the error paths. Inputs that cannot even be turned into an HTTP request are
//! rejected from the corpus.
//!
//! Run with `cargo +nightly fuzz run signature` from the crate directory.
#![no_main]

use {
    arbitrary::Arbitrary,
    bytes::Bytes,
    chrono::{DateTime, Utc},
    libfuzzer_sys::{Corpus, fuzz_target},
    scratchstack_aws_principal::{Principal, User},
    scratchstack_aws_signature::{
        GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SessionPolicies, SignatureError, SignatureOptions,
        VecSignedHeaderRequirements, service_for_signing_key_fn, sigv4_validate_request,
    },
    scratchstack_core::{
        RequestId,
        http::{Method, Request, Uri},
    },
    std::str::FromStr,
    tokio::runtime::Builder as RuntimeBuilder,
    tower::BoxError,
};

#[derive(Arbitrary, Debug)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Patch,
}

impl From<HttpMethod> for Method {
    fn from(method: HttpMethod) -> Self {
        match method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Options => Method::OPTIONS,
            HttpMethod::Trace => Method::TRACE,
            HttpMethod::Connect => Method::CONNECT,
            HttpMethod::Patch => Method::PATCH,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct ValidateInput {
    method: HttpMethod,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    region: String,
    service: String,
    s3: bool,
    url_encode_form: bool,
    always_present: Vec<String>,
    if_in_request: Vec<String>,
    prefixes: Vec<String>,
}

/// Every access key resolves to the AWS example user and secret key.
async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError> {
    let k_secret =
        KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").expect("example key is well-formed");
    let k_signing = k_secret.to_ksigning(req.request_date(), req.region(), req.service());
    let principal = Principal::from(
        User::builder()
            .partition("aws")
            .account_id("123456789012")
            .path("/")
            .user_name("test")
            .build()
            .expect("example user is well-formed"),
    );
    Ok(GetSigningKeyResponse::builder()
        .principal(principal)
        .signing_key(k_signing)
        .session_policies(SessionPolicies::UNRESTRICTED)
        .build())
}

fuzz_target!(|data: ValidateInput| -> Corpus {
    match run_target(data) {
        Ok(()) => Corpus::Keep,
        Err(_) => Corpus::Reject,
    }
});

/// Fails only when the input cannot be made into an HTTP request; validation errors are the
/// point of the exercise and are ignored.
fn run_target(data: ValidateInput) -> Result<(), BoxError> {
    // 2015-08-30T12:36:00Z, the AWS test-suite timestamp.
    let server_timestamp: DateTime<Utc> = DateTime::from_timestamp(1_440_938_160, 0).expect("fixed timestamp is valid");

    let uri = Uri::from_maybe_shared(data.uri)?;
    let mut builder = Request::builder().method(Method::from(data.method)).uri(uri).extension(RequestId::new());
    for (name, value) in data.headers {
        builder = builder.header(name, value);
    }
    let request = builder.body(Bytes::from(data.body))?;

    let required_headers = VecSignedHeaderRequirements::builder()
        .always_present(data.always_present)
        .if_in_request(data.if_in_request)
        .prefixes(data.prefixes)
        .build();
    let options = SignatureOptions::builder().s3(data.s3).url_encode_form(data.url_encode_form).build();
    let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

    let rt = RuntimeBuilder::new_current_thread().build()?;
    rt.block_on(async move {
        let _ = sigv4_validate_request(
            request,
            &data.region,
            &data.service,
            &mut get_signing_key_svc,
            server_timestamp,
            &required_headers,
            options,
        )
        .await;
    });
    Ok(())
}
