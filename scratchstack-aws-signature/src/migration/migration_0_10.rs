//! # Migrating from 0.10 to 0.12
//!
//! Version 0.11 reshaped this crate's API and 0.12 reshaped its errors, so a caller coming from
//! 0.10 arrives at a crate that shares little beyond its name with the one it left. This guide
//! covers that jump directly; there is nothing to be gained by stopping at 0.11 along the way.
//! Callers already on 0.11 want [the 0.11 guide][crate::migration::migration_0_11], which covers
//! the second half alone.
//!
//! Nearly every entry point changed shape, so the compiler will find nearly all of the work. What
//! it will not find are the changes in behavior -- above all
//! [session policies](#session-policies-must-be-enforced), which compiles cleanly while quietly
//! not enforcing anything.
//!
//! ## Changes
//!
//! ### Elimination of `Request` type
//! The main change is the elimination of the `scratchstack_aws_signature::Request` type. Instead,
//! [`http::Request`][crate::core::http::Request] is used directly and there is no longer a need to
//! copy data from one `Request` type to the other.
//!
//! With this, there is also no need to build a
//! [`GetSigningKeyRequest`][crate::GetSigningKeyRequest] in the validation code;
//! [`sigv4_validate_request`][crate::sigv4_validate_request] assembles one and calls your
//! signing-key service itself.
//!
//! This sample code from 0.10:
//! ```ignore
//! let http_req = http::Request::get("https://example.com").body(())?;
//! let sig_req = scratchstack_aws_signature::Request::from_http_request_parts(
//!     &http_req.into_parts().0, None);
//! let gsk_req = sig_req.to_get_signing_request(SigningKeyKind::KSigning, REGION, SERVICE)?;
//! let (principal, signing_key) = get_signing_key_service.call(gsk_req).await?;
//! sigv4_verify(&sig_req, &signing_key, None, REGION, SERVICE)?;
//! ```
//!
//! Would be written in 0.12:
//! ```ignore
//! let http_req = Request::get("https://example.com").extension(RequestId::new()).body(())?;
//! let (parts, body, auth) = sigv4_validate_request(
//!     http_req, REGION, SERVICE, &mut get_signing_key_service, Utc::now(),
//!     &NoSignedHeaderRequirements, SignatureOptions::default()).await?;
//! ```
//!
//! The `None` that `sigv4_verify` took was the allowed clock mismatch; it now lives on
//! [`SignatureOptions`][crate::SignatureOptions] with the rest of the verification settings. What
//! comes back is the request parts, the body that had to be read to hash it, and a
//! [`SigV4AuthenticatorResponse`][crate::auth::SigV4AuthenticatorResponse] carrying the
//! authenticated principal and the session's policies.
//!
//! ### Compile-time key type checking
//! In 0.10, keys of different types were all stored as the `SigningKey` type with a discriminator,
//! `SigningKeyKind`, indicating the underlying key type at runtime. This made it impossible to
//! use compile-time checks to ensure that the correct key type was used.
//!
//! The `SigningKey` type has been replaced with a distinct key type for each key type:
//! * [`KSecretKey`][crate::KSecretKey]: The raw secret key prefixed with `"AWS4"`.
//! * [`KDateKey`][crate::KDateKey]: Key derived from `KSecretKey` and the current UTC date.
//! * [`KRegionKey`][crate::KRegionKey]: Key derived from `KDateKey` and the region.
//! * [`KServiceKey`][crate::KServiceKey]: Key derived from `KRegionKey` and the service.
//! * [`KSigningKey`][crate::KSigningKey]: Key derived from `KServiceKey` and the string
//!   "aws4_request".
//!
//! The derived key types have fixed sizes. [`KSecretKey`][crate::KSecretKey] holds the secret
//! key (including the `"AWS4"` prefix) in a heap allocation that is zeroized on drop; AWS-issued
//! secret keys are 40 characters long. With the discriminator gone, so is the
//! `InvalidSigningKeyKind` error it used to produce.
//!
//! ### Signing key functions changed
//! Previously, `get_signing_key_fn()` was used to convert a function into a
//! [Tower `Service`][tower::Service] that could be used to get signing keys. This is now called
//! [`service_for_signing_key_fn()`][crate::service_for_signing_key_fn].
//!
//! In addition, the signature of the function passed in has changed. Previously, parameters to
//! the function were broken out separately:
//! ```ignore
//! async fn get_signing_key(
//!    kind: SigningKeyKind,
//!    access_key: String,
//!    session_token: Option<String>,
//!    request_date: DateTime<Utc>,
//!    region: String,
//!    service: String)
//! -> Result<(PrincipalActor, SigningKey), SignatureError>
//! ```
//!
//! These parameters are now encapsulated in the (non-exhaustive)
//! [`GetSigningKeyRequest`][crate::GetSigningKeyRequest] type, and the tuple of
//! `(PrincipalActor, SigningKey)` is now encapsulated in the
//! [`GetSigningKeyResponse`][crate::GetSigningKeyResponse] type. The function signature is now:
//! ```
//! # use scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, SignatureError};
//! async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError>
//! # { Err(scratchstack_aws_signature::internal_service_error!("not implemented")) }
//! ```
//!
//! The error type is [`SignatureError`][crate::SignatureError], as it was in 0.10. Version 0.11
//! typed these entry points against `tower::BoxError` and made callers downcast to find out what
//! had gone wrong; 0.12 undoes that. `From<Box<dyn Error + Send + Sync>>` is implemented and
//! recovers a boxed `SignatureError` rather than burying it, so a service written against 0.11
//! can be adapted with `.map_err(SignatureError::from)`.
//!
//! ### Signing key requests and responses are built, not tupled
//! Both types are immutable and constructed through [`bon`] builders. Fields that are not
//! required gain `maybe_`-prefixed setters taking an `Option`, and `.build()` does not return a
//! `Result`:
//!
//! ```
//! # use chrono::{NaiveDate, Utc};
//! # use scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SessionPolicies};
//! # use scratchstack_core::RequestId;
//! # use std::str::FromStr;
//! # let user = scratchstack_aws_principal::User::builder()
//! #     .partition("aws").account_id("123456789012").path("/").user_name("u").build().unwrap();
//! # let key = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap()
//! #     .to_ksigning(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap(), "us-east-1", "example");
//! # let token: Option<String> = None;
//! let response = GetSigningKeyResponse::builder()
//!     .principal(user)
//!     .signing_key(key)
//!     .session_policies(SessionPolicies::UNRESTRICTED)
//!     .build();
//!
//! let request = GetSigningKeyRequest::builder()
//!     .access_key("AKIAIOSFODNN7EXAMPLE")
//!     .maybe_session_token(token)
//!     .request_date(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap())
//!     .region("us-east-1")
//!     .service("example")
//!     .request_id(RequestId::new())
//!     .server_timestamp(Utc::now())
//!     .build();
//! ```
//!
//! ### Requests carry a request id
//! [`GetSigningKeyRequest`][crate::GetSigningKeyRequest] has a required `request_id` field, so
//! that a signing-key provider can tag its logs with the request being served and errors can
//! carry the id back out. [`sigv4_validate_request`][crate::sigv4_validate_request] takes it from
//! the [`RequestId`][scratchstack_core::RequestId] extension on the incoming request, generating
//! one if the extension is absent.
//!
//! ### Requests carry the server timestamp
//! [`GetSigningKeyRequest`][crate::GetSigningKeyRequest] also has a required `server_timestamp`
//! field: the `server_timestamp` given to the validation entry point. It is the clock every
//! time-bound check in a provider should use -- session-token expiry, key acceptance windows --
//! so that one request is validated against one notion of "now" rather than several clocks read
//! at different moments. 0.10 passed only the request date, and a provider that needed the
//! current time read it itself.
//!
//! ### Session policies must be enforced
//! This is the one change the compiler will not catch. A signing-key provider that recognizes
//! temporary credentials returns [`SessionPolicies`][crate::SessionPolicies] on
//! [`GetSigningKeyResponse`][crate::GetSigningKeyResponse], and they reach the service as
//! [`SigV4AuthenticatorResponse::session_policies`][crate::auth::SigV4AuthenticatorResponse::session_policies]
//! (or, under the `axum` feature, as a request extension).
//!
//! These policies are a second gate, intersected with the principal's identity-based policies:
//! this crate authenticates the request but never evaluates them. A service that ignores the
//! field grants a restricted session its role's full permissions. An empty value means the
//! session is unrestricted, which is what long-term credentials should carry -- so the
//! [`GetSigningKeyResponse`][crate::GetSigningKeyResponse] builder requires the field, and a
//! provider passes [`SessionPolicies::UNRESTRICTED`][crate::SessionPolicies::UNRESTRICTED] for
//! them. Leaving it out is a compile error rather than a silently unrestricted session.
//!
//! ### `SignatureError` is rebuilt around AWS error codes
//! 0.10 named its variants after the failure and gave each a `message`, `header`, or `parameter`
//! field: `InvalidSignature`, `MalformedSignature`, `MalformedParameter`, `MissingHeader`,
//! `TimestampOutOfRange`, `UnknownAccessKey`. Variants are now named for the AWS error code the
//! failure renders as, so `UnknownAccessKey` is `InvalidClientTokenId`, `MissingHeader` is
//! `MissingRequiredHeader`, `MalformedParameter` is `MalformedQueryString`, and the signature and
//! timestamp variants collapse into `IncompleteSignature` and `SignatureDoesNotMatch`. Each
//! variant knows its [`error_code`][crate::SignatureError::error_code] and
//! [`http_status`][crate::SignatureError::http_status], so an error can be rendered as an AWS
//! response without a match arm per variant.
//!
//! Each variant is a newtype over a payload struct holding the message plus an optional request
//! id, rather than a struct variant with named fields. Construction from a message stays a
//! one-liner, because every payload struct implements `From<String>` and `From<&str>`:
//!
//! ```
//! # use scratchstack_aws_signature::SignatureError;
//! let e = SignatureError::MalformedQueryString("Invalid request query string".into());
//! ```
//!
//! Matching that binds the payload still works, but the binding is now a struct rather than a
//! set of named fields; read the text with `.message` or
//! [`SignatureError::message`][crate::SignatureError::message]. To attach a request id, use the
//! payload builder or [`SignatureError::with_request_id`][crate::SignatureError::with_request_id]:
//!
//! ```
//! # use scratchstack_aws_signature::{MalformedQueryStringError, SignatureError};
//! let e: SignatureError =
//!     MalformedQueryStringError::builder().message("bad query").request_id("abc").build().into();
//! let e = SignatureError::MalformedQueryString("bad query".into()).with_request_id("abc");
//! ```
//!
//! ### `SignatureError::IO` is gone, and internal failures carry no cause
//! The `IO(IOError)` variant has been removed; `From<IOError>` now produces an
//! [`InternalServiceError`][crate::InternalServiceError], a variant 0.10 had no equivalent for.
//! It holds no `Box<dyn Error>` either. Both facts exist to stop service internals reaching a
//! caller: the detail goes to the log and is dropped.
//!
//! Build one with the [`internal_service_error!`][crate::internal_service_error] macro, giving a
//! request id first where one is in hand -- that id is what ties the caller's response back to
//! the logged detail. The macro is the only constructor: `InternalServiceError` has no message
//! field, no builder and no `Default`, so there is nothing to put internal detail into.
//!
//! It is a macro so that the log entry is attributed to the code that failed rather than to a
//! single line inside this crate, which is what `RUST_LOG` filters on.
//!
//! ```
//! # use scratchstack_aws_signature::{internal_service_error, SignatureError};
//! # let query = "SELECT 1";
//! # let request_id = "11111111-2222-3333-4444-555555555555";
//! // The query text is logged, never returned.
//! let e: SignatureError = internal_service_error!(request_id; "Database query failed: {query}");
//! assert_eq!(e.to_string(), "Internal Service Error");
//! ```
//!
//! ### Required signed headers are a parameter
//! 0.10 checked the signature over whatever `SignedHeaders` named. A service can now demand that
//! particular headers be signed -- so a caller cannot leave one out and have it ignored -- by
//! passing an implementation of
//! [`SignedHeaderRequirements`][crate::SignedHeaderRequirements] to the validation entry point.
//! [`NoSignedHeaderRequirements`][crate::NoSignedHeaderRequirements] is the 0.10 behavior;
//! [`ConstSignedHeaderRequirements`][crate::ConstSignedHeaderRequirements],
//! [`SliceSignedHeaderRequirements`][crate::SliceSignedHeaderRequirements] and
//! [`VecSignedHeaderRequirements`][crate::VecSignedHeaderRequirements] cover a fixed or computed
//! list.
//!
//! ```
//! # use scratchstack_aws_signature::NoSignedHeaderRequirements;
//! let signed_headers = NoSignedHeaderRequirements;
//! ```
//!
//! ### `SignatureOptions` collects the verification settings
//! 0.10's `allowed_mismatch: Option<Duration>` parameter is now
//! [`SignatureOptions::allowed_mismatch`][crate::SignatureOptions::allowed_mismatch], alongside
//! [`s3`][crate::SignatureOptions::s3], `url_encode_form`, and
//! [`max_body_size`][crate::SignatureOptions::max_body_size]. `None` meant "skip the timestamp
//! check"; the field is a plain `Duration` defaulting to fifteen minutes, and
//! [`with_any_timestamp`][crate::SignatureOptions::with_any_timestamp] is what waives the check.
//!
//! The struct is `#[non_exhaustive]`, so that adding an option stays a non-breaking change:
//! struct literals do not compile outside this crate. Use the builder, or one of the associated
//! constants for the two common service shapes. The fields stay public for reading.
//!
//! ```
//! # use chrono::Duration;
//! # use scratchstack_aws_signature::SignatureOptions;
//! let options = SignatureOptions::S3;
//! let options = SignatureOptions::URL_ENCODE_FORM;
//! let options = SignatureOptions::builder().s3(true).allowed_mismatch(Duration::minutes(5)).build();
//! ```
//!
//! ### Presigned URLs honor `X-Amz-Expires`
//! A presigned URL is now accepted for `X-Amz-Expires` seconds after its `X-Amz-Date`, in place
//! of the `allowed_mismatch` window around the server time that ordinary requests get. In 0.10 it
//! was that window -- so a URL signed for one minute stayed good for fifteen, and one signed for
//! a day went bad after fifteen minutes. An `X-Amz-Expires` that is not a whole number of seconds
//! from 0 to 604800 is refused with
//! [`AuthorizationQueryParametersError`][crate::AuthorizationQueryParametersError]. Note that
//! [`with_any_timestamp`][crate::SignatureOptions::with_any_timestamp] does not disable this
//! bound.
//!
//! ### Request bodies are bounded
//! 0.10 took a body the caller had already read. [`sigv4_validate_request`][crate::sigv4_validate_request]
//! reads it instead, and reads at most
//! [`SignatureOptions::max_body_size`][crate::SignatureOptions::max_body_size] bytes -- 10 MiB by
//! default -- refusing anything larger with
//! [`RequestEntityTooLarge`][crate::SignatureError::RequestEntityTooLarge] (HTTP 413). The body
//! has to be buffered before the signature can be checked, so without a bound an unauthenticated
//! caller could make the service buffer as much as it liked. Services that accept larger uploads
//! should raise the bound or validate them through
//! [`sigv4_validate_streaming_headers`][crate::sigv4_validate_streaming_headers].
//!
//! To carry the bound, [`IntoRequestBytes::into_request_bytes`][crate::IntoRequestBytes::into_request_bytes]
//! takes a `max_size` argument; an implementation for a body type of your own must stop
//! reading at that size and return [`too_large()`][crate::too_large].
//!
//! ### `UNSIGNED-PAYLOAD` is honored for S3 only, and the token header must be signed
//! 0.10 hashed the body whatever `x-amz-content-sha256` said. The `UNSIGNED-PAYLOAD` marker is now
//! honored, leaving the body out of the signature, but only with
//! [`SignatureOptions::s3`][crate::SignatureOptions::s3] set and only when the header is itself in
//! `SignedHeaders`; for other services the body is still always hashed, as AWS does, and
//! [`sigv4_validate_streaming_headers`][crate::sigv4_validate_streaming_headers] -- which has no
//! body to hash -- refuses a marker passed as the body hash outright. Under S3 rules an
//! `x-amz-security-token` header must likewise be signed. Both are refused with
//! `SignatureDoesNotMatch`. AWS SDKs sign both headers already, so conforming clients see no
//! change.
//!
//! ### Principal types updated
//! This crate uses the [`Principal`][scratchstack_aws_principal::Principal] type from
//! [`scratchstack_aws_principal`]. Previously, the `PrincipalActor` type from v0.3 of that crate
//! was used. Only actor principals are supported now; v0.3 attempted to support both actor and
//! policy principals, but this was riddled with implementation errors.
//!
//! ### Type-dependencies from other crates exposed
//! This crate uses types from two other crates in its APIs: [`scratchstack_aws_principal`] and
//! [`scratchstack_core`]. To reduce the possibility of accidentally using a different version
//! of these crates, they are re-exported here under `principal` and `core` modules, respectively.
//! HTTP types come from `scratchstack_core::http`, which re-exports the `http` crate, so
//! `http::Request` and `scratchstack_core::http::Request` are the same type and either import
//! works.
//!
//! ### Feature flags
//! 0.10 had no feature flags. 0.12 has four, two of them on by default:
//! * `axum` (enabled by default): the `AwsSigV4VerifierLayer` Tower layer, which runs
//!   validation as middleware and attaches the principal, session data, and session policies to
//!   the request as extensions.
//! * `default_session_token` (enabled by default): `PostcardSessionTokenExtractor`,
//!   an encrypted session token format for services issuing their own temporary credentials.
//! * `sensitive-logging` (off by default): compiles in trace records that carry request material
//!   (canonical requests with their headers and query parameters) for debugging signature
//!   mismatches. This gates only this crate's records; see the crate documentation.
//! * `unstable` (off by default): exposes internals such as
//!   [`canonical::normalize_uri_path_component`][crate::canonical::normalize_uri_path_component],
//!   which are not needed for normal use.
//!
//! Turning `axum` and `default_session_token` off with `default-features = false` narrows the
//! crate to roughly the surface 0.10 covered. It does not restore the 0.10 *API*: every change
//! above applies whatever the features.
//!
//! ### Session tokens
//! 0.10 passed `session_token: Option<String>` to the signing-key function and left the rest to
//! the caller. Under `default_session_token` the crate ships a format for it, and
//! `PostcardSessionTokenExtractor` rejects a token whose `expires_at` is not later than the
//! request's `server_timestamp` with [`ExpiredTokenError`][crate::ExpiredTokenError] -- the
//! signing-key provider is not asked. A custom
//! [`ExtractSessionToken`][crate::ExtractSessionToken] implementation must make the same check;
//! providers do not repeat it.
//!
//! ### Streaming validation
//! [`sigv4_validate_streaming_headers`][crate::sigv4_validate_streaming_headers] validates a
//! request's headers against a body hash before the body arrives -- for answering
//! `Expect: 100-continue`, or for S3-style `aws-chunked` uploads -- and returns a
//! [`StreamingSignatureState`][crate::StreamingSignatureState] that validates each subsequent
//! chunk. A chunk that fails poisons the state, so every later chunk fails too. This is additive;
//! 0.10 had no equivalent.
