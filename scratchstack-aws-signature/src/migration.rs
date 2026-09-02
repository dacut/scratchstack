//! # Migration guides
//!
//! * [Migrating from 0.11 to 0.12](#migrating-from-011-to-012)
//! * [Migrating from 0.10 to 0.11](#migrating-from-010-to-011)
//!
//! # Migrating from 0.11 to 0.12
//!
//! Version 0.12 replaces the crate's error plumbing, moves its builders to [`bon`], and adds
//! server-side machinery that 0.11 left to the caller: an Axum layer, session tokens, session
//! policies, and streaming-body validation.
//!
//! Most of the work in migrating is mechanical, and the compiler will find nearly all of it. The
//! exception is [session policies](#session-policies-must-be-enforced), which compiles cleanly
//! while quietly not enforcing anything.
//!
//! ## Changes
//!
//! ### `SignatureError` replaces `BoxError`
//! In 0.11 the validation entry points and the signing-key service were typed against
//! `tower::BoxError`, so a caller had to downcast to find out what had gone wrong. In 0.12 they
//! use [`SignatureError`][crate::SignatureError] directly:
//!
//! ```ignore
//! // 0.11
//! async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError>;
//! let (parts, body, auth) = sigv4_validate_request(/* ... */).await?; // Err = BoxError
//! ```
//!
//! ```
//! # use scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, SignatureError};
//! // 0.12
//! async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError>
//! # { Err(scratchstack_aws_signature::internal_service_error!("not implemented")) }
//! ```
//!
//! `From<Box<dyn Error + Send + Sync>>` is still implemented, and recovers a `SignatureError`
//! that was boxed rather than burying it, so an existing `BoxError`-based service can be adapted
//! with `.map_err(SignatureError::from)`.
//!
//! ### Each `SignatureError` variant wraps a struct
//! Variants held a bare `String` in 0.11; each now holds a struct carrying that message plus an
//! optional request id. Construction from a message is unchanged, because every payload struct
//! implements `From<String>` and `From<&str>`:
//!
//! ```
//! # use scratchstack_aws_signature::SignatureError;
//! let e = SignatureError::MalformedQueryString("Invalid request query string".into());
//! ```
//!
//! Matching that binds the payload still works, but the binding is now a struct rather than a
//! `String`; read the text with `.message` or [`SignatureError::message`][crate::SignatureError::message].
//! To attach a request id, use the payload builder or
//! [`SignatureError::with_request_id`][crate::SignatureError::with_request_id]:
//!
//! ```
//! # use scratchstack_aws_signature::{MalformedQueryStringError, SignatureError};
//! let e: SignatureError =
//!     MalformedQueryStringError::builder().message("bad query").request_id("abc").build().into();
//! let e = SignatureError::MalformedQueryString("bad query".into()).with_request_id("abc");
//! ```
//!
//! ### `SignatureError::IO` is gone, and internal failures no longer carry a cause
//! The `IO(IOError)` variant has been removed; `From<IOError>` now produces an internal failure.
//! `InternalServiceError` no longer holds a `Box<dyn Error>` either. Both changes exist to stop
//! service internals reaching a caller: the detail goes to the log and is dropped.
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
//! ### Builders moved from `derive_builder` to `bon`
//! `.build()` no longer returns a `Result`, so calls that ended in `.build()?` or
//! `.build().unwrap()` drop the suffix. Optional fields gain `maybe_`-prefixed setters that take
//! an `Option`:
//!
//! ```ignore
//! // 0.11
//! GetSigningKeyResponse::builder().principal(user).signing_key(key).build()?
//! ```
//!
//! ```
//! # use chrono::{NaiveDate, Utc};
//! # use scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey};
//! # use scratchstack_core::RequestId;
//! # use std::str::FromStr;
//! # let user = scratchstack_aws_principal::User::builder()
//! #     .partition("aws").account_id("123456789012").path("/").user_name("u").build().unwrap();
//! # let key = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap()
//! #     .to_ksigning(NaiveDate::from_ymd_opt(2021, 1, 1).unwrap(), "us-east-1", "example");
//! # let token: Option<String> = None;
//! // 0.12
//! let response = GetSigningKeyResponse::builder().principal(user).signing_key(key).build();
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
//! at different moments. [`ExtractSessionTokenRequest`][crate::ExtractSessionTokenRequest] and
//! `GetSessionTokenEncryptionKeyRequest` carry it onward for the same reason.
//!
//! ### Session-token expiry is enforced
//! `PostcardSessionTokenExtractor` rejects a token whose `expires_at` is not later than the
//! request's `server_timestamp` with [`ExpiredTokenError`][crate::ExpiredTokenError]. It used
//! to return the token's data regardless and leave the comparison to the signing-key provider,
//! and a provider that did not make it accepted expired temporary credentials for as long as
//! the encryption key was still on file. A custom
//! [`ExtractSessionToken`][crate::ExtractSessionToken] implementation must make the same check;
//! providers no longer repeat it.
//!
//! ### `NO_ADDITIONAL_SIGNED_HEADERS` became a type
//! The constant is replaced by [`NoSignedHeaderRequirements`][crate::NoSignedHeaderRequirements],
//! a unit struct implementing [`SignedHeaderRequirements`][crate::SignedHeaderRequirements]:
//!
//! ```ignore
//! let signed_headers = NO_ADDITIONAL_SIGNED_HEADERS; // 0.11
//! ```
//!
//! ```
//! # use scratchstack_aws_signature::NoSignedHeaderRequirements;
//! let signed_headers = NoSignedHeaderRequirements; // 0.12
//! ```
//!
//! ### `SignatureOptions` is `#[non_exhaustive]`
//! Struct literals no longer compile outside this crate, so that adding an option stays a
//! non-breaking change. Use the builder, or one of the associated constants for the two common
//! service shapes:
//!
//! ```ignore
//! // 0.11
//! let options = SignatureOptions { s3: true, url_encode_form: false, ..Default::default() };
//! ```
//!
//! ```
//! # use chrono::Duration;
//! # use scratchstack_aws_signature::SignatureOptions;
//! // 0.12
//! let options = SignatureOptions::S3;
//! let options = SignatureOptions::URL_ENCODE_FORM;
//! let options = SignatureOptions::builder().s3(true).allowed_mismatch(Duration::minutes(5)).build();
//! ```
//!
//! The fields stay public for reading. `SignatureOptions::url_encode_form()` is deprecated in
//! favour of the [`URL_ENCODE_FORM`][crate::SignatureOptions::URL_ENCODE_FORM] constant.
//!
//! ### Session policies must be enforced
//! This is the one change the compiler will not catch. A signing-key provider that recognizes
//! temporary credentials now returns [`SessionPolicies`][crate::SessionPolicies] on
//! [`GetSigningKeyResponse`][crate::GetSigningKeyResponse], and they reach the service as
//! [`SigV4AuthenticatorResponse::session_policies`][crate::auth::SigV4AuthenticatorResponse::session_policies]
//! (or, under the `axum` feature, as a request extension).
//!
//! These policies are a second gate, intersected with the principal's identity-based policies:
//! this crate authenticates the request but never evaluates them. A service that ignores the
//! field grants a restricted session its role's full permissions. The default value is empty,
//! which means the session is unrestricted -- so long-term credentials behave as they did in
//! 0.11.
//!
//! ### `scratchstack_errors` became `scratchstack_core`
//! The `errors` re-export is gone; [`scratchstack_core`] is re-exported as `core` alongside
//! `principal`. HTTP types come from `scratchstack_core::http`, which re-exports the `http`
//! crate, so `http::Request` and `scratchstack_core::http::Request` are the same type and either
//! import works.
//!
//! ### New feature flags
//! 0.11 had one feature flag, `unstable`. 0.12 adds two, both enabled by default:
//! * `axum`: the `AwsSigV4VerifierLayer` Tower layer, which runs
//!   validation as middleware and attaches the principal, session data, and session policies to
//!   the request as extensions.
//! * `default_session_token`: `PostcardSessionTokenExtractor`,
//!   an encrypted session token format for services issuing their own temporary credentials.
//!
//! Turning both off with `default-features = false` narrows the crate to roughly the surface
//! 0.11 had. It does not restore the 0.11 *API*: every change above -- the error type, the bon
//! builders, the request ids, `NoSignedHeaderRequirements` -- applies whatever the features.
//!
//! ### Streaming validation
//! [`sigv4_validate_streaming_headers`][crate::sigv4_validate_streaming_headers] validates a
//! request's headers against a body hash before the body arrives -- for answering
//! `Expect: 100-continue`, or for S3-style `aws-chunked` uploads -- and returns a
//! [`StreamingSignatureState`][crate::StreamingSignatureState] that validates each subsequent
//! chunk. This is additive; nothing in 0.11 needs to change to use it.
//!
//! # Migrating from 0.10 to 0.11
//!
//! Version 0.11 brings significant changes to the scratchstack-aws-signature crate. These changes
//! are intended to make the crate more ergonomic (easier for consumers to use) and more efficient
//! (less copying of data).
//!
//! Unfortunately, this means that the 0.11 version is not backwards compatible with the 0.10
//! version.
//!
//! ## Changes
//!
//! ### Elimination of `Request` type
//! The main change is the elimination of the `scratchstack_aws_signature::Request` type. Instead,
//! `http::Request` is used directly and there is no longer a need to copy data from one `Request`
//! type to the other.
//!
//! With this, there is also no need to use the
//! [`GetSigningKeyRequest`][crate::GetSigningKeyRequest] type in the
//! validation code. (This type is used to pass get signing key requests.)
//!
//! This sample code from 0.10:
//! ```ignore
//! let http_req = http::Request::get("https://example.com").body(())?;
//! let sig_req = scratchstack_aws_signature::Request::from_http_request_parts(
//!     &http_req.into_parts().0, None);
//! let gsk_req = sig_req.to_get_signing_request(SigningKeyKind::KSigning, REGION, SERVICE)?;
//! let (principal, signing_key) = get_signing_key_service.call(gsk_req).await?;
//! sig4_verify(&sig_req, &signing_key, None, REGION, SERVICE)?;
//! ```
//!
//! Would be written in 0.11:
//! ```ignore
//! let http_req = http::Request::get("https://example.com").body(())?;
//! let (parts, body, auth) = sigv4_validate_request(
//!     http_req, &REGION, &SERVICE, &mut get_signing_key_service, Utc::now(),
//!     &NO_ADDITIONAL_SIGNED_HEADERS, SignatureOptions::default()).await?;
//! ```
//!
//! ### Compile-time key type checking
//! In 0.10, keys of different types were all stored as the `SigningKey` type with a discriminator,
//! `SigningKeyKind`, indicating the underlying key type at runtime. This made it impossible to
//! use compile-time checks to ensure that the correct key type was used.
//!
//! In 0.11, the `SigningKey` type has been replaced with a distinct key type for each key type:
//! * [`KSecretKey`][crate::KSecretKey]: The raw secret key prefixed with `"AWS4"`.
//! * [`KDateKey`][crate::KDateKey]: Key derived from `KSecretKey` and the current UTC date.
//! * [`KRegionKey`][crate::KRegionKey]: Key derived from `KDateKey` and the region.
//! * [`KServiceKey`][crate::KServiceKey]: Key derived from `KRegionKey` and the service.
//! * [`KSigningKey`][crate::KSigningKey]: Key derived from `KServiceKey` and the string
//!   "aws4_request".
//!
//! The derived key types have fixed sizes. [`KSecretKey`][crate::KSecretKey] holds the secret
//! key (including the `"AWS4"` prefix) in a heap allocation that is zeroized on drop; AWS-issued
//! secret keys are 40 characters long.
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
//! # use scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse};
//! use tower::BoxError;
//!
//! async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError>
//! # {
//! # Err("not implemented".into())
//! # }
//! ```
//!
//! Both of these types have builder APIs to construct them.
//!
//! ### Principal types updated
//! This crate uses the [`Principal`][scratchstack_aws_principal::Principal] type from
//! scratchstack_aws_principal v0.4. Previously, the `PrincipalActor` from v0.3 of that crate was
//! used. In v0.4, only actor principals are supported; v0.3 attempted to support both actor and
//! policy principals, but this was riddled with implementation errors.
//!
//! ### Type-dependencies from other crates exposed
//! This crate now uses types from two other crates in its APIs: [`scratchstack_aws_principal`] and
//! [`scratchstack_core`]. To reduce the possibility of accidentally using a different version
//! of these crates, they are re-exported here under `principal` and `core` modules, respectively.

use std::str::FromStr;
