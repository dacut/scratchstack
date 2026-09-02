//! AWS API request signatures verification routines.
//!
//! This implements the AWS [SigV4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
//! and [SigV4S3](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
//! server-side validation algorithms.
//!
//! **Stability of this module is not guaranteed except for items exposed at the crate root**.
//! The functions and types are subject to change in minor/patch versions. This is exposed for
//! testing purposes only.

use {
    crate::{
        GetSigningKeyRequest, GetSigningKeyResponse, IncompleteSignatureError, KSigningKey, SessionPolicies,
        SignatureDoesNotMatchError, SignatureError, constants::*, crypto::hmac_sha256,
    },
    bon::Builder,
    chrono::{DateTime, Duration, Utc},
    qualifier_attr::qualifiers,
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::RequestId,
    std::{
        fmt::{Debug, Formatter, Result as FmtResult},
        future::Future,
    },
    subtle::ConstantTimeEq,
    tower::{Service, ServiceExt},
};

/// Low-level structure for performing AWS SigV4 authentication after a canonical request has been generated.
#[derive(Builder, Clone, Default)]
#[cfg_attr(doc, doc(cfg(feature = "unstable")))]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
#[builder(derive(Debug))]
pub struct SigV4Authenticator {
    /// The SHA-256 hash of the canonical request.
    canonical_request_sha256: [u8; SHA256_OUTPUT_LEN],

    /// The credential passed into the request, in the form of `keyid/date/region/service/aws4_request`.
    /// The date must reflect that of the request timestamp in `YYYYMMDD` format, not the server's
    /// date. Timestamp validation is performed separately.
    pub(crate) credential: String,

    /// The optional session token.
    #[builder(into)]
    session_token: Option<String>,

    /// The signature passed into the request.
    pub(crate) signature: String,

    /// The timestamp of the request, from either `X-Amz-Date` query string/header or the `Date` header.
    pub(crate) request_timestamp: DateTime<Utc>,
}

impl SigV4Authenticator {
    /// Retrieve the SHA-256 hash of the canonical request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn canonical_request_sha256(&self) -> [u8; SHA256_OUTPUT_LEN] {
        self.canonical_request_sha256
    }

    /// Retrieve the credential passed into the request, in the form of `keyid/date/region/service/aws4_request`.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn credential(&self) -> &str {
        &self.credential
    }

    /// Retrieve the optional session token.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }

    /// Retrieve the signature passed into the request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn signature(&self) -> &str {
        &self.signature
    }

    /// Retrieve the timestamp of the request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn request_timestamp(&self) -> DateTime<Utc> {
        self.request_timestamp
    }

    /// Verify the request parameters make sense for the region, service, and specified timestamp.
    /// This must be called successfully before calling [validate_signature][Self::validate_signature].
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    pub fn prevalidate(
        &self,
        region: &str,
        service: &str,
        server_timestamp: DateTime<Utc>,
        allowed_mismatch: Duration,
        request_id: RequestId,
    ) -> Result<(), SignatureError> {
        let req_ts = self.request_timestamp();
        let min_ts = server_timestamp.checked_sub_signed(allowed_mismatch).unwrap_or(DateTime::<Utc>::MIN_UTC);
        let max_ts = server_timestamp.checked_add_signed(allowed_mismatch).unwrap_or(DateTime::<Utc>::MAX_UTC);

        // Rule 10: Make sure date isn't expired...
        if req_ts < min_ts {
            return Err(SignatureDoesNotMatchError::builder()
                .message(format!(
                    "Signature expired: {} is now earlier than {} ({} - {}.)",
                    req_ts.format(ISO8601_COMPACT_FORMAT),
                    min_ts.format(ISO8601_COMPACT_FORMAT),
                    server_timestamp.format(ISO8601_COMPACT_FORMAT),
                    duration_to_string(allowed_mismatch)
                ))
                .request_id(request_id)
                .build()
                .into());
        }

        // Rule 11: ... or too far into the future.
        if req_ts > max_ts {
            return Err(SignatureDoesNotMatchError::builder()
                .message(format!(
                    "Signature not yet current: {} is still later than {} ({} + {}.)",
                    req_ts.format(ISO8601_COMPACT_FORMAT),
                    max_ts.format(ISO8601_COMPACT_FORMAT),
                    server_timestamp.format(ISO8601_COMPACT_FORMAT),
                    duration_to_string(allowed_mismatch)
                ))
                .request_id(request_id)
                .build()
                .into());
        }

        // Rule 12: Credential scope must have exactly five elements.
        let credential_parts = self.credential().split('/').collect::<Vec<&str>>();
        if credential_parts.len() != 5 {
            return Err(IncompleteSignatureError::builder()
                .message(format!("{} got '{}'", MSG_CREDENTIAL_MUST_HAVE_FIVE_PARTS, self.credential()))
                .request_id(request_id)
                .build()
                .into());
        }

        let cscope_date = credential_parts[1];
        let cscope_region = credential_parts[2];
        let cscope_service = credential_parts[3];
        let cscope_term = credential_parts[4];

        // Rule 13: Credential scope must be correct for the region/service/date.
        let mut cscope_errors = Vec::new();
        if cscope_region != region {
            cscope_errors.push(format!("Credential should be scoped to a valid region, not '{}'.", cscope_region));
        }

        if cscope_service != service {
            cscope_errors.push(format!("Credential should be scoped to correct service: '{}'.", service));
        }

        if cscope_term != AWS4_REQUEST {
            cscope_errors.push(format!(
                "Credential should be scoped with a valid terminator: 'aws4_request', not '{}'.",
                cscope_term
            ));
        }

        let expected_cscope_date = req_ts.format(ISO8601_DATE_FORMAT).to_string();
        if cscope_date != expected_cscope_date {
            cscope_errors.push(format!("Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: '{}' != '{}', from '{}'.", cscope_date, expected_cscope_date, req_ts.format(ISO8601_COMPACT_FORMAT)));
        }

        if !cscope_errors.is_empty() {
            return Err(SignatureDoesNotMatchError::builder()
                .message(cscope_errors.join(" "))
                .request_id(request_id)
                .build()
                .into());
        }

        Ok(())
    }

    /// Return the signing key (`kSigning` from the [AWS documentation](https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html))
    /// for the request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    async fn get_signing_key<S, F>(
        &self,
        region: &str,
        service: &str,
        get_signing_key: &mut S,
        request_id: RequestId,
    ) -> Result<GetSigningKeyResponse, SignatureError>
    where
        S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = SignatureError, Future = F> + Send,
        F: Future<Output = Result<GetSigningKeyResponse, SignatureError>> + Send,
    {
        let access_key = self.credential().split('/').next().expect("prevalidate must been called first").to_string();

        let req = GetSigningKeyRequest::builder()
            .access_key(access_key)
            .maybe_session_token(self.session_token())
            .request_date(self.request_timestamp().date_naive())
            .region(region)
            .service(service)
            .request_id(request_id)
            .build();

        get_signing_key.oneshot(req).await
    }

    /// Return the string to sign for the request.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn get_string_to_sign(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            AWS4_HMAC_SHA256.len() + 1 + ISO8601_UTC_LENGTH + 1 + self.credential().len() + 1 + SHA256_HEX_LENGTH,
        );
        let hashed_canonical_request = hex::encode(self.canonical_request_sha256());

        // Remove the access key from the credential to get the credential scope. This requires that prevalidate() has
        // been called.
        let cscope = self.credential().split_once('/').map(|x| x.1).expect("prevalidate should have been called first");

        result.extend(AWS4_HMAC_SHA256.as_bytes());
        result.push(b'\n');
        result.extend(self.request_timestamp().format(ISO8601_COMPACT_FORMAT).to_string().as_bytes());
        result.push(b'\n');
        result.extend(cscope.as_bytes());
        result.push(b'\n');
        result.extend(hashed_canonical_request.as_bytes());
        result
    }

    /// Validate the request signature.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    pub async fn validate_signature<S, F>(
        &self,
        region: &str,
        service: &str,
        server_timestamp: DateTime<Utc>,
        allowed_mismatch: Duration,
        get_signing_key: &mut S,
        request_id: RequestId,
    ) -> Result<SigV4AuthenticatorResponse, SignatureError>
    where
        S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = SignatureError, Future = F> + Send,
        F: Future<Output = Result<GetSigningKeyResponse, SignatureError>> + Send,
    {
        self.prevalidate(region, service, server_timestamp, allowed_mismatch, request_id)?;
        let string_to_sign = self.get_string_to_sign();
        let response = self.get_signing_key(region, service, get_signing_key, request_id).await?;
        let expected_signature = hex::encode(hmac_sha256(response.signing_key().as_ref(), string_to_sign.as_ref()));
        let expected_signature_bytes = expected_signature.as_bytes();
        let signature_bytes = self.signature().as_bytes();
        let is_equal: bool = signature_bytes.ct_eq(expected_signature_bytes).into();
        if !is_equal {
            Err(SignatureDoesNotMatchError::builder()
                .message(MSG_REQUEST_SIGNATURE_MISMATCH)
                .request_id(request_id)
                .build()
                .into())
        } else {
            Ok(response.into())
        }
    }

    /// Validate the request signature against the given signing key response.
    #[cfg_attr(doc, doc(cfg(feature = "unstable")))]
    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    pub fn validate_signature_with_key(
        &self,
        region: &str,
        service: &str,
        server_timestamp: DateTime<Utc>,
        allowed_mismatch: Duration,
        signing_key: &KSigningKey,
        request_id: RequestId,
    ) -> Result<(), SignatureError> {
        self.prevalidate(region, service, server_timestamp, allowed_mismatch, request_id)?;
        let string_to_sign = self.get_string_to_sign();
        let expected_signature = hex::encode(hmac_sha256(signing_key.as_ref(), string_to_sign.as_ref()));
        let expected_signature_bytes = expected_signature.as_bytes();
        let signature_bytes = self.signature().as_bytes();
        let is_equal: bool = signature_bytes.ct_eq(expected_signature_bytes).into();
        if !is_equal {
            Err(SignatureDoesNotMatchError::builder()
                .message(MSG_REQUEST_SIGNATURE_MISMATCH)
                .request_id(request_id)
                .build()
                .into())
        } else {
            Ok(())
        }
    }
}

impl Debug for SigV4Authenticator {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("SigV4Authenticator")
            .field("canonical_request_sha256", &hex::encode(self.canonical_request_sha256()))
            .field("session_token", &self.session_token())
            .field("signature", &self.signature())
            .field("request_timestamp", &self.request_timestamp())
            .finish()
    }
}

/// Upon successful authentication of a signature, this is returned to convey the principal,
/// session data, and possibly policies associated with the request.
///
/// SigV4AuthenticatorResponse structs are immutable. Use [`SigV4AuthenticatorResponseBuilder`] to
/// construct a new response.
#[derive(Builder, Clone, Debug)]
pub struct SigV4AuthenticatorResponse {
    /// The principal actor of the request.
    #[builder(into)]
    principal: Principal,

    /// The session data associated with the principal.
    #[builder(into, default)]
    session_data: SessionData,

    /// The session policies restricting the principal's permissions; empty when the session is
    /// unrestricted.
    #[builder(into, default)]
    session_policies: SessionPolicies,
}

impl SigV4AuthenticatorResponse {
    /// Retrieve the principal actors of the request.
    #[inline]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Retrieve the session data associated with the principal.
    #[inline]
    pub fn session_data(&self) -> &SessionData {
        &self.session_data
    }

    /// Retrieve the session policies restricting the principal's permissions.
    #[inline]
    pub fn session_policies(&self) -> &SessionPolicies {
        &self.session_policies
    }
}

impl From<GetSigningKeyResponse> for SigV4AuthenticatorResponse {
    fn from(request: GetSigningKeyResponse) -> Self {
        SigV4AuthenticatorResponse {
            principal: request.principal,
            session_data: request.session_data,
            session_policies: request.session_policies,
        }
    }
}

fn duration_to_string(duration: Duration) -> String {
    let secs = duration.num_seconds();
    if secs % 60 == 0 {
        format!("{} min", duration.num_minutes())
    } else {
        format!("{} sec", secs)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::duration_to_string,
        crate::{
            ExpiredTokenError, GetSigningKeyRequest, GetSigningKeyResponse, InvalidClientTokenIdError, KSecretKey,
            SignatureError,
            auth::{SigV4Authenticator, SigV4AuthenticatorResponse},
            constants::*,
            service_for_signing_key_fn,
        },
        chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime, Utc},
        log::LevelFilter,
        scratchstack_aws_principal::{Principal, User},
        scratchstack_core::RequestId,
        std::{error::Error, str::FromStr},
    };

    fn init() {
        let _ = env_logger::builder().is_test(true).filter_level(LevelFilter::Trace).try_init();
    }

    #[test]
    fn test_derived() {
        init();
        let epoch = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let test_time = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).unwrap(),
                NaiveTime::from_hms_opt(12, 36, 0).unwrap(),
            ),
            Utc,
        );
        let auth1: SigV4Authenticator = Default::default();
        assert_eq!(
            auth1.canonical_request_sha256().as_slice(),
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        );
        assert!(auth1.credential().is_empty());
        assert!(auth1.session_token().is_none());
        assert!(auth1.signature().is_empty());
        assert_eq!(auth1.request_timestamp(), epoch);

        let sha256: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
            29, 30, 31,
        ];
        let auth2 = SigV4Authenticator::builder()
            .canonical_request_sha256(sha256)
            .credential("AKIA1/20151231/us-east-1/example/aws4_request".to_string())
            .session_token("token".to_string())
            .signature("1234".to_string())
            .request_timestamp(test_time)
            .build();

        assert_eq!(
            auth2.canonical_request_sha256().as_slice(),
            &[
                0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31,
            ]
        );
        assert_eq!(auth2.credential(), "AKIA1/20151231/us-east-1/example/aws4_request");
        assert_eq!(auth2.session_token(), Some("token"));
        assert_eq!(auth2.signature(), "1234");
        assert_eq!(auth2.request_timestamp(), test_time);

        assert_eq!(auth2.credential(), auth2.clone().credential());
        let _ = format!("{:?}", auth2);
    }

    async fn get_signing_key(request: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, SignatureError> {
        if let Some(token) = request.session_token() {
            match token {
                "internal-service-error" | "io-error" => {
                    return Err(SignatureError::internal_service_error_with_request_id(
                        "test internal service error",
                        request.request_id(),
                    ));
                }
                "invalid" => {
                    return Err(InvalidClientTokenIdError::builder()
                        .message(MSG_SECURITY_TOKEN_INVALID)
                        .request_id(request.request_id())
                        .build()
                        .into());
                }
                "expired" => {
                    return Err(ExpiredTokenError::builder().request_id(request.request_id()).build().into());
                }
                _ => (),
            }
        }

        match request.access_key() {
            "AKIDEXAMPLE" => {
                let principal = Principal::from(
                    User::builder()
                        .partition("aws")
                        .account_id("123456789012")
                        .path("/")
                        .user_name("test")
                        .build()
                        .unwrap(),
                );
                let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
                let k_signing = k_secret.to_ksigning(request.request_date(), request.region(), request.service());

                let response = GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build();
                Ok(response)
            }
            _ => Err(InvalidClientTokenIdError::builder().request_id(request.request_id()).build().into()),
        }
    }

    #[tokio::test]
    async fn test_error_ordering() {
        init();

        // Test that the error ordering is correct.
        let creq_sha256: [u8; SHA256_OUTPUT_LEN] = [0; SHA256_OUTPUT_LEN];
        let test_timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).unwrap(),
                NaiveTime::from_hms_opt(12, 36, 0).unwrap(),
            ),
            Utc,
        );
        let outdated_timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).unwrap(),
                NaiveTime::from_hms_opt(12, 20, 59).unwrap(),
            ),
            Utc,
        );
        let future_timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).unwrap(),
                NaiveTime::from_hms_opt(12, 51, 1).unwrap(),
            ),
            Utc,
        );
        let get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        let mismatch = Duration::minutes(15);
        let request_id = RequestId::from_microseconds_and_random(1440964261000000, 0);

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(outdated_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(ref msg) = e {
            assert_eq!(
                msg.message.as_str(),
                "Signature expired: 20150830T122059Z is now earlier than 20150830T122100Z (20150830T123600Z - 15 min.)"
            );
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(future_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(ref msg) = e {
            assert_eq!(
                msg.message.as_str(),
                "Signature not yet current: 20150830T125101Z is still later than 20150830T125100Z (20150830T123600Z + 15 min.)"
            );
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::IncompleteSignature(_) = e {
            assert_eq!(
                e.to_string(),
                "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got 'AKIDFOO/20130101/wrong-region/wrong-service'"
            );
            assert_eq!(e.error_code(), "IncompleteSignature");
            assert_eq!(e.http_status(), 400);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service/aws5_request".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(_) = e {
            assert_eq!(
                e.to_string(),
                "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'example'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'. Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: '20130101' != '20150830', from '20150830T123600Z'."
            );
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("invalid")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::InvalidClientTokenId(_) = e {
            assert_eq!(e.to_string(), "The security token included in the request is invalid");
            assert_eq!(e.error_code(), "InvalidClientTokenId");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::ExpiredToken(_) = e {
            assert_eq!(e.to_string(), "The security token included in the request is expired");
            assert_eq!(e.error_code(), "ExpiredToken");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("internal-service-error")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::InternalServiceError(_) = e {
            // The underlying detail went to the log; only the generic message is carried.
            assert_eq!(e.to_string(), "Internal Service Error");
            assert_eq!(e.error_code(), "InternalFailure");
            assert_eq!(SignatureError::http_status(&e), 500);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("io-error")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::InternalServiceError(_) = e {
            // An I/O failure must not leak the path or the OS error text to the caller.
            assert_eq!(e.to_string(), "Internal Service Error");
            assert_eq!(e.error_code(), "InternalFailure");
            assert_eq!(SignatureError::http_status(&e), 500);
            assert!(e.source().is_none());
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("ok")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::InvalidClientTokenId(_) = e {
            assert_eq!(e.to_string(), "The AWS access key provided does not exist in our records");
            assert_eq!(e.error_code(), "InvalidClientTokenId");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDEXAMPLE/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("ok")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let e = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(_) = e {
            assert_eq!(
                e.to_string(),
                "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details."
            );
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDEXAMPLE/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("ok")
            .signature("88bf1ccb1e3e4df7bb2ed6d89bcd8558d6770845007e1a5c392ac9edce0d5deb".to_string())
            .request_timestamp(test_timestamp)
            .build();

        let _ = auth
            .validate_signature(
                "us-east-1",
                "example",
                test_timestamp,
                mismatch,
                &mut get_signing_key_svc.clone(),
                request_id,
            )
            .await
            .unwrap();
    }

    #[test]
    fn test_duration_formatting() {
        init();
        assert_eq!(duration_to_string(Duration::seconds(32)).as_str(), "32 sec");
        assert_eq!(duration_to_string(Duration::seconds(60)).as_str(), "1 min");
        assert_eq!(duration_to_string(Duration::seconds(61)).as_str(), "61 sec");
        assert_eq!(duration_to_string(Duration::seconds(600)).as_str(), "10 min");
    }

    #[test_log::test]
    fn test_response_builder() {
        let principal = Principal::from(
            User::builder().partition("aws").account_id("123456789012").path("/").user_name("test").build().unwrap(),
        );
        let response = SigV4AuthenticatorResponse::builder().principal(principal).build();
        assert!(response.principal().as_user().is_some());
        assert!(response.session_data().is_empty());

        let response2 = response.clone();
        assert_eq!(format!("{:?}", response), format!("{:?}", response2));
    }
}
