//! Session token data types and utilities
use {
    crate::{KSecretKey, SignatureError},
    ascii_casing::{AsciiString, CaseInsensitive},
    bon::Builder,
    chrono::{DateTime, Utc},
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::{Principal, SessionData},
    scratchstack_core::RequestId,
    serde::{Deserialize, Serialize},
    std::{
        collections::{HashMap, HashSet},
        fmt::{Debug, Formatter, Result as FmtResult},
    },
    tower::Service,
};

/// Data from a session token.
#[derive(Builder, Clone, Debug, Deserialize, Serialize)]
pub struct SessionTokenData {
    /// The ID of the role associated with this session.
    #[builder(into)]
    pub role_id: String,

    /// The access key ID of the session token.
    #[builder(into)]
    pub access_key_id: String,

    /// The secret key of the session token.
    #[builder(into)]
    pub secret_key: KSecretKey,

    /// The principal associated with the session token.
    ///
    /// This is typically an [`AssumedRole`][scratchstack_aws_principal::AssumedRole] or a
    /// [`FederatedUser`][scratchstack_aws_principal::FederatedUser]; in certain use cases, it
    /// may be a [`Service`][scratchstack_aws_principal::Service].
    ///
    /// This should never be a [`RootUser`][scratchstack_aws_principal::RootUser] or a
    /// [`User`][scratchstack_aws_principal::User], as these principals cannot be directly
    /// associated with session tokens. Scratchstack does not enforce this requirement, but it is
    /// recommended to avoid potential security issues and to maintain consistency with AWS's
    /// session token usage.
    #[builder(into)]
    pub principal: Principal,

    /// The expiration time of the session token. An extractor rejects the token with
    /// [`ExpiredTokenError`][crate::ExpiredTokenError] once the server's clock reaches this
    /// instant.
    #[builder(into)]
    pub expires_at: DateTime<Utc>,

    /// The issuing time of the session token.
    #[builder(into)]
    pub issued_at: DateTime<Utc>,

    /// Inline policy associated with the session token.
    #[serde(with = "inline_policy_json")]
    #[builder(into)]
    pub inline_policy: Option<AspenPolicy>,

    /// Managed policy identifiers associated with the session token.
    #[builder(into)]
    pub managed_policy_ids: Vec<String>,

    /// The name of the session.
    #[builder(into)]
    pub role_session_name: String,

    /// Additional metadata associated with the session token.
    #[builder(into)]
    pub metadata: SessionData,

    /// Tags associated with the session token.
    #[builder(into)]
    pub tags: HashMap<AsciiString<CaseInsensitive>, String>,

    /// Keys of the transitive tags associated with the session token. These are tags that will be
    /// passed to any sessions that are assumed by this session.
    #[builder(into)]
    pub transitive_tag_keys: HashSet<AsciiString<CaseInsensitive>>,
}

/// Policies that restrict a session's permissions, carried from the session token into request
/// handling.
///
/// A signing-key provider that recognizes temporary credentials populates this from the
/// [`SessionTokenData`] it extracts; the Axum layer then attaches it to the request as an
/// extension alongside the principal and session data. Services evaluate these policies as an
/// additional gate intersected with the principal's identity-based policies.
///
/// The default value — no inline policy, no managed policy ids — means the session is
/// unrestricted: either the caller used long-term credentials, or no session policies were
/// passed to `sts:AssumeRole`. [`SessionPolicies::UNRESTRICTED`] names that value, so a
/// provider that returns it is seen to have decided rather than to have forgotten.
#[derive(Builder, Clone, Debug, Default)]
pub struct SessionPolicies {
    /// The inline session policy document supplied to `sts:AssumeRole`, if any.
    inline_policy: Option<AspenPolicy>,

    /// Prefixed ("ANPA…") managed policy ids supplied to `sts:AssumeRole` via `PolicyArns`.
    /// These are references: the policy documents are resolved when a request is authorized,
    /// not when the session is created.
    #[builder(into, default)]
    managed_policy_ids: Vec<String>,
}

impl SessionPolicies {
    /// No restriction: the session may do whatever the principal's identity-based policies
    /// allow. This is what long-term credentials get, and what `sts:AssumeRole` produces when it
    /// is passed no session policies.
    pub const UNRESTRICTED: Self = Self {
        inline_policy: None,
        managed_policy_ids: Vec::new(),
    };

    /// Retrieve the inline session policy, if any.
    #[inline]
    pub fn inline_policy(&self) -> Option<&AspenPolicy> {
        self.inline_policy.as_ref()
    }

    /// Indicates whether the session is unrestricted: no inline policy and no managed policy
    /// ids.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inline_policy.is_none() && self.managed_policy_ids.is_empty()
    }

    /// Retrieve the prefixed ("ANPA…") managed policy ids.
    #[inline]
    pub fn managed_policy_ids(&self) -> &[String] {
        &self.managed_policy_ids
    }
}

/// Request for extracting session token data from an opaque session token string.
#[derive(Builder, Clone)]
pub struct ExtractSessionTokenRequest {
    /// The opaque session token string.
    #[builder(into)]
    session_token: String,

    /// The request id for logging and tracing.
    #[builder(into)]
    request_id: RequestId,

    /// The time the server received the request, against which the token's expiry is checked.
    server_timestamp: DateTime<Utc>,
}

impl ExtractSessionTokenRequest {
    /// Returns the opaque session token string to be decoded.
    #[inline(always)]
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    /// Returns the request id for logging and tracing.
    #[inline(always)]
    pub fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the time the server received the request.
    #[inline(always)]
    pub fn server_timestamp(&self) -> DateTime<Utc> {
        self.server_timestamp
    }
}

impl Debug for ExtractSessionTokenRequest {
    /// Formats the request with the session token redacted: the token is bearer-credential
    /// material and must not end up in logs.
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("ExtractSessionTokenRequest")
            .field("session_token", &"<redacted>")
            .field("request_id", &self.request_id)
            .field("server_timestamp", &self.server_timestamp)
            .finish()
    }
}

/// Trait for extracting data from an opaque session token.
///
/// This refines the Tower [`Service`] trait, specifying that the response is expected to be a
/// [`SessionTokenData`] struct and the error is expected to be a [`SignatureError`].
///
/// The format of a session token is not defined by AWS, and Scratchstack itself does not require a
/// specific format. However, the session token must contain enough information to allow the
/// signature validation process to determine the principal associated with the request,
/// the permissions associated with the session, and other relevant metadata (including the
/// expiration time of the session).
///
/// An implementation must reject a token whose expiration time has passed with
/// [`ExpiredTokenError`][crate::ExpiredTokenError], comparing it against the request's
/// [`server_timestamp`][ExtractSessionTokenRequest::server_timestamp] rather than a clock of its
/// own. Signing-key providers rely on this: they do not repeat the check.
///
/// This trait is blanket-implemented for every [`Service`] with the matching request, response,
/// and error types; do not implement it directly.
pub trait ExtractSessionToken:
    Service<ExtractSessionTokenRequest, Response = SessionTokenData, Error = SignatureError>
{
}

impl<T> ExtractSessionToken for T where
    T: Service<ExtractSessionTokenRequest, Response = SessionTokenData, Error = SignatureError>
{
}

/// Serde adapter for [`SessionTokenData::inline_policy`] that carries the policy as its JSON
/// document string. Aspen policies use flexible JSON representations (e.g. element-or-list) that
/// can only be (de)serialized with a self-describing format, so they cannot be embedded directly
/// in non-self-describing formats such as the postcard encoding used for session tokens.
mod inline_policy_json {
    use {
        scratchstack_aspen::Policy as AspenPolicy,
        serde::{Deserialize, Deserializer, Serializer, de::Error as _},
        std::str::FromStr as _,
    };

    pub(super) fn serialize<S: Serializer>(policy: &Option<AspenPolicy>, serializer: S) -> Result<S::Ok, S::Error> {
        match policy {
            None => serializer.serialize_none(),
            Some(policy) => serializer.serialize_some(&policy.to_string()),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<AspenPolicy>, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            None => Ok(None),
            Some(policy) => AspenPolicy::from_str(&policy).map(Some).map_err(D::Error::custom),
        }
    }
}

#[cfg(feature = "default_session_token")]
mod default_session_token;

#[cfg(feature = "default_session_token")]
pub use default_session_token::*;

#[cfg(test)]
mod tests {
    use {super::ExtractSessionTokenRequest, chrono::DateTime, scratchstack_core::RequestId};

    /// `ExtractSessionToken` is a public extension point, so an implementation living outside this
    /// crate has to be able to read the request it is handed. These accessors are the only way to
    /// do that -- the fields are private.
    #[test_log::test]
    fn extract_session_token_request_is_readable() {
        let request_id = RequestId::new();
        let server_timestamp = DateTime::from_timestamp(1_767_225_600, 0).unwrap();
        let req = ExtractSessionTokenRequest::builder()
            .session_token("0abcdef")
            .request_id(request_id)
            .server_timestamp(server_timestamp)
            .build();

        assert_eq!(req.session_token(), "0abcdef");
        assert_eq!(req.request_id(), request_id);
        assert_eq!(req.server_timestamp(), server_timestamp);
    }

    /// The session token is bearer-credential material. A derived `Debug` would print it in full,
    /// putting a live token into any log line that formats this request.
    #[test_log::test]
    fn extract_session_token_request_redacts_the_token() {
        let req = ExtractSessionTokenRequest::builder()
            .session_token("0SECRET-TOKEN-MATERIAL")
            .request_id(RequestId::new())
            .server_timestamp(DateTime::from_timestamp(1_767_225_600, 0).unwrap())
            .build();

        let debug = format!("{req:?}");
        assert!(!debug.contains("SECRET-TOKEN-MATERIAL"), "token leaked into Debug: {debug}");
        assert!(debug.contains("<redacted>"), "expected redaction marker: {debug}");
    }
}
