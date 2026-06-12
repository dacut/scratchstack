//! Session token data types and utilities
use {
    crate::{KSecretKey, SignatureError},
    ascii_casing::{AsciiString, CaseInsensitive},
    chrono::{DateTime, Utc},
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::{Principal, SessionData},
    serde::{Deserialize, Serialize},
    std::collections::{HashMap, HashSet},
    tower::Service,
};

/// Data from a session token.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionTokenData {
    /// The ID of the role associated with this session.
    pub role_id: String,

    /// The access key ID of the session token.
    pub access_key_id: String,

    /// The secret key of the session token.
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
    pub principal: Principal,

    /// The expiration time of the session token.
    pub expires_at: DateTime<Utc>,

    /// The issuing time of the session token.
    pub issued_at: DateTime<Utc>,

    /// Inline policy associated with the session token.
    #[serde(with = "inline_policy_json")]
    pub inline_policy: Option<AspenPolicy>,

    /// Managed policy identifiers associated with the session token.
    pub managed_policy_ids: Vec<String>,

    /// The name of the session.
    pub role_session_name: String,

    /// Additional metadata associated with the session token.
    pub metadata: SessionData,

    /// Tags associated with the session token.
    pub tags: HashMap<AsciiString<CaseInsensitive>, String>,

    /// Keys of the transitive tags associated with the session token. These are tags that will be
    /// passed to any sessions that are assumed by this session.
    pub transitive_tag_keys: HashSet<AsciiString<CaseInsensitive>>,
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
/// This trait is blanket-implemented for every [`Service`] with the matching request, response,
/// and error types; do not implement it directly.
pub trait ExtractSessionToken: Service<String, Response = SessionTokenData, Error = SignatureError> {}

impl<T> ExtractSessionToken for T where T: Service<String, Response = SessionTokenData, Error = SignatureError> {}

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
