//! Session token data types and utilities
use {
    crate::{KSecretKey, SignatureError},
    chrono::{DateTime, Utc},
    scratchstack_arn::Arn,
    scratchstack_aspen::Policy as AspenPolicy,
    scratchstack_aws_principal::{Principal, SessionData},
    serde::{Deserialize, Serialize},
    tower::Service,
};

/// Data from a session token.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionTokenData {
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

    /// Permissions associated with the session token.
    pub permissions: SessionTokenPermissions,

    /// The name of the session.
    pub session_name: String,

    /// Additional metadata associated with the session token.
    pub metadata: SessionData,
}

/// Permissions associated with a session token.
///
/// The session token may have permissions associated with it that are more restrictive than the
/// permissions of the principal. This is specified as either an inline policy or a reference to a
/// managed policy.
///
/// It is allowed to have no permissions associated with the session token; however, the result is
/// the session will have no permissions at all, even if the principal has permissions.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum SessionTokenPermissions {
    /// No permissions are associated with the session token. The session will have no permissions
    /// at all, even if the principal has permissions.
    #[default]
    None,

    /// An inline policy is directly attached to the session token. This policy is more restrictive
    /// than the permissions of the principal.
    InlinePolicy(AspenPolicy),

    /// A reference to a managed policy is attached to the session token. This policy is more
    /// restrictive than the permissions of the principal.
    ManagedPolicy(Arn),
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

#[cfg(feature = "default_session_token")]
mod default_session_token;

#[cfg(feature = "default_session_token")]
pub use default_session_token::*;
