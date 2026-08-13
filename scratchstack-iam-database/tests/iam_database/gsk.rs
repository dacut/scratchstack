//! GetSigningKey (direct database lookup) test suite.
use {
    chrono::NaiveDate,
    pretty_assertions::assert_eq,
    scratchstack_aws_principal::{Principal, SessionValue},
    scratchstack_aws_signature::{GetSigningKeyRequest, SignatureError},
    scratchstack_iam_database::GetSigningKeyFromDatabase,
    std::sync::Arc,
    tower::{BoxError, Service as _, ServiceExt as _},
};

/// The seeded long-term access key belonging to Example-User-1.
const SEEDED_ACCESS_KEY_ID: &str = "AKIAEXAMPLEACCESSKEYID123";

/// Look up a signing key for the given access key id and optional session token.
async fn get_signing_key(
    pool: &sqlx::PgPool,
    access_key_id: &str,
    session_token: Option<&str>,
) -> Result<scratchstack_aws_signature::GetSigningKeyResponse, BoxError> {
    let mut gsk = GetSigningKeyFromDatabase::new(Arc::new(pool.clone()), "aws", "us-east-1", "iam");
    let request = GetSigningKeyRequest::builder()
        .access_key(access_key_id)
        .session_token(session_token.map(str::to_string))
        .request_date(NaiveDate::from_ymd_opt(2024, 1, 1).expect("Failed to build request date"))
        .region("us-east-1")
        .service("iam")
        .build()
        .expect("Failed to build GetSigningKeyRequest");

    gsk.ready().await.expect("GetSigningKeyFromDatabase should be ready").call(request).await
}

/// Assert that the error is an `InvalidClientTokenId` carrying the expected message.
fn assert_invalid_client_token_id(e: BoxError, expected_message: &str) {
    let e = e.downcast::<SignatureError>().expect("Expected a SignatureError");
    assert!(matches!(*e, SignatureError::InvalidClientTokenId(_)), "Expected InvalidClientTokenId, got: {e:?}");
    assert_eq!(e.to_string(), expected_message);
}

/// A long-term access key with no session token resolves to the owning user.
pub async fn test_get_signing_key_long_term(pool: &sqlx::PgPool) {
    let resp = get_signing_key(pool, SEEDED_ACCESS_KEY_ID, None).await.expect("Failed to get signing key");

    let Principal::User(user) = resp.principal() else {
        panic!("Expected a user principal, got: {:?}", resp.principal());
    };
    assert_eq!(user.account_id(), "123456789012");
    assert_eq!(user.user_name(), "Example-User-1");

    assert_eq!(resp.session_data().get("aws:userid"), Some(&SessionValue::String("AIDAEXAMPLEUSERID123".to_string())));
}

/// A long-term access key presented with a session token is rejected: AWS treats the mismatched
/// credential pair as an invalid security token rather than ignoring the token.
pub async fn test_get_signing_key_long_term_with_session_token(pool: &sqlx::PgPool) {
    let e = get_signing_key(pool, SEEDED_ACCESS_KEY_ID, Some("some-session-token"))
        .await
        .expect_err("A long-term access key with a session token must be rejected");
    assert_invalid_client_token_id(e, "The security token included in the request is invalid");
}

/// An access key that is too short to carry a prefix is rejected.
pub async fn test_get_signing_key_short_access_key(pool: &sqlx::PgPool) {
    let e = get_signing_key(pool, "AKIASHORT", None).await.expect_err("A short access key must be rejected");
    assert_invalid_client_token_id(e, "The AWS access key provided does not exist in our records.");
}

/// An access key with an unrecognized prefix is rejected.
pub async fn test_get_signing_key_unknown_prefix(pool: &sqlx::PgPool) {
    let e = get_signing_key(pool, "AKIBEXAMPLEACCESSKEYID123", None)
        .await
        .expect_err("An access key with an unknown prefix must be rejected");
    assert_invalid_client_token_id(e, "The AWS access key provided does not exist in our records.");
}

/// An access key that isn't in the database is rejected.
pub async fn test_get_signing_key_nonexistent(pool: &sqlx::PgPool) {
    let e = get_signing_key(pool, "AKIANOSUCHACCESSKEYID123", None)
        .await
        .expect_err("A nonexistent access key must be rejected");
    assert_invalid_client_token_id(e, "The AWS access key provided does not exist in our records.");
}
