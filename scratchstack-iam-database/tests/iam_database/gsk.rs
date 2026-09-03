//! GetSigningKey (direct database lookup) test suite.
use {
    chrono::{NaiveDate, Utc},
    pretty_assertions::assert_eq,
    scratchstack_aws_principal::{Principal, SessionValue},
    scratchstack_aws_signature::{GetSigningKeyRequest, SignatureError},
    scratchstack_core::RequestId,
    scratchstack_iam_database::GetSigningKeyFromDatabase,
    std::sync::Arc,
    tower::{Service as _, ServiceExt as _},
};

/// The seeded long-term access key belonging to Example-User-1.
const SEEDED_ACCESS_KEY_ID: &str = "AKIAEXAMPLEACCESSKEYID123";

const MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST: &str = "The AWS access key provided does not exist in our records";

/// Look up a signing key for the given access key id and optional session token.
async fn get_signing_key(
    pool: &sqlx::PgPool,
    access_key_id: &str,
    session_token: Option<&str>,
) -> Result<scratchstack_aws_signature::GetSigningKeyResponse, SignatureError> {
    let mut gsk = GetSigningKeyFromDatabase::builder()
        .pool(Arc::new(pool.clone()))
        .partition("aws")
        .region("us-east-1")
        .service("iam")
        .build();

    let request = GetSigningKeyRequest::builder()
        .access_key(access_key_id)
        .maybe_session_token(session_token.map(|x| x.to_string()))
        .request_date(NaiveDate::from_ymd_opt(2024, 1, 1).expect("Failed to build request date"))
        .region("us-east-1")
        .service("iam")
        .request_id(RequestId::new())
        .server_timestamp(Utc::now())
        .build();

    gsk.ready().await.expect("GetSigningKeyFromDatabase should be ready").call(request).await
}

/// Assert that the error is an `InvalidClientTokenId` carrying the expected message.
fn assert_invalid_client_token_id(e: SignatureError, expected_message: &str) {
    assert!(matches!(e, SignatureError::InvalidClientTokenId(_)), "Expected InvalidClientTokenId, got: {e:?}");
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
    assert_invalid_client_token_id(e, MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST);
}

/// An access key whose four-byte prefix ends inside a multi-byte character is rejected rather
/// than panicking.
///
/// Access keys reach the lookup as the Latin-1 decoding of the credential in the `Authorization`
/// header, so every byte at or above 0x80 becomes a two-byte character. That lets a caller
/// present a key that clears the 20-byte length check and whose fourth byte lands inside a
/// character, which the `[..4]` slice this once used would panic on. The length and boundary
/// assertions are what make this input the case it claims to be; without them the test would
/// still pass if the string stopped having either property.
pub async fn test_get_signing_key_prefix_splits_multibyte_char(pool: &sqlx::PgPool) {
    // 'Ã' occupies bytes 3..5, so the prefix ends inside it.
    let access_key_id = format!("ABC\u{00C3}{}", "X".repeat(16));
    assert!(access_key_id.len() >= 20, "sanity: clears the byte-length check");
    assert!(!access_key_id.is_char_boundary(4), "sanity: byte 4 falls inside a character");

    let e = get_signing_key(pool, &access_key_id, None)
        .await
        .expect_err("An access key whose prefix splits a character must be rejected");
    assert_invalid_client_token_id(e, MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST);
}

/// An access key with an unrecognized prefix is rejected.
pub async fn test_get_signing_key_unknown_prefix(pool: &sqlx::PgPool) {
    let e = get_signing_key(pool, "AKIBEXAMPLEACCESSKEYID123", None)
        .await
        .expect_err("An access key with an unknown prefix must be rejected");
    assert_invalid_client_token_id(e, MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST);
}

/// An access key that isn't in the database is rejected.
pub async fn test_get_signing_key_nonexistent(pool: &sqlx::PgPool) {
    let e = get_signing_key(pool, "AKIANOSUCHACCESSKEYID123", None)
        .await
        .expect_err("A nonexistent access key must be rejected");
    assert_invalid_client_token_id(e, MSG_ACCESS_KEY_PROVIDED_DOES_NOT_EXIST);
}
