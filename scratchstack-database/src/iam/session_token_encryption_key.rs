//! Database operations for session token encryption keys.
mod create_session_token_encryption_key;
mod get_session_token_encryption_key;
mod list_session_token_encryption_keys;
mod update_session_token_encryption_key;
pub use {
    create_session_token_encryption_key::*, get_session_token_encryption_key::*, list_session_token_encryption_keys::*,
    update_session_token_encryption_key::*,
};

use scratchstack_shapes_iam::types::error::ValidationError;

/// Validate that a session token encryption key id is well-formed: it must start with the `STEK`
/// prefix and be 16..=128 characters of `[A-Za-z0-9_]`. The shape-level validation on
/// `GetSessionTokenEncryptionKeyRequest` already enforces the regex and length window; this adds
/// the prefix requirement so we can derive the stored body.
pub(crate) fn validate_session_token_encryption_key_id(stek_id: &str) -> Result<(), ValidationError> {
    if stek_id.len() < 16 || stek_id.len() > 128 || !stek_id.starts_with("STEK") {
        return Err(ValidationError::builder()
            .message(format!("Session token encryption key id {stek_id} is not valid."))
            .build());
    }
    if !stek_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(ValidationError::builder()
            .message(format!("Session token encryption key id {stek_id} is not valid."))
            .build());
    }
    Ok(())
}
