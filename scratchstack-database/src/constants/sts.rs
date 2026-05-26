//! Constants (and quasi-constants) used for STS-related activities.
#![allow(unused)] // TODO: Remove once STS operations are implemented

use {scratchstack_pagination::PAGINATION_KEY_SIZE, uuid::Uuid};

// True constants

/// Default duration for session encryption tokens (1 day).
pub(crate) const DEFAULT_SESSION_TOKEN_DURATION_SECS: i64 = 24 * 60 * 60;

/// The maximum allowed duration for sessions (12 hours).
pub(crate) const MAX_SESSION_DURATION_SECS: i64 = 12 * 60 * 60;

/// The maximum allowed timestamp error for decrypting session tokens (15 minutes).
pub(crate) const MAX_SESSION_TOKEN_TIMESTAMP_ERROR_SECS: i64 = 15 * 60;

/// #error message: `"Internal failure"`.
pub(crate) const MSG_INTERNAL_FAILURE: &str = "Internal failure";

/// A fixed key for pagination operations. We really don't care if this is exposed since the user
/// has raw access to the database anyway.
pub(crate) const PAGINATION_KEY: &[u8; PAGINATION_KEY_SIZE] =
    b"\xc8\x80\xe0Y\x9f\xf2\xeb\xfc\xdfK]\xaf\x12\x13\xf1ts\xd2\xfc\x0e\xb0\xd7?\xa8\x89\xccC\xf6\xee\x14Fc";

/// The pagination key ID for STS operations.
pub(crate) const PAGINATION_KEY_ID: Uuid =
    Uuid::from_bytes([0x66, 0x3f, 0x12, 0x3f, 0x85, 0xf6, 0x4c, 0x0c, 0xa1, 0x9b, 0xce, 0x63, 0x33, 0xdf, 0x71, 0x97]);

/// The service identifier for the STS service, as a principal.
pub(crate) const SERVICE_ID_STS: &str = "sts.amazonaws.com";

/// The service key for the STS service in an ARN.
pub(crate) const SERVICE_KEY_STS: &str = "sts";

/// The current version of the STS API implemented.
pub(crate) const STS_API_VERSION: &str = "2011-06-15";
