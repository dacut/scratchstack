//! Database operations for the Scratchstack IAM database implementation.
//!
//! All operations take database transactions, allowing these operations to be used in larger
//! transactions as needed. Any returned results are subject to the transaction being committed.
//! Do **not** use results until the commit has been completed.

mod account;
mod partition;
mod user;

pub use {account::*, partition::*, user::*};

use {scratchstack_pagination::PAGINATION_KEY_SIZE, uuid::Uuid};

/// A fixed key for pagination operations. We really don't care if this is exposed since the user
/// has raw access to the database anyway.
pub(crate) const PAGINATION_KEY: &[u8; PAGINATION_KEY_SIZE] = b"\xb2\xa5\xac\x4c\x41\x9e\x8a\x62\x01\xf4\x18\x53\xde\x61\x63\x86\x14\x4a\xd1\x20\xf1\xbb\xe0\x93\x62\x5e\xf4\xc6\x6a\x7d\x80\xd8";

/// An identifier for the fixed key.
pub(crate) const PAGINATION_KEY_ID: Uuid =
    Uuid::from_bytes([0x1d, 0x78, 0xc0, 0x8d, 0x6c, 0x63, 0x44, 0x8a, 0xa0, 0x04, 0x77, 0xa3, 0xc6, 0xee, 0x90, 0x1e]);

/// The current version of the IAM API implemented.
pub(crate) const IAM_API_VERSION: &str = "2010-05-08";
