//! Constants used across database operations.

/// Constants related to Identity and Access Management (IAM).
#[cfg(feature = "iam")]
pub mod iam;

/// Operations related to the Security Token Service (STS).
#[cfg(feature = "sts")]
pub mod sts;
