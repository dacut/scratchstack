//! Shared constants used by multiple test modules.

/// A minimal valid Aspen policy document, accepted by every CreatePolicy/CreatePolicyVersion path.
pub const VALID_POLICY_DOCUMENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
