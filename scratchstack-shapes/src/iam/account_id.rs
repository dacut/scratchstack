use anyhow::{Result as AnyResult, bail};

/// Validates that the given account ID is a 12-digit number.
pub fn validate_account_id(account_id: impl AsRef<str>) -> AnyResult<()> {
    let account_id = account_id.as_ref();

    if account_id != "aws" && (account_id.len() != 12 || !account_id.chars().all(|c| c.is_ascii_digit())) {
        bail!("Account ID must be a 12-digit number");
    }

    Ok(())
}

/// Parse and validate an `account_id` field for Clap.
pub(crate) fn clap_parse_account_id(account_id: &str) -> Result<String, String> {
    validate_account_id(account_id).map_err(|e| format!("Invalid account id: {e}"))?;
    Ok(account_id.to_owned())
}

#[cfg(test)]
mod tests {
    /// Make sure we accept the "aws" pseudo-account ID.
    #[test_log::test]
    fn test_aws_account_id() {
        super::validate_account_id("aws").unwrap();
    }
}
