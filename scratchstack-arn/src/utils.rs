use crate::ArnError;

/// Verify that a partition name meets the naming requirements.
///
/// AWS does not publish a formal specification for partition names. In this validator, we require:
///
/// *   The partition must be composed of Unicode alphabetic non-uppercase characters, ASCII numeric
///     characters, or `-` (codepoint `\u{0x002d}`).
/// *   The partition must have between 1 and 32 characters.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// "Non-uppercase" is the same as "lowercase" for most Western scripts, but other scripts do not have a concept of
/// uppercase and lowercase.
///
/// The value must be in NFKC normalized form for validation on accented characters to succeed. For example, `ç`
/// represented as the codepoint `\u{0231}` ("Latin small letter c with cedilla") is valid, but `\u{0063}\u{0327}`
/// ("Latin small letter c" followed by "combining cedilla") is not.
///
/// Examples of valid partition names:
///
/// *   `aws`
/// *   `local`
/// *   `1`
/// *   `intranet-1`
/// *   `aws-中国`
/// *   `việtnam`
///
/// If `partition` meets the requirements, Ok is returned. Otherwise, a [ArnError::InvalidPartition] error is returned.
pub fn validate_partition(partition: &str) -> Result<(), ArnError> {
    if partition.is_empty() {
        return Err(ArnError::InvalidPartition(partition.to_string()));
    }

    let mut last_was_dash = true;
    for (i, c) in partition.char_indices() {
        if i == 32 {
            return Err(ArnError::InvalidPartition(partition.to_string()));
        }

        if (c.is_alphabetic() && !c.is_uppercase()) || c.is_ascii_digit() {
            last_was_dash = false;
        } else if c == '-' {
            if last_was_dash {
                return Err(ArnError::InvalidPartition(partition.to_string()));
            }

            last_was_dash = true;
        } else {
            return Err(ArnError::InvalidPartition(partition.to_string()));
        }
    }

    if last_was_dash {
        Err(ArnError::InvalidPartition(partition.to_string()))
    } else {
        Ok(())
    }
}

/// Verify that an account id meets AWS requirements.
///
/// An account id must be 12 ASCII digits or the string `aws`.
///
/// If `account_id` meets this requirement, Ok is returned. Otherwise, a [ArnError::InvalidAccountId] error is
/// returned.
pub fn validate_account_id(account_id: &str) -> Result<(), ArnError> {
    if account_id != "aws" {
        let a_bytes = account_id.as_bytes();

        if a_bytes.len() != 12 {
            return Err(ArnError::InvalidAccountId(account_id.to_string()));
        }

        for c in a_bytes.iter() {
            if !c.is_ascii_digit() {
                return Err(ArnError::InvalidAccountId(account_id.to_string()));
            }
        }
    }

    Ok(())
}

#[derive(PartialEq)]
enum RegionParseState {
    Start,
    LastWasAlpha,
    LastWasDash,
    LastWasDigit,
}

enum RegionParseSection {
    Region,
    LocalRegion,
}

/// Verify that a region name meets the naming requirements.
///
/// AWS does not publish a formal specification for region names. In this validator, we require:
///
/// *   The region must be composed of Unicode alphabetic non-uppercase characters or `-` (codepoint 45/0x002d),
///     followed by a `-` and one or more ASCII digits, or the name `local`.
/// *   The region can have a local region appended to it: after the region, a '-', one or more Unicode alphabetic
///     non-uppercase characters or `-`, followed by a `-` and one or more ASCII digits.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// "Non-uppercase" is the same as "lowercase" for most Western scripts, but other scripts do not have a concept of
/// uppercase and lowercase.
///
/// Examples of valid region names:
/// *   `test-1`
/// *   `prod-west-1`
/// *   `prod-east-1-dca-2`
/// *   `sverige-söder-1`
/// *   `ap-southeast-7-hòa-hiệp-bắc-3`
/// *   `日本-東京-1`
///
/// If `region` meets the requirements, Ok is returned. Otherwise, a [ArnError::InvalidRegion] error is returned.
pub fn validate_region(region: &str) -> Result<(), ArnError> {
    // As a special case, we accept the region "local"
    if region == "local" {
        return Ok(());
    }

    let mut section = RegionParseSection::Region;
    let mut state = RegionParseState::Start;

    for c in region.chars() {
        if c == '-' {
            match state {
                RegionParseState::Start | RegionParseState::LastWasDash => {
                    return Err(ArnError::InvalidRegion(region.to_string()));
                }
                RegionParseState::LastWasAlpha => {
                    state = RegionParseState::LastWasDash;
                }
                RegionParseState::LastWasDigit => match section {
                    RegionParseSection::Region => {
                        section = RegionParseSection::LocalRegion;
                        state = RegionParseState::LastWasDash;
                    }
                    RegionParseSection::LocalRegion => {
                        return Err(ArnError::InvalidRegion(region.to_string()));
                    }
                },
            }
        } else if c.is_alphabetic() && !c.is_uppercase() {
            match state {
                RegionParseState::Start | RegionParseState::LastWasDash | RegionParseState::LastWasAlpha => {
                    state = RegionParseState::LastWasAlpha;
                }
                _ => {
                    return Err(ArnError::InvalidRegion(region.to_string()));
                }
            }
        } else if c.is_ascii_digit() {
            match state {
                RegionParseState::LastWasDash | RegionParseState::LastWasDigit => {
                    state = RegionParseState::LastWasDigit;
                }
                _ => {
                    return Err(ArnError::InvalidRegion(region.to_string()));
                }
            }
        } else {
            return Err(ArnError::InvalidRegion(region.to_string()));
        }
    }

    if state == RegionParseState::LastWasDigit {
        Ok(())
    } else {
        Err(ArnError::InvalidRegion(region.to_string()))
    }
}

/// Verify that a service name meets the naming requirements.
///
/// AWS does not publish a formal specification for service names. In this validator, we specify:
/// *   The service must be composed of at least one or more Unicode non-uppercase alphabetic characeters, numeric
/// *   characters, or `-`.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// "Non-uppercase" is the same as "lowercase" for most Western scripts, but other scripts do not have a concept of
/// uppercase and lowercase.
///
/// If `service` meets the requirements, Ok is returned. Otherwise, a [ArnError::InvalidService] error is
/// returned.
pub fn validate_service(service: &str) -> Result<(), ArnError> {
    if service.is_empty() {
        return Err(ArnError::InvalidService(service.to_string()));
    }

    let mut last_was_dash = true;

    for c in service.chars() {
        if c.is_alphanumeric() && !c.is_uppercase() {
            last_was_dash = false;
        } else if c == '-' {
            if last_was_dash {
                return Err(ArnError::InvalidService(service.to_string()));
            }

            last_was_dash = true;
        } else {
            return Err(ArnError::InvalidService(service.to_string()));
        }
    }

    if last_was_dash {
        Err(ArnError::InvalidService(service.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use {super::*, crate::ArnError, pretty_assertions::assert_eq};

    // ── validate_partition ───────────────────────────────────────────────────

    #[test]
    fn partition_valid() {
        assert!(validate_partition("aws").is_ok());
        assert!(validate_partition("local").is_ok());
        assert!(validate_partition("1").is_ok());
        assert!(validate_partition("intranet-1").is_ok());
        assert!(validate_partition("aws-中国").is_ok());
        assert!(validate_partition("việtnam").is_ok());
    }

    #[test]
    fn partition_at_max_length() {
        // 32 chars is the maximum (checked at byte index 32, so a 32-char ASCII name is valid).
        assert!(validate_partition("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1").is_ok());
    }

    #[test]
    fn partition_too_long() {
        let p = "a".repeat(33);
        assert_eq!(validate_partition(&p), Err(ArnError::InvalidPartition(p)));
    }

    #[test]
    fn partition_empty() {
        assert_eq!(validate_partition(""), Err(ArnError::InvalidPartition("".to_string())));
    }

    #[test]
    fn partition_leading_dash() {
        assert_eq!(validate_partition("-aws"), Err(ArnError::InvalidPartition("-aws".to_string())));
    }

    #[test]
    fn partition_trailing_dash() {
        assert_eq!(validate_partition("aws-"), Err(ArnError::InvalidPartition("aws-".to_string())));
    }

    #[test]
    fn partition_consecutive_dashes() {
        assert_eq!(validate_partition("aws--1"), Err(ArnError::InvalidPartition("aws--1".to_string())));
    }

    #[test]
    fn partition_uppercase() {
        assert_eq!(validate_partition("Aws"), Err(ArnError::InvalidPartition("Aws".to_string())));
    }

    #[test]
    fn partition_invalid_char() {
        assert_eq!(validate_partition("aws_1"), Err(ArnError::InvalidPartition("aws_1".to_string())));
    }

    #[test]
    fn partition_emoji() {
        assert_eq!(validate_partition("🦀"), Err(ArnError::InvalidPartition("🦀".to_string())));
    }

    // ── validate_account_id ──────────────────────────────────────────────────

    #[test]
    fn account_id_valid_numeric() {
        assert!(validate_account_id("123456789012").is_ok());
    }

    #[test]
    fn account_id_valid_aws() {
        assert!(validate_account_id("aws").is_ok());
    }

    #[test]
    fn account_id_empty() {
        assert_eq!(validate_account_id(""), Err(ArnError::InvalidAccountId("".to_string())));
    }

    #[test]
    fn account_id_too_short() {
        assert_eq!(validate_account_id("12345678901"), Err(ArnError::InvalidAccountId("12345678901".to_string())));
    }

    #[test]
    fn account_id_too_long() {
        assert_eq!(validate_account_id("1234567890123"), Err(ArnError::InvalidAccountId("1234567890123".to_string())));
    }

    #[test]
    fn account_id_non_numeric() {
        assert_eq!(validate_account_id("12345678901a"), Err(ArnError::InvalidAccountId("12345678901a".to_string())));
    }

    #[test]
    fn account_id_not_aws_string() {
        // "AWS" (uppercase) is not the special "aws" literal.
        assert_eq!(validate_account_id("AWS"), Err(ArnError::InvalidAccountId("AWS".to_string())));
    }

    // ── validate_region ──────────────────────────────────────────────────────

    #[test]
    fn region_valid() {
        assert!(validate_region("local").is_ok());
        assert!(validate_region("us-east-1").is_ok());
        assert!(validate_region("us-west-2").is_ok());
        assert!(validate_region("test-1").is_ok());
        assert!(validate_region("us-east-1-bos-1").is_ok());
        assert!(validate_region("ap-southeast-7-hòa-hiệp-bắc-3").is_ok());
    }

    #[test]
    fn region_empty() {
        assert_eq!(validate_region(""), Err(ArnError::InvalidRegion("".to_string())));
    }

    #[test]
    fn region_leading_dash() {
        assert_eq!(validate_region("-us-east-1"), Err(ArnError::InvalidRegion("-us-east-1".to_string())));
    }

    #[test]
    fn region_trailing_dash() {
        assert_eq!(validate_region("us-east-1-"), Err(ArnError::InvalidRegion("us-east-1-".to_string())));
    }

    #[test]
    fn region_consecutive_dashes() {
        assert_eq!(validate_region("us-east--1"), Err(ArnError::InvalidRegion("us-east--1".to_string())));
    }

    #[test]
    fn region_uppercase() {
        assert_eq!(validate_region("Us-East-1"), Err(ArnError::InvalidRegion("Us-East-1".to_string())));
    }

    #[test]
    fn region_no_numeric_suffix() {
        // Must end with a digit group.
        assert_eq!(validate_region("us-east"), Err(ArnError::InvalidRegion("us-east".to_string())));
    }

    #[test]
    fn region_digit_before_alpha() {
        // Digits cannot precede alphabetic chars (e.g. "us-east-1a" is invalid).
        assert_eq!(validate_region("us-east-1a"), Err(ArnError::InvalidRegion("us-east-1a".to_string())));
    }

    #[test]
    fn region_alpha_only() {
        assert_eq!(validate_region("us-east"), Err(ArnError::InvalidRegion("us-east".to_string())));
    }

    #[test]
    fn region_too_many_local_zones() {
        // Only one local-zone suffix is allowed.
        assert_eq!(
            validate_region("us-east-1-bos-1-lax-1"),
            Err(ArnError::InvalidRegion("us-east-1-bos-1-lax-1".to_string()))
        );
    }

    #[test]
    fn region_emoji() {
        assert_eq!(validate_region("us-east-🦀"), Err(ArnError::InvalidRegion("us-east-🦀".to_string())));
    }

    // ── validate_service ─────────────────────────────────────────────────────

    #[test]
    fn service_valid() {
        assert!(validate_service("s3").is_ok());
        assert!(validate_service("ec2").is_ok());
        assert!(validate_service("kafka-cluster").is_ok());
        assert!(validate_service("execute-api").is_ok());
    }

    #[test]
    fn service_empty() {
        assert_eq!(validate_service(""), Err(ArnError::InvalidService("".to_string())));
    }

    #[test]
    fn service_leading_dash() {
        assert_eq!(validate_service("-ec2"), Err(ArnError::InvalidService("-ec2".to_string())));
    }

    #[test]
    fn service_trailing_dash() {
        assert_eq!(validate_service("ec2-"), Err(ArnError::InvalidService("ec2-".to_string())));
    }

    #[test]
    fn service_consecutive_dashes() {
        assert_eq!(validate_service("ec--2"), Err(ArnError::InvalidService("ec--2".to_string())));
    }

    #[test]
    fn service_uppercase() {
        assert_eq!(validate_service("Ec2"), Err(ArnError::InvalidService("Ec2".to_string())));
    }

    #[test]
    fn service_emoji() {
        assert_eq!(validate_service("🦀"), Err(ArnError::InvalidService("🦀".to_string())));
    }
}
