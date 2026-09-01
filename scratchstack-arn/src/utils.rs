use crate::ArnError;

/// The maximum number of characters allowed in a partition name. As only ASCII is accepted, this is equivalently a
/// limit on the number of bytes.
const MAX_PARTITION_LENGTH: usize = 32;

/// Verify that a partition name meets the naming requirements.
///
/// AWS does not publish a formal specification for partition names. In this validator, we require:
///
/// *   The partition must be composed of ASCII lowercase letters (`a`-`z`), ASCII digits (`0`-`9`), or `-`.
/// *   The partition must have between 1 and 32 characters.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// Non-ASCII characters are rejected. See the [module documentation][crate::utils] for why.
///
/// Examples of valid partition names:
///
/// *   `aws`
/// *   `aws-cn`
/// *   `aws-us-gov`
/// *   `local`
/// *   `1`
/// *   `intranet-1`
///
/// # Errors
///
/// Returns [`ArnError::InvalidPartition`] if `partition` does not meet the requirements above.
pub fn validate_partition(partition: &str) -> Result<(), ArnError> {
    // Only ASCII is accepted, so the byte length is the character length for anything that validates.
    if partition.is_empty() || partition.len() > MAX_PARTITION_LENGTH {
        return Err(ArnError::InvalidPartition(partition.to_string()));
    }

    let mut last_was_dash = true;
    for c in partition.bytes() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            last_was_dash = false;
        } else if c == b'-' {
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
/// # Errors
///
/// Returns [`ArnError::InvalidAccountId`] if `account_id` does not meet this requirement.
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
/// *   The region is either the literal name `local`, or one or more `-`-separated groups of ASCII lowercase letters
///     (`a`-`z`), followed by a `-` and one or more ASCII digits (`0`-`9`). For example, `prod-west-1`.
/// *   The region may have a local region appended to it: a `-`, followed by a second region of the same form. For
///     example, `prod-east-1-dca-2`. At most one local region may be appended.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
/// *   No maximum length is enforced.
///
/// Non-ASCII characters are rejected. See the [module documentation][crate::utils] for why.
///
/// Examples of valid region names:
/// *   `us-east-1`
/// *   `test-1`
/// *   `prod-west-1`
/// *   `prod-east-1-dca-2`
/// *   `local`
///
/// # Errors
///
/// Returns [`ArnError::InvalidRegion`] if `region` does not meet the requirements above.
pub fn validate_region(region: &str) -> Result<(), ArnError> {
    // As a special case, we accept the region "local"
    if region == "local" {
        return Ok(());
    }

    let mut section = RegionParseSection::Region;
    let mut state = RegionParseState::Start;

    for c in region.bytes() {
        if c == b'-' {
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
        } else if c.is_ascii_lowercase() {
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
/// AWS does not publish a formal specification for service names. In this validator, we require:
///
/// *   The service must be composed of one or more ASCII lowercase letters (`a`-`z`), ASCII digits (`0`-`9`), or `-`.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
/// *   No maximum length is enforced.
///
/// Non-ASCII characters are rejected. See the [module documentation][crate::utils] for why.
///
/// # Errors
///
/// Returns [`ArnError::InvalidService`] if `service` does not meet the requirements above.
pub fn validate_service(service: &str) -> Result<(), ArnError> {
    if service.is_empty() {
        return Err(ArnError::InvalidService(service.to_string()));
    }

    let mut last_was_dash = true;

    for c in service.bytes() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            last_was_dash = false;
        } else if c == b'-' {
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
        assert!(validate_partition("aws-cn").is_ok());
        assert!(validate_partition("aws-us-gov").is_ok());
    }

    #[test]
    fn partition_at_max_length() {
        // 32 characters is the maximum. Only ASCII validates, so this is also 32 bytes.
        let p = "a".repeat(31) + "1";
        assert_eq!(p.len(), 32);
        assert!(validate_partition(&p).is_ok());
    }

    #[test]
    fn partition_too_long() {
        let p = "a".repeat(33);
        assert_eq!(validate_partition(&p), Err(ArnError::InvalidPartition(p)));
    }

    #[test]
    fn partition_non_ascii() {
        // Non-ASCII is rejected outright. In particular, names that are indistinguishable from a valid
        // ASCII name, or from each other, must not validate -- ARN components drive authorization
        // decisions and are compared byte-for-byte.
        for p in [
            "aws-中国",
            "việtnam",
            "\u{0430}ws",                       // Cyrillic a, a homograph of "aws"
            "\u{AC00}\u{B098}",                 // precomposed Hangul syllables
            "\u{1100}\u{1161}\u{1102}\u{1161}", // the same text as conjoining jamo
            "\u{0915}\u{0940}",                 // Devanagari, whose vowel signs are Other_Alphabetic
            "c\u{0327}",                        // c followed by a combining cedilla
        ] {
            assert_eq!(validate_partition(p), Err(ArnError::InvalidPartition(p.to_string())), "accepted {p:?}");
        }
    }

    #[test]
    fn partition_non_ascii_over_byte_limit() {
        // Under 32 characters but over 32 bytes: rejected for being non-ASCII, not for its length.
        let p = "中".repeat(20);
        assert!(p.chars().count() < 32 && p.len() > 32);
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
        assert!(validate_region("ap-southeast-7-dca-3").is_ok());
    }

    #[test]
    fn region_non_ascii() {
        for r in ["sverige-söder-1", "ap-southeast-7-hòa-hiệp-bắc-3", "日本-東京-1", "us-e\u{0430}st-1"] {
            assert_eq!(validate_region(r), Err(ArnError::InvalidRegion(r.to_string())), "accepted {r:?}");
        }
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
        assert!(validate_service("s3outposts").is_ok());
    }

    #[test]
    fn service_non_ascii() {
        // Includes a non-ASCII digit, which the previous Unicode-alphanumeric rule accepted.
        for svc in ["één", "nœrøyfjorden", "ec\u{0662}", "\u{0435}c2"] {
            assert_eq!(validate_service(svc), Err(ArnError::InvalidService(svc.to_string())), "accepted {svc:?}");
        }
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
