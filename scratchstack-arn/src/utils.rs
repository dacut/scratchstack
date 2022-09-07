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
/// *   ｀日本-東京-1`
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
    #[test]
    fn check_valid_services() {
        assert!(super::validate_service("s3").is_ok());
        assert!(super::validate_service("kafka-cluster").is_ok());
        assert!(super::validate_service("execute-api").is_ok());
    }
}
