//! IAM identifier generation and parsing.
use {
    rand::random,
    scratchstack_aws_principal::{IamResourceType, InvalidIamResourceType},
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

const ID_ALPHABET: base32::Alphabet = base32::Alphabet::Rfc4648 {
    padding: false,
};

/// The underlying structure of an IAM identifier.
///
/// The actual format used by AWS is not publicly documented beyond the
/// [first four characters](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids),
/// but all returned values are strings of length 20 (ASIA) or 21 (all other types) in base-32
/// encoding.
///
/// Older generation access keys start with a 0 bit and don't seem to include the account id in any
/// obviously discernable manner. There is an apparent checksum in these ids, as simple tampering
/// causes STS GetAccessKeyInfo to fail with "Access key ID is not valid."
///
/// Never generation access key start with a 1 bit and include the account id in the next 40 bits.
/// The remaining 39 bits are presumably a unique identifier for the resource.
///
/// This implementation follows the newer AWS format.
///
/// In decoded binary format, an identifier is represented as:
/// ```text
///            Byte:        0        1        2        3        4        5        6        7        8        9
///             Bit: 76543210 76543210 76543210 76543210 76543210 76543210 76543210 76543210 76543210 76543210
///                  1AAAAAAA AAAAAAAA AAAAAAAA AAAAAAAA AAAAAAAA ARRRRRRR RRRRRRRR RRRRRRRR RRRRRRRR RRRRRRRR
///  Account ID Bit:            3          2          1           0
///                   9876543 21098765 43210987 65432109 87654321 0         3          2          1          0
/// Resource ID Bit:                                               8765432 10987654 32109876 54321098 76543210
/// A = account id
/// R = resource id
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IamId {
    /// The resource type that the identifier represents. This is a 4-character string that is unique across
    /// all resource types.
    pub resource_type: IamResourceType,

    /// The account ID that the identifier belongs to. This is a 12-digit number that is unique
    /// across all accounts.
    ///
    /// This is represented as a `u64` but only occupies 40 bits.
    pub account_id: u64,

    /// The unique identifier for the resource. This is a 39-bit number that is unique across all
    /// resources of the same type in the same account.
    pub resource_id: u64,
}

impl IamId {
    /// Generate a new IAM identifier for the given resource type and account ID. The resource ID is
    /// generated randomly and is not guaranteed to be unique.
    pub fn new(resource_type: IamResourceType, account_id: u64) -> Self {
        assert!(account_id < (1 << 40));
        let resource_id = random::<u64>() & ((1 << 39) - 1);
        Self {
            resource_type,
            account_id,
            resource_id,
        }
    }
}

impl Display for IamId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.resource_type.as_str())?;

        // The first 3 bytes will always be 0 since account_id only occupies 40 bits.
        let account_id_bytes = self.account_id.to_be_bytes();

        // The first 3 bytes (0..3) will always be 0 since resource_id only occupies 39 bits.
        // Additionally, the top bit of byte 3 will also be 0.
        let resource_id_bytes = self.resource_id.to_be_bytes();

        assert_eq!(account_id_bytes[0], 0);
        assert_eq!(account_id_bytes[1], 0);
        assert_eq!(account_id_bytes[2], 0);
        assert_eq!(resource_id_bytes[0], 0);
        assert_eq!(resource_id_bytes[1], 0);
        assert_eq!(resource_id_bytes[2], 0);
        assert_eq!(resource_id_bytes[3] & 0b1000_0000, 0);

        // The actual format used by AWS is not publicly documented beyond the first four characters,
        // but all returned values are strings of length 20 (ASIA) or 21 (all other types) in base-32
        // encoding. This implementation follows the newer AWS format.
        let mut bytes = [0u8; 10];

        // The leading bit is always 1.
        bytes[0] = 0b1000_0000 | account_id_bytes[3] >> 1;
        bytes[1] = (account_id_bytes[3] << 7) & 0x80 | (account_id_bytes[4] >> 1);
        bytes[2] = (account_id_bytes[4] << 7) & 0x80 | (account_id_bytes[5] >> 1);
        bytes[3] = (account_id_bytes[5] << 7) & 0x80 | (account_id_bytes[6] >> 1);
        bytes[4] = (account_id_bytes[6] << 7) & 0x80 | (account_id_bytes[7] >> 1);
        bytes[5] = (account_id_bytes[7] << 7) & 0x80 | resource_id_bytes[3];
        bytes[6] = resource_id_bytes[4];
        bytes[7] = resource_id_bytes[5];
        bytes[8] = resource_id_bytes[6];
        bytes[9] = resource_id_bytes[7];
        f.write_str(&base32::encode(ID_ALPHABET, &bytes))
    }
}

impl FromStr for IamId {
    type Err = InvalidIamId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let iam_id_type = IamResourceType::from_str(&s[0..4])?;
        let payload = base32::decode(ID_ALPHABET, &s[4..]).ok_or_else(|| InvalidIamId(s.to_string()))?;
        if payload.len() != 10 {
            return Err(InvalidIamId(s.to_string()));
        }

        // Topmost bit must be a 1 for newer generation ids.
        if payload[0] & 0b1000_0000 == 0 {
            return Err(InvalidIamId(s.to_string()));
        }

        let account_id = ((payload[0] as u64 & 0x7F) << 33)
            | (payload[1] as u64) << 25
            | (payload[2] as u64) << 17
            | (payload[3] as u64) << 9
            | (payload[4] as u64) << 1
            | ((payload[5] as u64) & 0x80) >> 7;

        let resource_id = ((payload[5] as u64 & 0x7F) << 32)
            | (payload[6] as u64) << 24
            | (payload[7] as u64) << 16
            | (payload[8] as u64) << 8
            | (payload[9] as u64);

        Ok(Self {
            resource_type: iam_id_type,
            account_id,
            resource_id,
        })
    }
}

/// Error returned when an invalid IAM identifier string is parsed.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InvalidIamId(String);

impl Display for InvalidIamId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Invalid IAM id: {}", self.0)
    }
}

impl From<InvalidIamResourceType> for InvalidIamId {
    fn from(err: InvalidIamResourceType) -> Self {
        Self(err.0)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, pretty_assertions::assert_eq};

    /// Known IAM id: AKIAYDZXWZRFXQVTHPAJ
    /// Account id: 557925715019
    /// Resource id: 258422848521
    #[test_log::test]
    fn known_id_display() {
        let id = IamId {
            resource_type: IamResourceType::AccessKey,
            account_id: 557925715019,
            resource_id: 258422848521,
        };
        assert_eq!(id.to_string(), "AKIAYDZXWZRFXQVTHPAJ");

        let id2 = IamId::from_str("AKIAYDZXWZRFXQVTHPAJ").expect("Failed to parse known id");
        assert_eq!(id, id2);
    }

    #[test_log::test]
    fn roundtrip() {
        let id = IamId {
            resource_type: IamResourceType::AccessKey,
            account_id: 557925715019,
            resource_id: 258422848521,
        };
        let s = id.to_string();
        let parsed = IamId::from_str(&s).expect("Failed to parse IamId");
        assert_eq!(id, parsed);
    }

    #[test_log::test]
    fn new_creates_valid_id() {
        let id = IamId::new(IamResourceType::User, 123456789012);
        assert_eq!(id.resource_type, IamResourceType::User);
        assert_eq!(id.account_id, 123456789012);
        assert!(id.resource_id < (1 << 39), "resource_id must fit in 39 bits");
    }

    #[test_log::test]
    fn new_roundtrip() {
        // Verify that a newly generated id survives a Display/FromStr roundtrip.
        let id = IamId::new(IamResourceType::Role, 999999999999);
        let s = id.to_string();
        let parsed = IamId::from_str(&s).expect("Failed to parse generated IamId");
        assert_eq!(id, parsed);
    }

    // ── IamResourceType ──────────────────────────────────────────────────────

    #[test_log::test]
    fn resource_type_all_variants() {
        let cases = [
            (IamResourceType::AccessKey, "AKIA"),
            (IamResourceType::BearerToken, "ABIA"),
            (IamResourceType::Certificate, "ASCA"),
            (IamResourceType::ContextSpecificCredential, "ACCA"),
            (IamResourceType::Group, "AGPA"),
            (IamResourceType::InstanceProfile, "AIPA"),
            (IamResourceType::ManagedPolicy, "ANPA"),
            (IamResourceType::ManagedPolicyVersion, "ANVA"),
            (IamResourceType::Role, "AROA"),
            (IamResourceType::SshPublicKey, "APKA"),
            (IamResourceType::TemporaryAccessKey, "ASIA"),
            (IamResourceType::User, "AIDA"),
        ];

        for (rt, s) in cases {
            assert_eq!(rt.as_str(), s, "as_str mismatch for {rt:?}");
            assert_eq!(IamResourceType::from_str(s).expect("from_str failed"), rt, "from_str mismatch for {s}");
        }
    }

    #[test_log::test]
    fn resource_type_from_str_invalid() {
        let err = IamResourceType::from_str("XXXX").unwrap_err();
        assert_eq!(err, InvalidIamResourceType("XXXX".to_string()));
        assert_eq!(err.to_string(), "Invalid IAM resource type: XXXX");
    }

    #[test_log::test]
    fn resource_type_derived_traits() {
        let types = [
            IamResourceType::AccessKey,
            IamResourceType::BearerToken,
            IamResourceType::Certificate,
            IamResourceType::ContextSpecificCredential,
            IamResourceType::Group,
            IamResourceType::InstanceProfile,
            IamResourceType::ManagedPolicy,
            IamResourceType::ManagedPolicyVersion,
            IamResourceType::Role,
            IamResourceType::SshPublicKey,
            IamResourceType::TemporaryAccessKey,
            IamResourceType::User,
        ];

        // Clone + Copy
        let t = types[0];
        let cloned = t;
        assert_eq!(t, cloned);

        // Eq / PartialEq
        for i in 0..types.len() {
            for j in 0..types.len() {
                if i == j {
                    assert_eq!(types[i], types[j]);
                } else {
                    assert_ne!(types[i], types[j]);
                }
            }
        }

        // Ord: derive(Ord) uses declaration order, so Certificate < User, etc.
        assert!(IamResourceType::Certificate < IamResourceType::User);
        assert!(IamResourceType::User > IamResourceType::Group);

        // Hash (compile-time check via use in a HashMap)
        let mut map = std::collections::HashMap::new();
        for t in &types {
            map.insert(*t, t.as_str());
        }
        assert_eq!(map.len(), types.len());

        // Debug
        let _ = format!("{:?}", types[0]);
    }

    // ── IamId FromStr error paths ─────────────────────────────────────────────

    #[test_log::test]
    fn from_str_invalid_resource_type() {
        // "XXXX" is not a known resource type prefix.
        let err = IamId::from_str("XXXXAAAAAAAAAAAAAAAA").unwrap_err();
        assert_eq!(err.to_string(), "Invalid IAM id: XXXX");
    }

    #[test_log::test]
    fn from_str_invalid_base32_payload() {
        // '!' is not a valid base32 character.
        let err = IamId::from_str("AIDA!!!!!!!!!!!!!!!!").unwrap_err();
        assert_eq!(err.to_string(), "Invalid IAM id: AIDA!!!!!!!!!!!!!!!!");
    }

    #[test_log::test]
    fn from_str_wrong_payload_length() {
        // 8 base32 chars (40 bits) decode to 5 bytes, not 10 -> length check fails.
        // "AIDA" (4) + 8 'A' chars = 12 total.
        let s = "AIDAAAAAAAAA"; // 4 + 8 = 12 chars total
        assert_eq!(s.len(), 12, "sanity: 4 type chars + 8 payload chars");
        let err = IamId::from_str(s).unwrap_err();
        assert_eq!(err.to_string(), format!("Invalid IAM id: {s}"));
    }

    #[test_log::test]
    fn from_str_old_generation_id() {
        // "AAAAAAAAAAAAAAAA" (16 'A's) decodes to 10 zero bytes; first byte MSB = 0
        // -> rejected as an old-generation id.
        let s = "AIDAAAAAAAAAAAAAAAAA";
        let err = IamId::from_str(s).unwrap_err();
        assert_eq!(err.to_string(), format!("Invalid IAM id: {s}"));
    }

    // ── IamId derived traits ─────────────────────────────────────────────────

    #[test_log::test]
    fn iam_id_derived_traits() {
        let a = IamId {
            resource_type: IamResourceType::User,
            account_id: 1,
            resource_id: 1,
        };
        let b = IamId {
            resource_type: IamResourceType::User,
            account_id: 1,
            resource_id: 2,
        };
        let c = IamId {
            resource_type: IamResourceType::Role,
            account_id: 1,
            resource_id: 1,
        };

        // Clone / Copy
        let a2 = a;
        assert_eq!(a, a2);

        // Eq / PartialEq
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert_ne!(a, c);

        // Ord: resource_type first, then account_id, then resource_id.
        // Role is declared before User, so Role < User → c < a.
        assert!(a < b, "same type and account; a.resource_id 1 < b.resource_id 2");
        assert!(c < a, "Role declared before User → Role < User");

        // Hash
        let mut map = std::collections::HashMap::new();
        map.insert(a, "a");
        map.insert(b, "b");
        assert_eq!(map.len(), 2);

        // Debug
        let _ = format!("{:?}", a);
    }

    // ── InvalidIamId ─────────────────────────────────────────────────────────

    #[test_log::test]
    fn invalid_iam_id_display() {
        let err = InvalidIamId("bad-id-value".to_string());
        assert_eq!(err.to_string(), "Invalid IAM id: bad-id-value");
    }

    #[test_log::test]
    fn invalid_iam_id_from_resource_type_error() {
        let rt_err = InvalidIamResourceType("ZZZZ".to_string());
        let id_err = InvalidIamId::from(rt_err);
        assert_eq!(id_err, InvalidIamId("ZZZZ".to_string()));
        assert_eq!(id_err.to_string(), "Invalid IAM id: ZZZZ");
    }

    #[test_log::test]
    fn invalid_iam_id_derived_traits() {
        let a = InvalidIamId("foo".to_string());
        let b = InvalidIamId("bar".to_string());

        // Clone
        let a2 = a.clone();
        assert_eq!(a, a2);

        // Eq / PartialEq
        assert_ne!(a, b);

        // Debug
        let _ = format!("{:?}", a);
    }

    // ── InvalidIamResourceType ────────────────────────────────────────────────

    #[test_log::test]
    fn invalid_iam_resource_type_display() {
        let err = InvalidIamResourceType("ZZZZ".to_string());
        assert_eq!(err.to_string(), "Invalid IAM resource type: ZZZZ");
    }

    #[test_log::test]
    fn invalid_iam_resource_type_is_std_error() {
        let err = InvalidIamResourceType("ZZZZ".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test_log::test]
    fn invalid_iam_resource_type_derived_traits() {
        let a = InvalidIamResourceType("AAA".to_string());
        let b = InvalidIamResourceType("BBB".to_string());

        // Clone
        let a2 = a.clone();
        assert_eq!(a, a2);

        // Eq / PartialEq
        assert_ne!(a, b);

        // Debug
        let _ = format!("{:?}", a);
    }
}
