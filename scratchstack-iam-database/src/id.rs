//! IAM identifier generation and parsing.
use {
    bon::bon,
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

/// The number of bits an account id occupies within an IAM identifier.
const ACCOUNT_ID_BITS: u32 = 40;

/// The number of bits a resource id occupies within an IAM identifier.
const RESOURCE_ID_BITS: u32 = 39;

/// The underlying structure of an IAM identifier.
///
/// The actual format used by AWS is not publicly documented beyond the
/// [first four characters](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids).
/// Observed values are base-32, and either 20 or 21 characters long depending on the resource
/// type.
///
/// Identifiers minted here are always 20 characters, whatever the resource type: the
/// four-character prefix, then the ten-byte payload described below. Ten bytes is 80 bits, which
/// is exactly sixteen base-32 characters with nothing left over to pad.
///
/// Older generation access keys start with a 0 bit and don't seem to include the account id in any
/// obviously discernible manner. There is an apparent checksum in these ids, as simple tampering
/// causes STS GetAccessKeyInfo to fail with "Access key ID is not valid."
///
/// Newer generation access keys start with a 1 bit and include the account id in the next 40 bits.
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
///
/// This struct is `#[non_exhaustive]`: outside this crate it must be built with
/// [`IamId::builder`] rather than struct literal syntax, so that adding a field stays a
/// non-breaking change. The fields remain public for reading.
///
/// ```compile_fail,E0639
/// # use scratchstack_iam_database::id::IamId;
/// let _ = IamId {
///     account_id: 557925715019,
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct IamId {
    /// The resource type the identifier represents.
    ///
    /// This is an [`IamResourceType`] rather than a string. Each variant renders through
    /// [`IamResourceType::as_str`] to a distinct four-character prefix -- `AKIA` for an access
    /// key, `AIDA` for a user -- and that prefix is what an identifier's string form begins with.
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

#[bon]
impl IamId {
    /// Create an [`IamIdBuilder`] for building an [`IamId`].
    ///
    /// # Errors
    ///
    /// An [`InvalidIamId`] error is returned if `account_id` does not fit in 40 bits or
    /// `resource_id` does not fit in 39 bits.
    ///
    /// # Example
    ///
    /// ```
    /// # use scratchstack_iam_database::id::IamId;
    /// # use scratchstack_aws_principal::IamResourceType;
    /// let id = IamId::builder()
    ///     .resource_type(IamResourceType::AccessKey)
    ///     .account_id(557925715019)
    ///     .resource_id(258422848521)
    ///     .build()
    ///     .unwrap();
    /// assert_eq!(id.to_string(), "AKIAYDZXWZRFXQVTHPAJ");
    /// ```
    #[builder(builder_type = IamIdBuilder, finish_fn = build)]
    pub fn builder(
        /// The resource type that the identifier represents.
        resource_type: IamResourceType,

        /// The account id the identifier belongs to. This must fit in 40 bits.
        account_id: u64,

        /// The unique identifier for the resource. This must fit in 39 bits.
        resource_id: u64,
    ) -> Result<Self, InvalidIamId> {
        if account_id >= (1 << ACCOUNT_ID_BITS) {
            return Err(InvalidIamId(format!("Account id {account_id} does not fit in {ACCOUNT_ID_BITS} bits")));
        }

        if resource_id >= (1 << RESOURCE_ID_BITS) {
            return Err(InvalidIamId(format!("Resource id {resource_id} does not fit in {RESOURCE_ID_BITS} bits")));
        }

        Ok(Self {
            resource_type,
            account_id,
            resource_id,
        })
    }

    /// Generate a new IAM identifier for the given resource type and account ID. The resource ID is
    /// generated randomly and is not guaranteed to be unique.
    ///
    /// # Panics
    ///
    /// Panics if `account_id` does not fit in 40 bits.
    ///
    /// [`IamId::builder`] reports that same condition as an [`InvalidIamId`] instead. Reach for
    /// the builder when the account id came from outside, and for this when the caller has
    /// already established that it is one.
    pub fn new(resource_type: IamResourceType, account_id: u64) -> Self {
        assert!(account_id < (1 << ACCOUNT_ID_BITS), "Account id {account_id} does not fit in {ACCOUNT_ID_BITS} bits");
        let resource_id = random::<u64>() & ((1 << RESOURCE_ID_BITS) - 1);
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
        // A string shorter than the resource type prefix, or one whose fourth byte falls inside a
        // multi-byte character, carries no prefix to read. Neither is an id, so report that rather
        // than slicing into it.
        let Some(resource_type) = s.get(0..4) else {
            return Err(InvalidIamId(s.to_string()));
        };

        // The prefix ends on a character boundary, so the remainder is safe to take directly.
        let iam_id_type = IamResourceType::from_str(resource_type)?;
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

    #[test_log::test]
    fn builder_matches_struct_literal() {
        let built = IamId::builder()
            .resource_type(IamResourceType::AccessKey)
            .account_id(557925715019)
            .resource_id(258422848521)
            .build()
            .unwrap();

        assert_eq!(
            built,
            IamId {
                resource_type: IamResourceType::AccessKey,
                account_id: 557925715019,
                resource_id: 258422848521,
            }
        );
        assert_eq!(built.to_string(), "AKIAYDZXWZRFXQVTHPAJ");
    }

    #[test_log::test]
    fn builder_rejects_out_of_range_ids() {
        let err = IamId::builder()
            .resource_type(IamResourceType::AccessKey)
            .account_id(1 << ACCOUNT_ID_BITS)
            .resource_id(0)
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), "Invalid IAM id: Account id 1099511627776 does not fit in 40 bits");

        let err = IamId::builder()
            .resource_type(IamResourceType::AccessKey)
            .account_id(0)
            .resource_id(1 << RESOURCE_ID_BITS)
            .build()
            .unwrap_err();
        assert_eq!(err.to_string(), "Invalid IAM id: Resource id 549755813888 does not fit in 39 bits");
    }

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

    /// Every identifier this crate mints is 20 characters: the four-character prefix plus the
    /// ten-byte payload, which is 80 bits and so encodes to exactly sixteen base-32 characters
    /// with no padding. AWS returns 21 for some resource types; this does not, and the struct
    /// doc says so.
    #[test_log::test]
    fn display_is_always_twenty_characters() {
        // Both bit fields at their extremes, so a zero payload and a saturated one are covered
        // as well as a realistic value.
        let ids = [(0, 0), (557925715019, 258422848521), ((1 << ACCOUNT_ID_BITS) - 1, (1 << RESOURCE_ID_BITS) - 1)];

        for resource_type in ALL_RESOURCE_TYPES {
            for (account_id, resource_id) in ids {
                let id = IamId::builder()
                    .resource_type(resource_type)
                    .account_id(account_id)
                    .resource_id(resource_id)
                    .build()
                    .expect("ids at the field bounds must build");
                let rendered = id.to_string();

                assert_eq!(
                    rendered.chars().count(),
                    20,
                    "{resource_type:?} with {account_id}/{resource_id} rendered {rendered:?}"
                );
                assert_eq!(IamId::from_str(&rendered).expect("must parse back"), id);
            }
        }
    }

    #[test_log::test]
    fn new_creates_valid_id() {
        let id = IamId::new(IamResourceType::User, 123456789012);
        assert_eq!(id.resource_type, IamResourceType::User);
        assert_eq!(id.account_id, 123456789012);
        assert!(id.resource_id < (1 << 39), "resource_id must fit in 39 bits");
    }

    /// The panic documented on [`IamId::new`]. The message matches the wording
    /// `IamId::builder` uses for the same condition, so the two report it the same way.
    #[test_log::test]
    #[should_panic(expected = "Account id 1099511627776 does not fit in 40 bits")]
    fn new_panics_on_out_of_range_account_id() {
        let _ = IamId::new(IamResourceType::User, 1 << ACCOUNT_ID_BITS);
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

    /// Every [`IamResourceType`] variant.
    ///
    /// One list, used by every test below that needs to walk the variants, so they cannot drift
    /// apart. Adding a variant upstream is caught by [`expected_prefix`], whose match is
    /// exhaustive; extend this list at the same time.
    const ALL_RESOURCE_TYPES: [IamResourceType; 13] = [
        IamResourceType::AccessKey,
        IamResourceType::BearerToken,
        IamResourceType::Certificate,
        IamResourceType::ContextSpecificCredential,
        IamResourceType::Group,
        IamResourceType::InstanceProfile,
        IamResourceType::ManagedPolicy,
        IamResourceType::ManagedPolicyVersion,
        IamResourceType::Role,
        IamResourceType::SessionTokenEncryptionKey,
        IamResourceType::SshPublicKey,
        IamResourceType::TemporaryAccessKey,
        IamResourceType::User,
    ];

    /// The four-character prefix a variant renders to, restated independently of `as_str`.
    ///
    /// The match is exhaustive on purpose. A variant added to [`IamResourceType`] stops this
    /// compiling, which is the only thing that keeps a test named `all_variants` honest:
    /// `SessionTokenEncryptionKey` was absent from these tests for exactly as long as nothing
    /// here had to account for it.
    fn expected_prefix(resource_type: IamResourceType) -> &'static str {
        match resource_type {
            IamResourceType::AccessKey => "AKIA",
            IamResourceType::BearerToken => "ABIA",
            IamResourceType::Certificate => "ASCA",
            IamResourceType::ContextSpecificCredential => "ACCA",
            IamResourceType::Group => "AGPA",
            IamResourceType::InstanceProfile => "AIPA",
            IamResourceType::ManagedPolicy => "ANPA",
            IamResourceType::ManagedPolicyVersion => "ANVA",
            IamResourceType::Role => "AROA",
            IamResourceType::SessionTokenEncryptionKey => "STEK",
            IamResourceType::SshPublicKey => "APKA",
            IamResourceType::TemporaryAccessKey => "ASIA",
            IamResourceType::User => "AIDA",
        }
    }

    #[test_log::test]
    fn resource_type_all_variants() {
        for resource_type in ALL_RESOURCE_TYPES {
            let prefix = expected_prefix(resource_type);
            assert_eq!(resource_type.as_str(), prefix, "as_str mismatch for {resource_type:?}");
            assert_eq!(
                IamResourceType::from_str(prefix).expect("from_str failed"),
                resource_type,
                "from_str mismatch for {prefix}"
            );
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
        let types = ALL_RESOURCE_TYPES;

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
    fn from_str_shorter_than_prefix() {
        // Too short to carry a resource type prefix at all; this must report the string rather
        // than slice past its end.
        for s in ["", "A", "AK", "AKI"] {
            let err = IamId::from_str(s).unwrap_err();
            assert_eq!(err.to_string(), format!("Invalid IAM id: {s}"), "input {s:?}");
        }
    }

    #[test_log::test]
    fn from_str_prefix_splits_multibyte_char() {
        // 'Ã' occupies bytes 3..5, so the four-byte prefix ends inside it. The string is long
        // enough by every byte-length measure and still has no prefix to read.
        let s = "AKI\u{00C3}AAAAAAAAAAAAAAAA";
        assert!(s.len() > 20, "sanity: long enough to pass a byte-length check");
        let err = IamId::from_str(s).unwrap_err();
        assert_eq!(err.to_string(), format!("Invalid IAM id: {s}"));
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
