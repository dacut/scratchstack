//! IAM identifier generation and parsing.
use {
    rand::random,
    std::{
        error::Error as StdError,
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

        let account_id = ((payload[0] as u64 & 0b0111_1111) << 25)
            | (payload[1] as u64) << 17
            | (payload[2] as u64) << 9
            | (payload[3] as u64) << 1
            | (payload[4] as u64) >> 7;
        let resource_id = ((payload[4] as u64 & 0b0111_1111) << 32)
            | (payload[5] as u64) << 32
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

/// The resource type that an IAM identifier represents.
///
/// Reference: [IAM identifiers: Unique identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids)
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum IamResourceType {
    /// Certificate (`ASCA`).
    Certificate,

    /// A context-specific credential (`ACCA`).
    ContextSpecificCredential,

    /// IAM group (`AGPA`).
    Group,

    /// Instance profile (`AIPA`).
    InstanceProfile,

    /// IAM managed policy (`ANPA`).
    ManagedPolicy,

    /// IAM managed policy version (`ANVA`).
    ManagedPolicyVersion,

    /// Persistent access key (`AKIA`).
    PersistentAccessKey,

    /// An IAM role (`AROA`).
    Role,

    /// STS service bearer token (`ABIA`).
    ServiceBearerToken,

    /// SSH public key (`APKA`).
    SshPublicKey,

    /// Temporary access key (`ASIA`).
    TemporaryAccessKey,

    /// IAM user (`AIDA`).
    User,
}

impl IamResourceType {
    /// Get the 4-character string representation of the resource type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Certificate => "ASCA",
            Self::ContextSpecificCredential => "ACCA",
            Self::Group => "AGPA",
            Self::InstanceProfile => "AIPA",
            Self::ManagedPolicy => "ANPA",
            Self::ManagedPolicyVersion => "ANVA",
            Self::PersistentAccessKey => "AKIA",
            Self::Role => "AROA",
            Self::ServiceBearerToken => "ABIA",
            Self::SshPublicKey => "APKA",
            Self::TemporaryAccessKey => "ASIA",
            Self::User => "AIDA",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidIamResourceType(String);

impl Display for InvalidIamResourceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Invalid IAM resource type: {}", self.0)
    }
}

impl StdError for InvalidIamResourceType {}

impl FromStr for IamResourceType {
    type Err = InvalidIamResourceType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ASCA" => Ok(Self::Certificate),
            "ACCA" => Ok(Self::ContextSpecificCredential),
            "AGPA" => Ok(Self::Group),
            "AIPA" => Ok(Self::InstanceProfile),
            "ANPA" => Ok(Self::ManagedPolicy),
            "ANVA" => Ok(Self::ManagedPolicyVersion),
            "AKIA" => Ok(Self::PersistentAccessKey),
            "AROA" => Ok(Self::Role),
            "ABIA" => Ok(Self::ServiceBearerToken),
            "APKA" => Ok(Self::SshPublicKey),
            "ASIA" => Ok(Self::TemporaryAccessKey),
            "AIDA" => Ok(Self::User),
            _ => Err(InvalidIamResourceType(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known IAM id: AKIAYDZXWZRFXQVTHPAJ
    /// Account id: 557925715019
    /// Resource id: 258422848521
    #[test_log::test]
    fn test_known_id() {
        let id = IamId {
            resource_type: IamResourceType::PersistentAccessKey,
            account_id: 557925715019,
            resource_id: 258422848521,
        };
        assert_eq!(id.to_string(), "AKIAYDZXWZRFXQVTHPAJ");
    }
}
