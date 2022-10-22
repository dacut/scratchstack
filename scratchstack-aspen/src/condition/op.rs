use {
    super::{
        arn::{arn_match, ArnCmp},
        binary::{binary_match, BINARY_DISPLAY_NAMES},
        boolean::{bool_match, BOOL_DISPLAY_NAMES},
        date::{date_match, DateCmp},
        ipaddr::{ip_address_match, IP_ADDRESS_DISPLAY_NAMES},
        null::{null_match, NULL_DISPLAY_NAME},
        numeric::{numeric_match, NumericCmp},
        string::{string_match, StringCmp},
        variant::Variant,
    },
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    scratchstack_aws_principal::SessionValue,
    serde::{de, de::Deserializer, ser::Serializer, Deserialize, Serialize},
    std::{
        borrow::Borrow,
        collections::BTreeMap,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

/// An operator for a condition clause.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConditionOp {
    /// Operators for ARNs.
    Arn(ArnCmp, Variant),

    /// Operators for binary values. Variant here is only allowed to be [Variant::None] or [Variant::IfExists].
    Binary(Variant),

    /// Operators on boolean values. Variant here is only allowed to be [Variant::None] or [Variant::IfExists].
    Bool(Variant),

    /// Operators for date/time values.
    Date(DateCmp, Variant),

    /// Operators on IP addresses and networks.
    IpAddress(Variant),

    /// Operator on the presence/absence of a value.
    Null,

    /// Operators on numeric values.
    Numeric(NumericCmp, Variant),

    /// Operators on string vaules.
    String(StringCmp, Variant),
}

/// The `ArnEquals` operator.
pub const ArnEquals: ConditionOp = ConditionOp::Arn(ArnCmp::Equals, Variant::None);

/// The `ArnEqualsIfExists` operator.
pub const ArnEqualsIfExists: ConditionOp = ConditionOp::Arn(ArnCmp::Equals, Variant::IfExists);

/// The `ArnNotEquals` operator.
pub const ArnNotEquals: ConditionOp = ConditionOp::Arn(ArnCmp::Equals, Variant::Negated);

/// The `ArnNotEqualsIfExists` operator.
pub const ArnNotEqualsIfExists: ConditionOp = ConditionOp::Arn(ArnCmp::Equals, Variant::IfExistsNegated);

/// The `ArnLike` operator.
pub const ArnLike: ConditionOp = ConditionOp::Arn(ArnCmp::Like, Variant::None);

/// The `ArnLikeIfExists` operator.
pub const ArnLikeIfExists: ConditionOp = ConditionOp::Arn(ArnCmp::Like, Variant::IfExists);

/// The `ArnNotLike` operator.
pub const ArnNotLike: ConditionOp = ConditionOp::Arn(ArnCmp::Like, Variant::Negated);

/// The `ArnNotLikeIfExists` operator.
pub const ArnNotLikeIfExists: ConditionOp = ConditionOp::Arn(ArnCmp::Like, Variant::IfExistsNegated);

/// The `BinaryEquals` operator.
pub const BinaryEquals: ConditionOp = ConditionOp::Binary(Variant::None);

/// The `BinaryEqualsIfExists` operator.
pub const BinaryEqualsIfExists: ConditionOp = ConditionOp::Binary(Variant::IfExists);

/// The `BinaryNotEquals` operator.
pub const Bool: ConditionOp = ConditionOp::Bool(Variant::None);

/// The `BoolIfExists` operator.
pub const BoolIfExists: ConditionOp = ConditionOp::Bool(Variant::IfExists);

/// The `DateEquals` operator.
pub const DateEquals: ConditionOp = ConditionOp::Date(DateCmp::Equals, Variant::None);

/// The `DateEqualsIfExists` operator.
pub const DateEqualsIfExists: ConditionOp = ConditionOp::Date(DateCmp::Equals, Variant::IfExists);

/// The `DateNotEquals` operator.
pub const DateNotEquals: ConditionOp = ConditionOp::Date(DateCmp::Equals, Variant::Negated);

/// The `DateNotEqualsIfExists` operator.
pub const DateNotEqualsIfExists: ConditionOp = ConditionOp::Date(DateCmp::Equals, Variant::IfExistsNegated);

/// The `DateLessThan` operator.
pub const DateLessThan: ConditionOp = ConditionOp::Date(DateCmp::LessThan, Variant::None);

/// The `DateLessThanIfExists` operator.
pub const DateLessThanIfExists: ConditionOp = ConditionOp::Date(DateCmp::LessThan, Variant::IfExists);

/// The `DateGreaterThanEquals` operator.
pub const DateGreaterThanEquals: ConditionOp = ConditionOp::Date(DateCmp::LessThan, Variant::Negated);

/// The `DateGreaterThanEqualsIfExists` operator.
pub const DateGreaterThanEqualsIfExists: ConditionOp = ConditionOp::Date(DateCmp::LessThan, Variant::IfExistsNegated);

/// The `DateLessThanEquals` operator.
pub const DateLessThanEquals: ConditionOp = ConditionOp::Date(DateCmp::LessThanEquals, Variant::None);

/// The `DateLessThanEqualsIfExists` operator.
pub const DateLessThanEqualsIfExists: ConditionOp = ConditionOp::Date(DateCmp::LessThanEquals, Variant::IfExists);

/// The `DateGreaterThan` operator.
pub const DateGreaterThan: ConditionOp = ConditionOp::Date(DateCmp::LessThanEquals, Variant::Negated);

/// The `DateGreaterThanIfExists` operator.
pub const DateGreaterThanIfExists: ConditionOp = ConditionOp::Date(DateCmp::LessThanEquals, Variant::IfExistsNegated);

/// The `IpAddress` operator.
pub const IpAddress: ConditionOp = ConditionOp::IpAddress(Variant::None);

/// The `IpAddressIfExists` operator.
pub const IpAddressIfExists: ConditionOp = ConditionOp::IpAddress(Variant::IfExists);

/// The `NotIpAddress` operator.
pub const NotIpAddress: ConditionOp = ConditionOp::IpAddress(Variant::Negated);

/// The `NotIpAddressIfExists` operator.
pub const NotIpAddressIfExists: ConditionOp = ConditionOp::IpAddress(Variant::IfExistsNegated);

/// The `Null` operator.
pub const Null: ConditionOp = ConditionOp::Null;

/// The `NumericEquals` operator.
pub const NumericEquals: ConditionOp = ConditionOp::Numeric(NumericCmp::Equals, Variant::None);

/// The `NumericEqualsIfExists` operator.
pub const NumericEqualsIfExists: ConditionOp = ConditionOp::Numeric(NumericCmp::Equals, Variant::IfExists);

/// The `NumericNotEquals` operator.
pub const NumericNotEquals: ConditionOp = ConditionOp::Numeric(NumericCmp::Equals, Variant::Negated);

/// The `NumericNotEqualsIfExists` operator.
pub const NumericNotEqualsIfExists: ConditionOp = ConditionOp::Numeric(NumericCmp::Equals, Variant::IfExistsNegated);

/// The `NumericLessThan` operator.
pub const NumericLessThan: ConditionOp = ConditionOp::Numeric(NumericCmp::LessThan, Variant::None);

/// The `NumericLessThanIfExists` operator.
pub const NumericLessThanIfExists: ConditionOp = ConditionOp::Numeric(NumericCmp::LessThan, Variant::IfExists);

/// The `NumericGreaterThanEquals` operator.
pub const NumericGreaterThanEquals: ConditionOp = ConditionOp::Numeric(NumericCmp::LessThan, Variant::Negated);

/// The `NumericGreaterThanEqualsIfExists` operator.
pub const NumericGreaterThanEqualsIfExists: ConditionOp =
    ConditionOp::Numeric(NumericCmp::LessThan, Variant::IfExistsNegated);

/// The `NumericLessThanEquals` operator.
pub const NumericLessThanEquals: ConditionOp = ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::None);

/// The `NumericLessThanEqualsIfExists` operator.
pub const NumericLessThanEqualsIfExists: ConditionOp =
    ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::IfExists);

/// The `NumericGreaterThan` operator.
pub const NumericGreaterThan: ConditionOp = ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::Negated);

/// The `NumericGreaterThanIfExists` operator.
pub const NumericGreaterThanIfExists: ConditionOp =
    ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::IfExistsNegated);

/// The `StringEquals` operator.
pub const StringEquals: ConditionOp = ConditionOp::String(StringCmp::Equals, Variant::None);

/// The `StringEqualsIfExists` operator.
pub const StringEqualsIfExists: ConditionOp = ConditionOp::String(StringCmp::Equals, Variant::IfExists);

/// The `StringNotEquals` operator.
pub const StringNotEquals: ConditionOp = ConditionOp::String(StringCmp::Equals, Variant::Negated);

/// The `StringNotEqualsIfExists` operator.
pub const StringNotEqualsIfExists: ConditionOp = ConditionOp::String(StringCmp::Equals, Variant::IfExistsNegated);

/// The `StringEqualsIgnoreCase` operator.
pub const StringEqualsIgnoreCase: ConditionOp = ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::None);

/// The `StringEqualsIgnoreCaseIfExists` operator.
pub const StringEqualsIgnoreCaseIfExists: ConditionOp =
    ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::IfExists);

/// The `StringNotEqualsIgnoreCase` operator.
pub const StringNotEqualsIgnoreCase: ConditionOp = ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::Negated);

/// The `StringNotEqualsIgnoreCaseIfExists` operator.
pub const StringNotEqualsIgnoreCaseIfExists: ConditionOp =
    ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::IfExistsNegated);

/// The `StringLike` operator.
pub const StringLike: ConditionOp = ConditionOp::String(StringCmp::Like, Variant::None);

/// The `StringLikeIfExists` operator.
pub const StringLikeIfExists: ConditionOp = ConditionOp::String(StringCmp::Like, Variant::IfExists);

/// The `StringNotLike` operator.
pub const StringNotLike: ConditionOp = ConditionOp::String(StringCmp::Like, Variant::Negated);

/// The `StringNotLikeIfExists` operator.
pub const StringNotLikeIfExists: ConditionOp = ConditionOp::String(StringCmp::Like, Variant::IfExistsNegated);

impl Borrow<str> for ConditionOp {
    fn borrow(&self) -> &str {
        match self {
            Self::Arn(cmp, variant) => cmp.display_name(variant),
            Self::Binary(variant) => BINARY_DISPLAY_NAMES[variant.as_usize()],
            Self::Bool(variant) => BOOL_DISPLAY_NAMES[variant.as_usize()],
            Self::Date(cmp, variant) => cmp.display_name(variant),
            Self::IpAddress(variant) => IP_ADDRESS_DISPLAY_NAMES[variant.as_usize()],
            Self::Null => NULL_DISPLAY_NAME,
            Self::Numeric(cmp, variant) => cmp.display_name(variant),
            Self::String(cmp, variant) => cmp.display_name(variant),
        }
    }
}

impl PartialEq<str> for ConditionOp {
    fn eq(&self, other: &str) -> bool {
        self.to_string().as_str() == other
    }
}

impl Display for ConditionOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.borrow())
    }
}

impl<'de> Deserialize<'de> for ConditionOp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ConditionOp::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for ConditionOp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

const NULL: SessionValue = SessionValue::Null;

impl ConditionOp {
    /// Indicates whether this condition operator matches the request [Context].
    ///
    /// Any variables in the condition are resolved according to the specified [PolicyVersion].
    ///
    /// # Errors
    ///
    /// If a condition clause contains a malformed variable reference and [PolicyVersion::V2012_10_17] or later is
    /// used, [AspenError::InvalidSubstitution] is returned.
    pub fn matches(
        &self,
        condition: &BTreeMap<String, StringLikeList<String>>,
        context: &Context,
        pv: PolicyVersion,
    ) -> Result<bool, AspenError> {
        for (key, allowed) in condition.iter() {
            let value = context.session_data().get(key).unwrap_or(&NULL);

            let result = match self {
                Self::Arn(cmp, variant) => arn_match(context, pv, allowed, value, *cmp, *variant),
                Self::Binary(variant) => binary_match(context, pv, allowed, value, *variant),
                Self::Bool(variant) => bool_match(context, pv, allowed, value, *variant),
                Self::Date(cmp, variant) => date_match(context, pv, allowed, value, *cmp, *variant),
                Self::IpAddress(variant) => ip_address_match(context, pv, allowed, value, *variant),
                Self::Null => null_match(context, pv, allowed, value),
                Self::Numeric(cmp, variant) => numeric_match(context, pv, allowed, value, *cmp, *variant),
                Self::String(cmp, variant) => string_match(context, pv, allowed, value, *cmp, *variant),
            }?;

            if !result {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl FromStr for ConditionOp {
    type Err = AspenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ArnEquals" => Ok(ArnEquals),
            "ArnEqualsIfExists" => Ok(ArnEqualsIfExists),
            "ArnNotEquals" => Ok(ArnNotEquals),
            "ArnNotEqualsIfExists" => Ok(ArnNotEqualsIfExists),
            "ArnLike" => Ok(ArnLike),
            "ArnLikeIfExists" => Ok(ArnLikeIfExists),
            "ArnNotLike" => Ok(ArnNotLike),
            "ArnNotLikeIfExists" => Ok(ArnNotLikeIfExists),
            "BinaryEquals" => Ok(BinaryEquals),
            "BinaryEqualsIfExists" => Ok(BinaryEqualsIfExists),
            "Bool" => Ok(Bool),
            "BoolIfExists" => Ok(BoolIfExists),
            "DateEquals" => Ok(DateEquals),
            "DateEqualsIfExists" => Ok(DateEqualsIfExists),
            "DateNotEquals" => Ok(DateNotEquals),
            "DateNotEqualsIfExists" => Ok(DateNotEqualsIfExists),
            "DateLessThan" => Ok(DateLessThan),
            "DateLessThanIfExists" => Ok(DateLessThanIfExists),
            "DateGreaterThanEquals" => Ok(DateGreaterThanEquals),
            "DateGreaterThanEqualsIfExists" => Ok(DateGreaterThanEqualsIfExists),
            "DateLessThanEquals" => Ok(DateLessThanEquals),
            "DateLessThanEqualsIfExists" => Ok(DateLessThanEqualsIfExists),
            "DateGreaterThan" => Ok(DateGreaterThan),
            "DateGreaterThanIfExists" => Ok(DateGreaterThanIfExists),
            "IpAddress" => Ok(IpAddress),
            "IpAddressIfExists" => Ok(IpAddressIfExists),
            "NotIpAddress" => Ok(NotIpAddress),
            "NotIpAddressIfExists" => Ok(NotIpAddressIfExists),
            "Null" => Ok(Null),
            "NumericEquals" => Ok(NumericEquals),
            "NumericEqualsIfExists" => Ok(NumericEqualsIfExists),
            "NumericNotEquals" => Ok(NumericNotEquals),
            "NumericNotEqualsIfExists" => Ok(NumericNotEqualsIfExists),
            "NumericLessThan" => Ok(NumericLessThan),
            "NumericLessThanIfExists" => Ok(NumericLessThanIfExists),
            "NumericGreaterThanEquals" => Ok(NumericGreaterThanEquals),
            "NumericGreaterThanEqualsIfExists" => Ok(NumericGreaterThanEqualsIfExists),
            "NumericLessThanEquals" => Ok(NumericLessThanEquals),
            "NumericLessThanEqualsIfExists" => Ok(NumericLessThanEqualsIfExists),
            "NumericGreaterThan" => Ok(NumericGreaterThan),
            "NumericGreaterThanIfExists" => Ok(NumericGreaterThanIfExists),
            "StringEquals" => Ok(StringEquals),
            "StringEqualsIfExists" => Ok(StringEqualsIfExists),
            "StringNotEquals" => Ok(StringNotEquals),
            "StringNotEqualsIfExists" => Ok(StringNotEqualsIfExists),
            "StringEqualsIgnoreCase" => Ok(StringEqualsIgnoreCase),
            "StringEqualsIgnoreCaseIfExists" => Ok(StringEqualsIgnoreCaseIfExists),
            "StringNotEqualsIgnoreCase" => Ok(StringNotEqualsIgnoreCase),
            "StringNotEqualsIgnoreCaseIfExists" => Ok(StringNotEqualsIgnoreCaseIfExists),
            "StringLike" => Ok(StringLike),
            "StringLikeIfExists" => Ok(StringLikeIfExists),
            "StringNotLike" => Ok(StringNotLike),
            "StringNotLikeIfExists" => Ok(StringNotLikeIfExists),
            _ => Err(AspenError::InvalidConditionOperator(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            condition::{
                arn::ArnCmp, date::DateCmp, numeric::NumericCmp, op::ConditionOp, string::StringCmp, variant::Variant,
            },
            condop,
        },
        std::{
            cmp::{Ordering, PartialOrd},
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test_log::test]
    fn test_derived() {
        let cops = vec![
            (ConditionOp::Arn(ArnCmp::Equals, Variant::None), "Arn(Equals, None)"),
            (ConditionOp::Arn(ArnCmp::Equals, Variant::IfExists), "Arn(Equals, IfExists)"),
            (ConditionOp::Arn(ArnCmp::Equals, Variant::Negated), "Arn(Equals, Negated)"),
            (ConditionOp::Arn(ArnCmp::Equals, Variant::IfExistsNegated), "Arn(Equals, IfExistsNegated)"),
            (ConditionOp::Arn(ArnCmp::Like, Variant::None), "Arn(Like, None)"),
            (ConditionOp::Arn(ArnCmp::Like, Variant::IfExists), "Arn(Like, IfExists)"),
            (ConditionOp::Arn(ArnCmp::Like, Variant::Negated), "Arn(Like, Negated)"),
            (ConditionOp::Arn(ArnCmp::Like, Variant::IfExistsNegated), "Arn(Like, IfExistsNegated)"),
            (ConditionOp::Binary(Variant::None), "Binary(None)"),
            (ConditionOp::Binary(Variant::IfExists), "Binary(IfExists)"),
            (ConditionOp::Bool(Variant::None), "Bool(None)"),
            (ConditionOp::Bool(Variant::IfExists), "Bool(IfExists)"),
            (ConditionOp::Date(DateCmp::Equals, Variant::None), "Date(Equals, None)"),
            (ConditionOp::Date(DateCmp::Equals, Variant::IfExists), "Date(Equals, IfExists)"),
            (ConditionOp::Date(DateCmp::Equals, Variant::Negated), "Date(Equals, Negated)"),
            (ConditionOp::Date(DateCmp::Equals, Variant::IfExistsNegated), "Date(Equals, IfExistsNegated)"),
            (ConditionOp::Date(DateCmp::LessThan, Variant::None), "Date(LessThan, None)"),
            (ConditionOp::Date(DateCmp::LessThan, Variant::IfExists), "Date(LessThan, IfExists)"),
            (ConditionOp::Date(DateCmp::LessThan, Variant::Negated), "Date(LessThan, Negated)"),
            (ConditionOp::Date(DateCmp::LessThan, Variant::IfExistsNegated), "Date(LessThan, IfExistsNegated)"),
            (ConditionOp::Date(DateCmp::LessThanEquals, Variant::None), "Date(LessThanEquals, None)"),
            (ConditionOp::Date(DateCmp::LessThanEquals, Variant::IfExists), "Date(LessThanEquals, IfExists)"),
            (ConditionOp::Date(DateCmp::LessThanEquals, Variant::Negated), "Date(LessThanEquals, Negated)"),
            (
                ConditionOp::Date(DateCmp::LessThanEquals, Variant::IfExistsNegated),
                "Date(LessThanEquals, IfExistsNegated)",
            ),
            (ConditionOp::IpAddress(Variant::None), "IpAddress(None)"),
            (ConditionOp::IpAddress(Variant::IfExists), "IpAddress(IfExists)"),
            (ConditionOp::IpAddress(Variant::Negated), "IpAddress(Negated)"),
            (ConditionOp::IpAddress(Variant::IfExistsNegated), "IpAddress(IfExistsNegated)"),
            (ConditionOp::Null, "Null"),
            (ConditionOp::Numeric(NumericCmp::Equals, Variant::None), "Numeric(Equals, None)"),
            (ConditionOp::Numeric(NumericCmp::Equals, Variant::IfExists), "Numeric(Equals, IfExists)"),
            (ConditionOp::Numeric(NumericCmp::Equals, Variant::Negated), "Numeric(Equals, Negated)"),
            (ConditionOp::Numeric(NumericCmp::Equals, Variant::IfExistsNegated), "Numeric(Equals, IfExistsNegated)"),
            (ConditionOp::Numeric(NumericCmp::LessThan, Variant::None), "Numeric(LessThan, None)"),
            (ConditionOp::Numeric(NumericCmp::LessThan, Variant::IfExists), "Numeric(LessThan, IfExists)"),
            (ConditionOp::Numeric(NumericCmp::LessThan, Variant::Negated), "Numeric(LessThan, Negated)"),
            (
                ConditionOp::Numeric(NumericCmp::LessThan, Variant::IfExistsNegated),
                "Numeric(LessThan, IfExistsNegated)",
            ),
            (ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::None), "Numeric(LessThanEquals, None)"),
            (ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::IfExists), "Numeric(LessThanEquals, IfExists)"),
            (ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::Negated), "Numeric(LessThanEquals, Negated)"),
            (
                ConditionOp::Numeric(NumericCmp::LessThanEquals, Variant::IfExistsNegated),
                "Numeric(LessThanEquals, IfExistsNegated)",
            ),
            (ConditionOp::String(StringCmp::Equals, Variant::None), "String(Equals, None)"),
            (ConditionOp::String(StringCmp::Equals, Variant::IfExists), "String(Equals, IfExists)"),
            (ConditionOp::String(StringCmp::Equals, Variant::Negated), "String(Equals, Negated)"),
            (ConditionOp::String(StringCmp::Equals, Variant::IfExistsNegated), "String(Equals, IfExistsNegated)"),
            (ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::None), "String(EqualsIgnoreCase, None)"),
            (ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::IfExists), "String(EqualsIgnoreCase, IfExists)"),
            (ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::Negated), "String(EqualsIgnoreCase, Negated)"),
            (
                ConditionOp::String(StringCmp::EqualsIgnoreCase, Variant::IfExistsNegated),
                "String(EqualsIgnoreCase, IfExistsNegated)",
            ),
            (ConditionOp::String(StringCmp::Like, Variant::None), "String(Like, None)"),
            (ConditionOp::String(StringCmp::Like, Variant::IfExists), "String(Like, IfExists)"),
            (ConditionOp::String(StringCmp::Like, Variant::Negated), "String(Like, Negated)"),
            (ConditionOp::String(StringCmp::Like, Variant::IfExistsNegated), "String(Like, IfExistsNegated)"),
        ];

        for (cop, debug) in &cops {
            assert_eq!(&format!("{:?}", cop), debug);
        }

        for i in 0..cops.len() {
            let mut hasher = DefaultHasher::new();
            cops[i].0.hash(&mut hasher);
            let i_hash = hasher.finish();

            for j in 0..cops.len() {
                let mut hasher = DefaultHasher::new();
                cops[j].0.hash(&mut hasher);
                let j_hash = hasher.finish();

                match i.cmp(&j) {
                    Ordering::Equal => {
                        assert_eq!(cops[i].0, cops[j].0);
                        assert_eq!(i_hash, j_hash);
                        assert_eq!(cops[i].0.cmp(&cops[j].0), Ordering::Equal);
                        assert_eq!(cops[i].0.partial_cmp(&cops[j].0), Some(Ordering::Equal));
                    }
                    Ordering::Less => {
                        assert_ne!(cops[i].0, cops[j].0);
                        assert_ne!(i_hash, j_hash);
                        assert_eq!(cops[i].0.cmp(&cops[j].0), Ordering::Less);
                        assert_eq!(cops[i].0.partial_cmp(&cops[j].0), Some(Ordering::Less));
                    }
                    Ordering::Greater => {
                        assert_ne!(cops[i].0, cops[j].0);
                        assert_ne!(i_hash, j_hash);
                        assert_eq!(cops[i].0.cmp(&cops[j].0), Ordering::Greater);
                        assert_eq!(cops[i].0.partial_cmp(&cops[j].0), Some(Ordering::Greater));
                    }
                }
            }
        }
    }

    #[test_log::test]
    fn test_deserialize_bad_type() {
        let e = serde_json::from_str::<ConditionOp>("3").unwrap_err();
        assert_eq!(e.to_string(), "invalid type: integer `3`, expected a string at line 1 column 1");

        let c = serde_json::from_str::<ConditionOp>("\"ArnEquals\"").unwrap();
        assert_eq!(c, condop::ArnEquals);
    }

    #[test_log::test]
    fn test_display() {
        let items = vec![
            "ArnEquals",
            "ArnEqualsIfExists",
            "ArnLike",
            "ArnLikeIfExists",
            "ArnNotEquals",
            "ArnNotEqualsIfExists",
            "ArnNotLike",
            "ArnNotLikeIfExists",
            "BinaryEquals",
            "BinaryEqualsIfExists",
            "Bool",
            "BoolIfExists",
            "DateEquals",
            "DateEqualsIfExists",
            "DateGreaterThan",
            "DateGreaterThanEquals",
            "DateGreaterThanEqualsIfExists",
            "DateGreaterThanIfExists",
            "DateLessThan",
            "DateLessThanEquals",
            "DateLessThanEqualsIfExists",
            "DateLessThanIfExists",
            "DateNotEquals",
            "DateNotEqualsIfExists",
            "IpAddress",
            "IpAddressIfExists",
            "NotIpAddress",
            "NotIpAddressIfExists",
            "Null",
            "NumericEquals",
            "NumericEqualsIfExists",
            "NumericGreaterThan",
            "NumericGreaterThanEquals",
            "NumericGreaterThanEqualsIfExists",
            "NumericGreaterThanIfExists",
            "NumericLessThan",
            "NumericLessThanEquals",
            "NumericLessThanEqualsIfExists",
            "NumericLessThanIfExists",
            "NumericNotEquals",
            "NumericNotEqualsIfExists",
            "StringEquals",
            "StringEqualsIfExists",
            "StringEqualsIgnoreCase",
            "StringEqualsIgnoreCaseIfExists",
            "StringLike",
            "StringLikeIfExists",
            "StringNotEquals",
            "StringNotEqualsIfExists",
            "StringNotEqualsIgnoreCase",
            "StringNotEqualsIgnoreCaseIfExists",
            "StringNotLike",
            "StringNotLikeIfExists",
        ];

        for item in items {
            let op = ConditionOp::from_str(item).unwrap();
            assert_eq!(format!("{}", op), item);
            assert_eq!(&op, item);
        }
    }
}
