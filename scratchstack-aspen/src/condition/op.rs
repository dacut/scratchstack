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
        NULL,
    },
    crate::{serutil::StringLikeList, AspenError, Context, PolicyVersion},
    serde::{Deserialize, Serialize},
    std::{
        borrow::Borrow,
        collections::BTreeMap,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConditionOp {
    Arn(ArnCmp, Variant),
    Binary(Variant),
    Bool(Variant),
    Date(DateCmp, Variant),
    IpAddress(Variant),
    Null,
    Numeric(NumericCmp, Variant),
    String(StringCmp, Variant),
}

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
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ConditionOp::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ConditionOp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl ConditionOp {
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
            "ArnEquals" => Ok(Self::Arn(ArnCmp::Equals, Variant::None)),
            "ArnEqualsIfExists" => Ok(Self::Arn(ArnCmp::Equals, Variant::IfExists)),
            "ArnNotEquals" => Ok(Self::Arn(ArnCmp::Equals, Variant::Negated)),
            "ArnNotEqualsIfExists" => Ok(Self::Arn(ArnCmp::Equals, Variant::IfExistsNegated)),
            "ArnLike" => Ok(Self::Arn(ArnCmp::Like, Variant::None)),
            "ArnLikeIfExists" => Ok(Self::Arn(ArnCmp::Like, Variant::IfExists)),
            "ArnNotLike" => Ok(Self::Arn(ArnCmp::Like, Variant::Negated)),
            "ArnNotLikeIfExists" => Ok(Self::Arn(ArnCmp::Like, Variant::IfExistsNegated)),
            "BinaryEquals" => Ok(Self::Binary(Variant::None)),
            "BinaryEqualsIfExists" => Ok(Self::Binary(Variant::IfExists)),
            "Bool" => Ok(Self::Bool(Variant::None)),
            "BoolIfExists" => Ok(Self::Bool(Variant::IfExists)),
            "DateEquals" => Ok(Self::Date(DateCmp::Equals, Variant::None)),
            "DateEqualsIfExists" => Ok(Self::Date(DateCmp::Equals, Variant::IfExists)),
            "DateNotEquals" => Ok(Self::Date(DateCmp::Equals, Variant::Negated)),
            "DateNotEqualsIfExists" => Ok(Self::Date(DateCmp::Equals, Variant::IfExistsNegated)),
            "DateLessThan" => Ok(Self::Date(DateCmp::LessThan, Variant::None)),
            "DateLessThanIfExists" => Ok(Self::Date(DateCmp::LessThan, Variant::IfExists)),
            "DateGreaterThanEquals" => Ok(Self::Date(DateCmp::LessThan, Variant::Negated)),
            "DateGreaterThanEqualsIfExists" => Ok(Self::Date(DateCmp::LessThan, Variant::IfExistsNegated)),
            "DateLessThanEquals" => Ok(Self::Date(DateCmp::LessThanEquals, Variant::None)),
            "DateLessThanEqualsIfExists" => Ok(Self::Date(DateCmp::LessThanEquals, Variant::IfExists)),
            "DateGreaterThan" => Ok(Self::Date(DateCmp::LessThanEquals, Variant::Negated)),
            "DateGreaterThanIfExists" => Ok(Self::Date(DateCmp::LessThanEquals, Variant::IfExistsNegated)),
            "IpAddress" => Ok(Self::IpAddress(Variant::None)),
            "IpAddressIfExists" => Ok(Self::IpAddress(Variant::IfExists)),
            "NotIpAddress" => Ok(Self::IpAddress(Variant::Negated)),
            "NotIpAddressIfExists" => Ok(Self::IpAddress(Variant::IfExistsNegated)),
            "Null" => Ok(Self::Null),
            "NumericEquals" => Ok(Self::Numeric(NumericCmp::Equals, Variant::None)),
            "NumericEqualsIfExists" => Ok(Self::Numeric(NumericCmp::Equals, Variant::IfExists)),
            "NumericNotEquals" => Ok(Self::Numeric(NumericCmp::Equals, Variant::Negated)),
            "NumericNotEqualsIfExists" => Ok(Self::Numeric(NumericCmp::Equals, Variant::IfExistsNegated)),
            "NumericLessThan" => Ok(Self::Numeric(NumericCmp::LessThan, Variant::None)),
            "NumericLessThanIfExists" => Ok(Self::Numeric(NumericCmp::LessThan, Variant::IfExists)),
            "NumericGreaterThanEquals" => Ok(Self::Numeric(NumericCmp::LessThan, Variant::Negated)),
            "NumericGreaterThanEqualsIfExists" => Ok(Self::Numeric(NumericCmp::LessThan, Variant::IfExistsNegated)),
            "NumericLessThanEquals" => Ok(Self::Numeric(NumericCmp::LessThanEquals, Variant::None)),
            "NumericLessThanEqualsIfExists" => Ok(Self::Numeric(NumericCmp::LessThanEquals, Variant::IfExists)),
            "NumericGreaterThan" => Ok(Self::Numeric(NumericCmp::LessThanEquals, Variant::Negated)),
            "NumericGreaterThanIfExists" => Ok(Self::Numeric(NumericCmp::LessThanEquals, Variant::IfExistsNegated)),
            "StringEquals" => Ok(Self::String(StringCmp::Equals, Variant::None)),
            "StringEqualsIfExists" => Ok(Self::String(StringCmp::Equals, Variant::IfExists)),
            "StringNotEquals" => Ok(Self::String(StringCmp::Equals, Variant::Negated)),
            "StringNotEqualsIfExists" => Ok(Self::String(StringCmp::Equals, Variant::IfExistsNegated)),
            "StringEqualsIgnoreCase" => Ok(Self::String(StringCmp::EqualsIgnoreCase, Variant::None)),
            "StringEqualsIgnoreCaseIfExists" => Ok(Self::String(StringCmp::EqualsIgnoreCase, Variant::IfExists)),
            "StringNotEqualsIgnoreCase" => Ok(Self::String(StringCmp::EqualsIgnoreCase, Variant::Negated)),
            "StringNotEqualsIgnoreCaseIfExists" => {
                Ok(Self::String(StringCmp::EqualsIgnoreCase, Variant::IfExistsNegated))
            }
            "StringLike" => Ok(Self::String(StringCmp::Like, Variant::None)),
            "StringLikeIfExists" => Ok(Self::String(StringCmp::Like, Variant::IfExists)),
            "StringNotLike" => Ok(Self::String(StringCmp::Like, Variant::Negated)),
            "StringNotLikeIfExists" => Ok(Self::String(StringCmp::Like, Variant::IfExistsNegated)),
            _ => Err(AspenError::InvalidConditionOperator(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::condition::{
            arn::ArnCmp, date::DateCmp, numeric::NumericCmp, op::ConditionOp, string::StringCmp, variant::Variant,
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
