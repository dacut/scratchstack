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
        cmp::Ordering,
        collections::BTreeMap,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl PartialEq<&str> for ConditionOp {
    fn eq(&self, other: &&str) -> bool {
        self.to_string().as_str() == *other
    }
}

impl PartialOrd for ConditionOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        <Self as Borrow<str>>::borrow(self).partial_cmp(<Self as Borrow<str>>::borrow(other))
    }
}

impl Ord for ConditionOp {
    fn cmp(&self, other: &Self) -> Ordering {
        <Self as Borrow<str>>::borrow(self).cmp(<Self as Borrow<str>>::borrow(other))
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
