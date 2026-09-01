use {
    super::{
        arn::{ArnCmp, arn_match},
        binary::{BINARY_DISPLAY_NAMES, binary_match},
        boolean::{BOOL_DISPLAY_NAMES, bool_match},
        date::{DateCmp, date_match},
        ipaddr::{IP_ADDRESS_DISPLAY_NAMES, ip_address_match},
        null::{NULL_DISPLAY_NAMES, null_match},
        numeric::{NumericCmp, numeric_match},
        setop::{FOR_ALL_VALUES_PREFIX, FOR_ANY_VALUE_PREFIX, SetOperator},
        string::{StringCmp, string_match},
        variant::{IfExists, Variant},
    },
    crate::{AspenError, Context, PolicyVersion, serutil::StringLikeList},
    scratchstack_aws_principal::SessionValue,
    serde::{
        Deserialize, Serialize,
        de::{self, Deserializer},
        ser::Serializer,
    },
    std::{
        collections::BTreeMap,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        slice,
        str::FromStr,
    },
};

/// The comparison a condition clause operator performs on a condition key's value.
///
/// This is the operator name with any set operator prefix stripped off: the `StringEquals` of
/// `ForAllValues:StringEquals`. See [`ConditionOp`] for the operator as a whole.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ConditionCmp {
    /// Operators for ARNs.
    Arn(ArnCmp, Variant),

    /// Operators for binary values. AWS defines no negated form, so this carries an [`IfExists`]
    /// rather than a [`Variant`].
    Binary(IfExists),

    /// Operators on boolean values. AWS defines no negated form, so this carries an [`IfExists`]
    /// rather than a [`Variant`].
    Bool(IfExists),

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

/// An operator for a condition clause.
///
/// An operator is a comparison -- [`ConditionCmp`] -- optionally qualified by a [`SetOperator`]
/// naming how the comparison is applied to a multivalued condition key. The [`op`][self] module
/// holds a constant for each unqualified operator; [`ConditionOp::for_all_values`] and
/// [`ConditionOp::for_any_value`] qualify one.
///
/// # Examples
///
/// ```
/// # use scratchstack_aspen::{condop, ConditionOp};
/// # use std::str::FromStr;
/// assert_eq!(ConditionOp::from_str("StringEquals").unwrap(), condop::StringEquals);
/// assert_eq!(
///     ConditionOp::from_str("ForAllValues:StringEquals").unwrap(),
///     condop::StringEquals.for_all_values()
/// );
/// assert_eq!(condop::StringLike.for_any_value().to_string(), "ForAnyValue:StringLike");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConditionOp {
    /// The comparison applied to the condition key's value.
    comparison: ConditionCmp,

    /// The set operator naming how the comparison is applied to a multivalued key.
    set_op: SetOperator,
}

/// The `ArnEquals` operator.
pub const ArnEquals: ConditionOp = ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Equals, Variant::None));

/// The `ArnEqualsIfExists` operator.
pub const ArnEqualsIfExists: ConditionOp = ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Equals, Variant::IfExists));

/// The `ArnNotEquals` operator.
pub const ArnNotEquals: ConditionOp = ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Equals, Variant::Negated));

/// The `ArnNotEqualsIfExists` operator.
pub const ArnNotEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Equals, Variant::IfExistsNegated));

/// The `ArnLike` operator.
pub const ArnLike: ConditionOp = ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Like, Variant::None));

/// The `ArnLikeIfExists` operator.
pub const ArnLikeIfExists: ConditionOp = ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Like, Variant::IfExists));

/// The `ArnNotLike` operator.
pub const ArnNotLike: ConditionOp = ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Like, Variant::Negated));

/// The `ArnNotLikeIfExists` operator.
pub const ArnNotLikeIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Arn(ArnCmp::Like, Variant::IfExistsNegated));

/// The `BinaryEquals` operator.
pub const BinaryEquals: ConditionOp = ConditionOp::plain(ConditionCmp::Binary(IfExists::No));

/// The `BinaryEqualsIfExists` operator.
pub const BinaryEqualsIfExists: ConditionOp = ConditionOp::plain(ConditionCmp::Binary(IfExists::Yes));

/// The `Bool` operator.
pub const Bool: ConditionOp = ConditionOp::plain(ConditionCmp::Bool(IfExists::No));

/// The `BoolIfExists` operator.
pub const BoolIfExists: ConditionOp = ConditionOp::plain(ConditionCmp::Bool(IfExists::Yes));

/// The `DateEquals` operator.
pub const DateEquals: ConditionOp = ConditionOp::plain(ConditionCmp::Date(DateCmp::Equals, Variant::None));

/// The `DateEqualsIfExists` operator.
pub const DateEqualsIfExists: ConditionOp = ConditionOp::plain(ConditionCmp::Date(DateCmp::Equals, Variant::IfExists));

/// The `DateNotEquals` operator.
pub const DateNotEquals: ConditionOp = ConditionOp::plain(ConditionCmp::Date(DateCmp::Equals, Variant::Negated));

/// The `DateNotEqualsIfExists` operator.
pub const DateNotEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::Equals, Variant::IfExistsNegated));

/// The `DateLessThan` operator.
pub const DateLessThan: ConditionOp = ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThan, Variant::None));

/// The `DateLessThanIfExists` operator.
pub const DateLessThanIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThan, Variant::IfExists));

/// The `DateGreaterThanEquals` operator.
pub const DateGreaterThanEquals: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThan, Variant::Negated));

/// The `DateGreaterThanEqualsIfExists` operator.
pub const DateGreaterThanEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThan, Variant::IfExistsNegated));

/// The `DateLessThanEquals` operator.
pub const DateLessThanEquals: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThanEquals, Variant::None));

/// The `DateLessThanEqualsIfExists` operator.
pub const DateLessThanEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThanEquals, Variant::IfExists));

/// The `DateGreaterThan` operator.
pub const DateGreaterThan: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThanEquals, Variant::Negated));

/// The `DateGreaterThanIfExists` operator.
pub const DateGreaterThanIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Date(DateCmp::LessThanEquals, Variant::IfExistsNegated));

/// The `IpAddress` operator.
pub const IpAddress: ConditionOp = ConditionOp::plain(ConditionCmp::IpAddress(Variant::None));

/// The `IpAddressIfExists` operator.
pub const IpAddressIfExists: ConditionOp = ConditionOp::plain(ConditionCmp::IpAddress(Variant::IfExists));

/// The `NotIpAddress` operator.
pub const NotIpAddress: ConditionOp = ConditionOp::plain(ConditionCmp::IpAddress(Variant::Negated));

/// The `NotIpAddressIfExists` operator.
pub const NotIpAddressIfExists: ConditionOp = ConditionOp::plain(ConditionCmp::IpAddress(Variant::IfExistsNegated));

/// The `Null` operator.
pub const Null: ConditionOp = ConditionOp::plain(ConditionCmp::Null);

/// The `NumericEquals` operator.
pub const NumericEquals: ConditionOp = ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::Equals, Variant::None));

/// The `NumericEqualsIfExists` operator.
pub const NumericEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::Equals, Variant::IfExists));

/// The `NumericNotEquals` operator.
pub const NumericNotEquals: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::Equals, Variant::Negated));

/// The `NumericNotEqualsIfExists` operator.
pub const NumericNotEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::Equals, Variant::IfExistsNegated));

/// The `NumericLessThan` operator.
pub const NumericLessThan: ConditionOp = ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThan, Variant::None));

/// The `NumericLessThanIfExists` operator.
pub const NumericLessThanIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThan, Variant::IfExists));

/// The `NumericGreaterThanEquals` operator.
pub const NumericGreaterThanEquals: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThan, Variant::Negated));

/// The `NumericGreaterThanEqualsIfExists` operator.
pub const NumericGreaterThanEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThan, Variant::IfExistsNegated));

/// The `NumericLessThanEquals` operator.
pub const NumericLessThanEquals: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::None));

/// The `NumericLessThanEqualsIfExists` operator.
pub const NumericLessThanEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::IfExists));

/// The `NumericGreaterThan` operator.
pub const NumericGreaterThan: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::Negated));

/// The `NumericGreaterThanIfExists` operator.
pub const NumericGreaterThanIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::IfExistsNegated));

/// The `StringEquals` operator.
pub const StringEquals: ConditionOp = ConditionOp::plain(ConditionCmp::String(StringCmp::Equals, Variant::None));

/// The `StringEqualsIfExists` operator.
pub const StringEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::Equals, Variant::IfExists));

/// The `StringNotEquals` operator.
pub const StringNotEquals: ConditionOp = ConditionOp::plain(ConditionCmp::String(StringCmp::Equals, Variant::Negated));

/// The `StringNotEqualsIfExists` operator.
pub const StringNotEqualsIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::Equals, Variant::IfExistsNegated));

/// The `StringEqualsIgnoreCase` operator.
pub const StringEqualsIgnoreCase: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::None));

/// The `StringEqualsIgnoreCaseIfExists` operator.
pub const StringEqualsIgnoreCaseIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::IfExists));

/// The `StringNotEqualsIgnoreCase` operator.
pub const StringNotEqualsIgnoreCase: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::Negated));

/// The `StringNotEqualsIgnoreCaseIfExists` operator.
pub const StringNotEqualsIgnoreCaseIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::IfExistsNegated));

/// The `StringLike` operator.
pub const StringLike: ConditionOp = ConditionOp::plain(ConditionCmp::String(StringCmp::Like, Variant::None));

/// The `StringLikeIfExists` operator.
pub const StringLikeIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::Like, Variant::IfExists));

/// The `StringNotLike` operator.
pub const StringNotLike: ConditionOp = ConditionOp::plain(ConditionCmp::String(StringCmp::Like, Variant::Negated));

/// The `StringNotLikeIfExists` operator.
pub const StringNotLikeIfExists: ConditionOp =
    ConditionOp::plain(ConditionCmp::String(StringCmp::Like, Variant::IfExistsNegated));

impl PartialEq<str> for ConditionOp {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl Display for ConditionOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(self.as_str())
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
    /// Returns the operator applying `cmp` to each value of a multivalued key as `set_op` directs.
    #[inline]
    pub const fn new(comparison: ConditionCmp, set_op: SetOperator) -> Self {
        Self {
            comparison,
            set_op,
        }
    }

    /// Returns the operator applying `cmp` with no set operator qualifying it.
    #[inline]
    pub const fn plain(comparison: ConditionCmp) -> Self {
        Self::new(comparison, SetOperator::None)
    }

    /// Returns the comparison this operator performs on a condition key's value.
    #[inline]
    pub const fn comparison(&self) -> ConditionCmp {
        self.comparison
    }

    /// Returns the set operator qualifying this operator, if any.
    #[inline]
    pub const fn set_operator(&self) -> SetOperator {
        self.set_op
    }

    /// Returns the name this operator is written with in a policy document.
    ///
    /// The name carries the set operator's prefix, if any: `ForAllValues:StringEquals`.
    ///
    /// Every operator has a name. The comparisons AWS defines in fewer than four forms carry a
    /// variant type with no more values than they have names -- see [`ConditionCmp::Binary`] --
    /// so there is no combination left for this to fail on.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        self.comparison.display_name(self.set_op)
    }

    /// Returns this operator qualified by [`SetOperator::ForAllValues`]: it matches only if every
    /// value of the condition key matches.
    #[inline]
    pub const fn for_all_values(self) -> Self {
        Self::new(self.comparison, SetOperator::ForAllValues)
    }

    /// Returns this operator qualified by [`SetOperator::ForAnyValue`]: it matches if at least one
    /// value of the condition key matches.
    #[inline]
    pub const fn for_any_value(self) -> Self {
        Self::new(self.comparison, SetOperator::ForAnyValue)
    }

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
            let value = context.session_data().get(&key).unwrap_or(&NULL);

            if !self.matches_key(context, pv, allowed, value)? {
                sensitive_trace!(
                    "Condition key {key:?} with allowed values {allowed:?} did not match session_data={:?}",
                    context.session_data()
                );
                return Ok(false);
            }

            sensitive_trace!(
                "Condition key {key:?} with allowed values {allowed:?} matched session_data={:?}",
                context.session_data()
            );
        }

        Ok(true)
    }

    /// Indicates whether the `value` a single condition key holds satisfies this operator against
    /// the `allowed` values the policy lists.
    fn matches_key(
        &self,
        context: &Context,
        pv: PolicyVersion,
        allowed: &StringLikeList<String>,
        value: &SessionValue,
    ) -> Result<bool, AspenError> {
        // A multivalued key holding no values says no more than an absent key does. Treating the
        // two alike keeps the answer from depending on whether the caller supplied an empty set or
        // nothing at all.
        let value = if value.is_null() {
            &NULL
        } else {
            value
        };

        // Null asks whether the key is present at all instead of comparing the values it holds, so
        // a set operator has nothing to distribute over: it evaluates the key as a whole, exactly
        // as the unqualified operator does.
        if matches!(self.comparison, ConditionCmp::Null) {
            return self.comparison.matches_value(context, pv, allowed, value);
        }

        match self.set_op {
            // Without a set operator the key is compared as a single value. A multivalued key
            // reaching a comparison that has no notion of a set matches nothing, which is what
            // each comparison does with a value of a type it cannot compare.
            SetOperator::None => self.comparison.matches_value(context, pv, allowed, value),

            SetOperator::ForAllValues => {
                for value in values_of(value) {
                    if !self.comparison.matches_value(context, pv, allowed, value)? {
                        return Ok(false);
                    }
                }

                // A key with no values matches vacuously.
                Ok(true)
            }

            SetOperator::ForAnyValue => {
                let values = values_of(value);
                for value in values {
                    if self.comparison.matches_value(context, pv, allowed, value)? {
                        return Ok(true);
                    }
                }

                // A key with no values has nothing to match, so the condition fails -- unless the
                // comparison carries the IfExists variant, whose whole purpose is to pass over a
                // key the request did not supply.
                Ok(values.is_empty() && self.comparison.if_exists())
            }
        }
    }
}

/// Returns the values a condition key holds, as a set operator sees them.
///
/// A single-valued key is a set of one; an absent key is the empty set.
fn values_of(value: &SessionValue) -> &[SessionValue] {
    match value {
        SessionValue::List(values) => values.as_slice(),
        SessionValue::Null => &[],
        value => slice::from_ref(value),
    }
}

impl ConditionCmp {
    /// Returns the name of this comparison under the given set operator.
    const fn display_name(&self, set_op: SetOperator) -> &'static str {
        match self {
            Self::Arn(cmp, variant) => cmp.display_name(set_op, variant),
            Self::Binary(if_exists) => BINARY_DISPLAY_NAMES[if_exists.as_usize()].name(set_op),
            Self::Bool(if_exists) => BOOL_DISPLAY_NAMES[if_exists.as_usize()].name(set_op),
            Self::Date(cmp, variant) => cmp.display_name(set_op, variant),
            Self::IpAddress(variant) => IP_ADDRESS_DISPLAY_NAMES[variant.as_usize()].name(set_op),
            Self::Null => NULL_DISPLAY_NAMES.name(set_op),
            Self::Numeric(cmp, variant) => cmp.display_name(set_op, variant),
            Self::String(cmp, variant) => cmp.display_name(set_op, variant),
        }
    }

    /// Indicates whether this comparison carries the `IfExists` suffix, which passes over a key
    /// the request did not supply.
    ///
    /// [`ConditionCmp::Null`] asks whether the key is present at all, so `IfExists` has nothing to
    /// add to it and it reports `false`.
    fn if_exists(&self) -> bool {
        match self {
            Self::Arn(_, variant)
            | Self::Date(_, variant)
            | Self::IpAddress(variant)
            | Self::Numeric(_, variant)
            | Self::String(_, variant) => variant.if_exists(),
            Self::Binary(if_exists) | Self::Bool(if_exists) => if_exists.if_exists(),
            Self::Null => false,
        }
    }

    /// Indicates whether a single `value` of a condition key satisfies this comparison against the
    /// `allowed` values the policy lists.
    fn matches_value(
        &self,
        context: &Context,
        pv: PolicyVersion,
        allowed: &StringLikeList<String>,
        value: &SessionValue,
    ) -> Result<bool, AspenError> {
        match self {
            Self::Arn(cmp, variant) => arn_match(context, pv, allowed, value, *cmp, *variant),
            Self::Binary(if_exists) => binary_match(context, pv, allowed, value, *if_exists),
            Self::Bool(if_exists) => bool_match(context, pv, allowed, value, *if_exists),
            Self::Date(cmp, variant) => date_match(context, pv, allowed, value, *cmp, *variant),
            Self::IpAddress(variant) => ip_address_match(context, pv, allowed, value, *variant),
            Self::Null => null_match(context, pv, allowed, value),
            Self::Numeric(cmp, variant) => numeric_match(context, pv, allowed, value, *cmp, *variant),
            Self::String(cmp, variant) => string_match(context, pv, allowed, value, *cmp, *variant),
        }
    }
}

impl FromStr for ConditionOp {
    type Err = AspenError;

    /// Parses an operator name, which is a comparison optionally prefixed by a set operator:
    /// `StringEquals`, `ForAllValues:StringEquals`, or `ForAnyValue:StringEquals`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (set_op, cmp) = match s.split_once(':') {
            Some((FOR_ALL_VALUES_PREFIX, cmp)) => (SetOperator::ForAllValues, cmp),
            Some((FOR_ANY_VALUE_PREFIX, cmp)) => (SetOperator::ForAnyValue, cmp),
            _ => (SetOperator::None, s),
        };

        // Report the operator as it was written, prefix and all, rather than the part that failed
        // to parse.
        let cmp = cmp_from_str(cmp).ok_or_else(|| AspenError::InvalidConditionOperator(s.to_string()))?;

        Ok(Self::new(cmp, set_op))
    }
}

/// Returns the comparison the given operator name performs, with any set operator prefix already
/// stripped off, or [`None`] if no operator goes by that name.
fn cmp_from_str(s: &str) -> Option<ConditionCmp> {
    match s {
        "ArnEquals" => Some(ArnEquals.comparison),
        "ArnEqualsIfExists" => Some(ArnEqualsIfExists.comparison),
        "ArnNotEquals" => Some(ArnNotEquals.comparison),
        "ArnNotEqualsIfExists" => Some(ArnNotEqualsIfExists.comparison),
        "ArnLike" => Some(ArnLike.comparison),
        "ArnLikeIfExists" => Some(ArnLikeIfExists.comparison),
        "ArnNotLike" => Some(ArnNotLike.comparison),
        "ArnNotLikeIfExists" => Some(ArnNotLikeIfExists.comparison),
        "BinaryEquals" => Some(BinaryEquals.comparison),
        "BinaryEqualsIfExists" => Some(BinaryEqualsIfExists.comparison),
        "Bool" => Some(Bool.comparison),
        "BoolIfExists" => Some(BoolIfExists.comparison),
        "DateEquals" => Some(DateEquals.comparison),
        "DateEqualsIfExists" => Some(DateEqualsIfExists.comparison),
        "DateNotEquals" => Some(DateNotEquals.comparison),
        "DateNotEqualsIfExists" => Some(DateNotEqualsIfExists.comparison),
        "DateLessThan" => Some(DateLessThan.comparison),
        "DateLessThanIfExists" => Some(DateLessThanIfExists.comparison),
        "DateGreaterThanEquals" => Some(DateGreaterThanEquals.comparison),
        "DateGreaterThanEqualsIfExists" => Some(DateGreaterThanEqualsIfExists.comparison),
        "DateLessThanEquals" => Some(DateLessThanEquals.comparison),
        "DateLessThanEqualsIfExists" => Some(DateLessThanEqualsIfExists.comparison),
        "DateGreaterThan" => Some(DateGreaterThan.comparison),
        "DateGreaterThanIfExists" => Some(DateGreaterThanIfExists.comparison),
        "IpAddress" => Some(IpAddress.comparison),
        "IpAddressIfExists" => Some(IpAddressIfExists.comparison),
        "NotIpAddress" => Some(NotIpAddress.comparison),
        "NotIpAddressIfExists" => Some(NotIpAddressIfExists.comparison),
        "Null" => Some(Null.comparison),
        "NumericEquals" => Some(NumericEquals.comparison),
        "NumericEqualsIfExists" => Some(NumericEqualsIfExists.comparison),
        "NumericNotEquals" => Some(NumericNotEquals.comparison),
        "NumericNotEqualsIfExists" => Some(NumericNotEqualsIfExists.comparison),
        "NumericLessThan" => Some(NumericLessThan.comparison),
        "NumericLessThanIfExists" => Some(NumericLessThanIfExists.comparison),
        "NumericGreaterThanEquals" => Some(NumericGreaterThanEquals.comparison),
        "NumericGreaterThanEqualsIfExists" => Some(NumericGreaterThanEqualsIfExists.comparison),
        "NumericLessThanEquals" => Some(NumericLessThanEquals.comparison),
        "NumericLessThanEqualsIfExists" => Some(NumericLessThanEqualsIfExists.comparison),
        "NumericGreaterThan" => Some(NumericGreaterThan.comparison),
        "NumericGreaterThanIfExists" => Some(NumericGreaterThanIfExists.comparison),
        "StringEquals" => Some(StringEquals.comparison),
        "StringEqualsIfExists" => Some(StringEqualsIfExists.comparison),
        "StringNotEquals" => Some(StringNotEquals.comparison),
        "StringNotEqualsIfExists" => Some(StringNotEqualsIfExists.comparison),
        "StringEqualsIgnoreCase" => Some(StringEqualsIgnoreCase.comparison),
        "StringEqualsIgnoreCaseIfExists" => Some(StringEqualsIgnoreCaseIfExists.comparison),
        "StringNotEqualsIgnoreCase" => Some(StringNotEqualsIgnoreCase.comparison),
        "StringNotEqualsIgnoreCaseIfExists" => Some(StringNotEqualsIgnoreCaseIfExists.comparison),
        "StringLike" => Some(StringLike.comparison),
        "StringLikeIfExists" => Some(StringLikeIfExists.comparison),
        "StringNotLike" => Some(StringNotLike.comparison),
        "StringNotLikeIfExists" => Some(StringNotLikeIfExists.comparison),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            AspenError,
            condition::{
                arn::ArnCmp,
                date::DateCmp,
                numeric::NumericCmp,
                op::{ConditionCmp, ConditionOp},
                setop::SetOperator,
                string::StringCmp,
                variant::{IfExists, Variant},
            },
            condop,
        },
        pretty_assertions::assert_eq,
        std::{
            cmp::{Ordering, PartialOrd},
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            str::FromStr,
        },
    };

    #[test_log::test]
    fn test_derived() {
        let cmps = vec![
            (ConditionCmp::Arn(ArnCmp::Equals, Variant::None), "Arn(Equals, None)"),
            (ConditionCmp::Arn(ArnCmp::Equals, Variant::IfExists), "Arn(Equals, IfExists)"),
            (ConditionCmp::Arn(ArnCmp::Equals, Variant::Negated), "Arn(Equals, Negated)"),
            (ConditionCmp::Arn(ArnCmp::Equals, Variant::IfExistsNegated), "Arn(Equals, IfExistsNegated)"),
            (ConditionCmp::Arn(ArnCmp::Like, Variant::None), "Arn(Like, None)"),
            (ConditionCmp::Arn(ArnCmp::Like, Variant::IfExists), "Arn(Like, IfExists)"),
            (ConditionCmp::Arn(ArnCmp::Like, Variant::Negated), "Arn(Like, Negated)"),
            (ConditionCmp::Arn(ArnCmp::Like, Variant::IfExistsNegated), "Arn(Like, IfExistsNegated)"),
            (ConditionCmp::Binary(IfExists::No), "Binary(No)"),
            (ConditionCmp::Binary(IfExists::Yes), "Binary(Yes)"),
            (ConditionCmp::Bool(IfExists::No), "Bool(No)"),
            (ConditionCmp::Bool(IfExists::Yes), "Bool(Yes)"),
            (ConditionCmp::Date(DateCmp::Equals, Variant::None), "Date(Equals, None)"),
            (ConditionCmp::Date(DateCmp::Equals, Variant::IfExists), "Date(Equals, IfExists)"),
            (ConditionCmp::Date(DateCmp::Equals, Variant::Negated), "Date(Equals, Negated)"),
            (ConditionCmp::Date(DateCmp::Equals, Variant::IfExistsNegated), "Date(Equals, IfExistsNegated)"),
            (ConditionCmp::Date(DateCmp::LessThan, Variant::None), "Date(LessThan, None)"),
            (ConditionCmp::Date(DateCmp::LessThan, Variant::IfExists), "Date(LessThan, IfExists)"),
            (ConditionCmp::Date(DateCmp::LessThan, Variant::Negated), "Date(LessThan, Negated)"),
            (ConditionCmp::Date(DateCmp::LessThan, Variant::IfExistsNegated), "Date(LessThan, IfExistsNegated)"),
            (ConditionCmp::Date(DateCmp::LessThanEquals, Variant::None), "Date(LessThanEquals, None)"),
            (ConditionCmp::Date(DateCmp::LessThanEquals, Variant::IfExists), "Date(LessThanEquals, IfExists)"),
            (ConditionCmp::Date(DateCmp::LessThanEquals, Variant::Negated), "Date(LessThanEquals, Negated)"),
            (
                ConditionCmp::Date(DateCmp::LessThanEquals, Variant::IfExistsNegated),
                "Date(LessThanEquals, IfExistsNegated)",
            ),
            (ConditionCmp::IpAddress(Variant::None), "IpAddress(None)"),
            (ConditionCmp::IpAddress(Variant::IfExists), "IpAddress(IfExists)"),
            (ConditionCmp::IpAddress(Variant::Negated), "IpAddress(Negated)"),
            (ConditionCmp::IpAddress(Variant::IfExistsNegated), "IpAddress(IfExistsNegated)"),
            (ConditionCmp::Null, "Null"),
            (ConditionCmp::Numeric(NumericCmp::Equals, Variant::None), "Numeric(Equals, None)"),
            (ConditionCmp::Numeric(NumericCmp::Equals, Variant::IfExists), "Numeric(Equals, IfExists)"),
            (ConditionCmp::Numeric(NumericCmp::Equals, Variant::Negated), "Numeric(Equals, Negated)"),
            (ConditionCmp::Numeric(NumericCmp::Equals, Variant::IfExistsNegated), "Numeric(Equals, IfExistsNegated)"),
            (ConditionCmp::Numeric(NumericCmp::LessThan, Variant::None), "Numeric(LessThan, None)"),
            (ConditionCmp::Numeric(NumericCmp::LessThan, Variant::IfExists), "Numeric(LessThan, IfExists)"),
            (ConditionCmp::Numeric(NumericCmp::LessThan, Variant::Negated), "Numeric(LessThan, Negated)"),
            (
                ConditionCmp::Numeric(NumericCmp::LessThan, Variant::IfExistsNegated),
                "Numeric(LessThan, IfExistsNegated)",
            ),
            (ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::None), "Numeric(LessThanEquals, None)"),
            (ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::IfExists), "Numeric(LessThanEquals, IfExists)"),
            (ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::Negated), "Numeric(LessThanEquals, Negated)"),
            (
                ConditionCmp::Numeric(NumericCmp::LessThanEquals, Variant::IfExistsNegated),
                "Numeric(LessThanEquals, IfExistsNegated)",
            ),
            (ConditionCmp::String(StringCmp::Equals, Variant::None), "String(Equals, None)"),
            (ConditionCmp::String(StringCmp::Equals, Variant::IfExists), "String(Equals, IfExists)"),
            (ConditionCmp::String(StringCmp::Equals, Variant::Negated), "String(Equals, Negated)"),
            (ConditionCmp::String(StringCmp::Equals, Variant::IfExistsNegated), "String(Equals, IfExistsNegated)"),
            (ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::None), "String(EqualsIgnoreCase, None)"),
            (
                ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::IfExists),
                "String(EqualsIgnoreCase, IfExists)",
            ),
            (ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::Negated), "String(EqualsIgnoreCase, Negated)"),
            (
                ConditionCmp::String(StringCmp::EqualsIgnoreCase, Variant::IfExistsNegated),
                "String(EqualsIgnoreCase, IfExistsNegated)",
            ),
            (ConditionCmp::String(StringCmp::Like, Variant::None), "String(Like, None)"),
            (ConditionCmp::String(StringCmp::Like, Variant::IfExists), "String(Like, IfExists)"),
            (ConditionCmp::String(StringCmp::Like, Variant::Negated), "String(Like, Negated)"),
            (ConditionCmp::String(StringCmp::Like, Variant::IfExistsNegated), "String(Like, IfExistsNegated)"),
        ];

        for (cmp, debug) in &cmps {
            assert_eq!(&format!("{cmp:?}"), debug);
        }

        // Every comparison can be qualified by every set operator, and operators order by
        // comparison first, then by the set operator qualifying it.
        let cops = cmps
            .iter()
            .flat_map(|(cmp, _)| {
                [SetOperator::None, SetOperator::ForAllValues, SetOperator::ForAnyValue]
                    .map(|set_op| (ConditionOp::new(*cmp, set_op), set_op))
            })
            .collect::<Vec<_>>();

        for (cop, set_op) in &cops {
            let comparison = cop.comparison();
            assert_eq!(cop.set_operator(), *set_op);
            assert_eq!(*cop, ConditionOp::new(comparison, *set_op));
            assert_eq!(ConditionOp::plain(comparison), ConditionOp::new(comparison, SetOperator::None));
            assert_eq!(cop.for_all_values(), ConditionOp::new(comparison, SetOperator::ForAllValues));
            assert_eq!(cop.for_any_value(), ConditionOp::new(comparison, SetOperator::ForAnyValue));
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
            assert_eq!(format!("{op}"), item);
            assert_eq!(&op, item);
            assert_eq!(op.set_operator(), SetOperator::None);

            // Every operator can be qualified by either set operator, which names it by the
            // prefix it is written with.
            for (set_op, name) in [
                (SetOperator::ForAllValues, format!("ForAllValues:{item}")),
                (SetOperator::ForAnyValue, format!("ForAnyValue:{item}")),
            ] {
                let set_operator_op = ConditionOp::from_str(&name).unwrap();
                assert_eq!(set_operator_op, ConditionOp::new(op.comparison(), set_op));
                assert_eq!(format!("{set_operator_op}"), name);
                assert_eq!(&set_operator_op, name.as_str());
            }
        }
    }

    /// A set operator is a prefix on an operator name; anything else in that position, and any
    /// misspelling of the operator itself, names no operator at all.
    #[test_log::test]
    fn test_invalid_operator_names() {
        for name in [
            "ForAllValues:Bogus",
            "ForAllValues:",
            "ForAllValues",
            // AWS spells this one in the singular; the plural is not an operator.
            "ForAnyValues:StringEquals",
            "ForAnyValue:ForAnyValue:StringEquals",
            "forallvalues:StringEquals",
            "Bogus:StringEquals",
            "StringEquals:",
            "",
        ] {
            assert_eq!(
                ConditionOp::from_str(name).unwrap_err(),
                AspenError::InvalidConditionOperator(name.to_string()),
                "expected {name} to be rejected"
            );
        }
    }
    /// Every operator that can be built has a name, and that name parses back to it.
    ///
    /// `as_str` indexes a table of names by the comparison and its variant, so a comparison paired
    /// with a variant the table has no row for would panic. The comparisons AWS defines in fewer
    /// than four forms carry a variant type with no more values than they have names -- `Binary`
    /// and `Bool` take an `IfExists`, not a `Variant` -- so there is no such pairing to build.
    /// `ConditionCmp::Binary(Variant::Negated)` does not compile.
    ///
    /// The round trip also pins the display tables to the order the discriminants index them in:
    /// a row out of place would name some other operator, and parse back to something else.
    #[test_log::test]
    fn test_every_operator_has_a_name_that_parses_back() {
        let mut comparisons = vec![ConditionCmp::Null];

        for variant in [Variant::None, Variant::IfExists, Variant::Negated, Variant::IfExistsNegated] {
            for arn in [ArnCmp::Equals, ArnCmp::Like] {
                comparisons.push(ConditionCmp::Arn(arn, variant));
            }
            for date in [DateCmp::Equals, DateCmp::LessThan, DateCmp::LessThanEquals] {
                comparisons.push(ConditionCmp::Date(date, variant));
            }
            for numeric in [NumericCmp::Equals, NumericCmp::LessThan, NumericCmp::LessThanEquals] {
                comparisons.push(ConditionCmp::Numeric(numeric, variant));
            }
            for string in [StringCmp::Equals, StringCmp::EqualsIgnoreCase, StringCmp::Like] {
                comparisons.push(ConditionCmp::String(string, variant));
            }
            comparisons.push(ConditionCmp::IpAddress(variant));
        }

        for if_exists in [IfExists::No, IfExists::Yes] {
            comparisons.push(ConditionCmp::Binary(if_exists));
            comparisons.push(ConditionCmp::Bool(if_exists));
        }

        // 1 Null + 4 variants * (2 Arn + 3 Date + 3 Numeric + 3 String + 1 IpAddress) + 2 Binary
        // + 2 Bool.
        assert_eq!(comparisons.len(), 53);

        let mut names = Vec::with_capacity(comparisons.len() * 3);
        for comparison in comparisons {
            for set_op in [SetOperator::None, SetOperator::ForAllValues, SetOperator::ForAnyValue] {
                let op = ConditionOp::new(comparison, set_op);
                let name = op.as_str();
                assert!(!name.is_empty(), "{op:?} has an empty name");
                assert_eq!(ConditionOp::from_str(name).unwrap(), op, "{name} did not parse back to {op:?}");
                names.push(name);
            }
        }

        // No two operators answer to the same name.
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "two operators share a name");
    }
}
