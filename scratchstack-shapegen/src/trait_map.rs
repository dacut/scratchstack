use {
    crate::{LengthConstraint, RangeConstraint, TraitId},
    serde::{Deserialize, Serialize},
    serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue},
    std::collections::BTreeMap,
};

/// A map of trait identifiers to their corresponding values.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[repr(transparent)]
pub struct TraitMap(BTreeMap<TraitId, JsonValue>);

impl TraitMap {
    /// Creates a new, empty `TraitMap`.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Returns the AwsQueryError information if present on these traits.
    #[inline(always)]
    pub fn aws_query_error(&self) -> Option<JsonValue> {
        self.0.get(&TraitId::AwsProtocolsAwsQueryError).cloned()
    }

    /// Sets the AwsQueryError information for these traits.
    pub fn set_aws_query_error(&mut self, error_info: JsonValue) {
        self.0.insert(TraitId::AwsProtocolsAwsQueryError, error_info);
    }

    /// Returns the enum value, if any, from these traits.
    #[inline(always)]
    pub fn enum_value(&self) -> Option<JsonValue> {
        self.0.get(&TraitId::SmithyApiEnumValue).cloned()
    }

    /// Returns the enum value as an integer, if any, from these traits.
    #[inline(always)]
    pub fn enum_value_as_i64(&self) -> Option<i64> {
        self.enum_value().and_then(|v| v.as_i64())
    }

    /// Returns the documentation as a string, if any, from these traits.
    #[inline(always)]
    pub fn documentation(&self) -> Option<&str> {
        self.0.get(&TraitId::SmithyApiDocumentation).and_then(|v| v.as_str())
    }

    /// Sets the documentation for these traits.
    pub fn set_documentation(&mut self, documentation: impl Into<String>) {
        self.0.insert(TraitId::SmithyApiDocumentation, JsonValue::String(documentation.into()));
    }

    /// If this trait has an error marker, return it.
    #[inline(always)]
    pub fn error(&self) -> Option<String> {
        let value = self.0.get(&TraitId::SmithyApiError)?;
        let error =
            value.as_str().unwrap_or_else(|| panic!("smithy.api#error must be a string, got {value}")).to_string();
        Some(error)
    }

    /// Sets the error marker for these traits.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.0.insert(TraitId::SmithyApiError, JsonValue::String(error.into()));
    }

    /// Returns the HTTP error code, if any, from these traits.
    pub fn http_error(&self) -> Option<u16> {
        Some(self.0.get(&TraitId::SmithyApiHttpError)?.as_u64()? as u16)
    }

    /// Sets the HTTP error code for these traits.
    pub fn set_http_error(&mut self, code: u16) {
        self.0.insert(TraitId::SmithyApiHttpError, JsonValue::Number(JsonNumber::from_u128(code as u128).unwrap()));
    }

    /// Indicates whether the trait map has a required constraint.
    #[inline(always)]
    pub fn is_required(&self) -> bool {
        self.0.contains_key(&TraitId::SmithyApiRequired)
    }

    /// Sets or clears the required flag from the trait map.
    #[inline(always)]
    pub fn set_required(&mut self, required: bool) {
        if required {
            self.0.insert(TraitId::SmithyApiRequired, JsonValue::Object(JsonMap::new()));
        } else {
            self.0.remove(&TraitId::SmithyApiRequired);
        }
    }

    /// Returns the length constraint, if any, from these traits.
    pub fn length_constraint(&self) -> Option<LengthConstraint> {
        let length = self.0.get(&TraitId::SmithyApiLength)?.as_object()?;
        let mut result = LengthConstraint::default();

        if let Some(min) = length.get("min").and_then(|v| v.as_u64()) {
            result.min = Some(min as usize);
        }
        if let Some(max) = length.get("max").and_then(|v| v.as_u64()) {
            result.max = Some(max as usize);
        }

        Some(result)
    }

    /// Sets the length constraint for these traits.
    pub fn set_length_constraint(&mut self, lc: LengthConstraint) {
        let mut inner = JsonMap::new();
        if let Some(min) = lc.min {
            inner.insert("min".to_string(), JsonValue::Number(JsonNumber::from_u128(min as u128).unwrap()));
        }
        if let Some(max) = lc.max {
            inner.insert("max".to_string(), JsonValue::Number(JsonNumber::from_u128(max as u128).unwrap()));
        }
        let value = JsonValue::Object(inner);
        self.0.insert(TraitId::SmithyApiLength, value);
    }

    /// Returns the pattern regular expression, if any, for this shape.
    pub fn pattern(&self) -> Option<&str> {
        self.0.get(&TraitId::SmithyApiPattern).and_then(|v| v.as_str())
    }

    /// Sets the pattern regular expression for this shape.
    pub fn set_pattern(&mut self, pattern: impl Into<String>) {
        self.0.insert(TraitId::SmithyApiPattern, JsonValue::String(pattern.into()));
    }

    /// Returns the range constraint, if any, for this shape.
    pub fn range_constraint(&self) -> Option<RangeConstraint> {
        let range = self.0.get(&TraitId::SmithyApiRange)?.as_object()?;
        let mut result = RangeConstraint::default();

        if let Some(min) = range.get("min").and_then(|v| v.as_i64()) {
            result.min = Some(min);
        }
        if let Some(max) = range.get("max").and_then(|v| v.as_i64()) {
            result.max = Some(max);
        }

        Some(result)
    }

    /// Returns the API XML namespace, if any, for this shape.
    ///
    /// Only the service shape carries this in practice; every other shape in the model inherits it
    /// via [`SmithyModel::xmlns`](crate::SmithyModel::xmlns).
    pub fn xml_namespace(&self) -> Option<&str> {
        self.0.get(&TraitId::SmithyApiXmlNamespace)?.as_object()?.get("uri")?.as_str()
    }

    /// Indicates whether the trait map has an AWS Query Error marker.
    #[inline(always)]
    pub fn is_aws_query_error(&self) -> bool {
        self.0.contains_key(&TraitId::AwsProtocolsAwsQueryError)
    }

    /// Indicates whether the trait map is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Indicates whether the trait map has an error marker.
    #[inline(always)]
    pub fn is_error(&self) -> bool {
        self.0.contains_key(&TraitId::SmithyApiError)
    }

    /// Indicates whether the trait map has an input marker.
    #[inline(always)]
    pub fn is_input(&self) -> bool {
        self.0.contains_key(&TraitId::SmithyApiInput)
    }

    /// Indicates whether the trait map has an output marker.
    #[inline(always)]
    pub fn is_output(&self) -> bool {
        self.0.contains_key(&TraitId::SmithyApiOutput)
    }
}
