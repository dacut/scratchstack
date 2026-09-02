use {
    crate::{ShapeBase, ShapeInfo, SmithyModel, TraitMap, escape_braces, usize_literal},
    proc_macro2::{Literal, TokenStream},
    quote::quote,
    serde::{Deserialize, Serialize},
};

/// The `unit` type in Smithy is similar to `Void` and `None` in other languages. It is used
/// when the input or output of an operation has no meaningful value or if a union member has no
/// meaningful value.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyUnit {
    /// Basic shape information for the `unit` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `boolean` is a Boolean value type.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyBoolean {
    /// Basic shape information for the `boolean` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `blob` is uninterpreted binary data.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyBlob {
    /// Basic shape information for the `blob` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `string` is a UTF-8 encoded string.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyString {
    /// Basic shape information for the `string` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `bigInteger` is an arbitrarily large signed integer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyBigInteger {
    /// Basic shape information for the `bigInteger` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `bigDecimal` is an arbitrary precision signed decimal number.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyBigDecimal {
    /// Basic shape information for the `bigDecimal` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `timestamp` represents an instant in time in the proleptic Gregorian calendar, independent
/// of local times or timezones. Timestamps support an allowable date range between midnight
/// January 1, 0001 CE to 23:59:59.999 on December 31, 9999 CE, with a temporal resolution of
/// 1 millisecond. This resolution and range ensures broad support across programming languages
/// and guarantees compatibility with RFC 3339.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyTimestamp {
    /// Basic shape information for the `timestamp` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `document` represents protocol-agnostic open content that functions as a kind of "any"
/// type. Document types are represented by a JSON-like data model and can contain UTF-8
/// strings, arbitrary precision numbers, booleans, nulls, a list of these values, and a map of
/// UTF-8 strings to these values. Open content is useful for modeling unstructured data that
/// has no schema, data that can't be modeled using rigid types, or data that has a schema that
/// evolves outside of the purview of a model. The serialization format of a document is an
/// implementation detail of a protocol and MUST NOT have any effect on the types exposed by
/// tooling to represent a document value.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyDocument {
    /// Basic shape information for the `document` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `byte` is an 8-bit signed integer ranging from -128 to 127 (inclusive).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyByte {
    /// Basic shape information for the `byte` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `short` is a 16-bit signed integer ranging from -32,768 to 32,767 (inclusive).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyShort {
    /// Basic shape information for the `short` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// An `integer` is a 32-bit signed integer ranging from -2^31 to (2^31)-1 (inclusive).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyInteger {
    /// Basic shape information for the `integer` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `long` is a 64-bit signed integer ranging from -2^63 to (2^63)-1 (inclusive).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyLong {
    /// Basic shape information for the `long` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `float` is a single precision IEEE-754 floating point number.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyFloat {
    /// Basic shape information for the `float` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

/// A `double` is a double precision IEEE-754 floating point number.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmithyDouble {
    /// Basic shape information for the `double` type.
    #[serde(flatten)]
    pub base: ShapeBase,
}

impl ShapeInfo for SmithyUnit {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "()".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn is_primitive(&self) -> bool {
        true
    }
}

impl SmithyUnit {
    /// Create a new `SmithyUnit` instance with the given Smithy name.
    pub fn new(smithy_name: impl Into<String>) -> Self {
        let base = ShapeBase {
            smithy_name: Some(smithy_name.into()),
            rust_typename: Some("()".to_string()),
            traits: TraitMap::new(),
        };
        Self {
            base,
        }
    }
}

impl ShapeInfo for SmithyBoolean {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "bool".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn is_primitive(&self) -> bool {
        true
    }
}

impl ShapeInfo for SmithyBlob {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "::std::vec::Vec<u8>".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn is_primitive(&self) -> bool {
        true
    }
}

impl ShapeInfo for SmithyString {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "::std::string::String".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn validator_body(&self) -> Option<TokenStream> {
        if self.is_builtin() {
            return None;
        }

        let simple_name = self.simple_name(); // Used in error messages
        let mut checks = TokenStream::new();

        if let Some(pattern) = self.base.traits.pattern() {
            // A plain string literal rather than a raw one: `Literal::string` escapes whatever the
            // model contains, so no choice of `r#""#` delimiters can collide with the pattern.
            let pattern_literal = Literal::string(pattern);
            let message =
                format!("{{field}} must match the regex {} for {simple_name}: {{value}}", escape_braces(pattern));

            checks.extend(quote! {
                static PAT: ::std::sync::LazyLock<::regex::Regex> = ::std::sync::LazyLock::new(|| {
                    ::regex::Regex::new(#pattern_literal).expect("Invalid regex pattern in Smithy model")
                });
                if !PAT.is_match(value) {
                    return ::std::result::Result::Err(::std::format!(#message));
                }
            });
        }

        if let Some(length) = self.base.traits.length_constraint() {
            // Smithy's `length` on a string counts Unicode code points, not bytes.
            if let Some(min) = length.min
                && min > 0
            {
                let message = format!("{{field}} must be at least {min} characters long for {simple_name}: {{value}}");
                let too_short = if min > 1 {
                    let min = usize_literal(min);
                    quote!(value.chars().count() < #min)
                } else {
                    quote!(value.is_empty())
                };

                checks.extend(quote! {
                    if #too_short {
                        return ::std::result::Result::Err(::std::format!(#message));
                    }
                });
            }

            if let Some(max) = length.max {
                let message = format!("{{field}} must be at most {max} characters long for {simple_name}: {{value}}");
                let max = usize_literal(max);

                checks.extend(quote! {
                    if value.chars().count() > #max {
                        return ::std::result::Result::Err(::std::format!(#message));
                    }
                });
            }
        }

        if checks.is_empty() {
            None
        } else {
            Some(checks)
        }
    }

    fn validator_fn_name(&self) -> Option<String> {
        if self.is_builtin() {
            return None;
        }

        let has_length = self
            .base
            .traits
            .length_constraint()
            .is_some_and(|lc| lc.max.is_some() || lc.min.is_some_and(|min| min > 0));

        if self.base.traits.pattern().is_some() || has_length {
            Some(crate::validator_fn_name_for(&self.simple_name()))
        } else {
            None
        }
    }

    fn is_primitive(&self) -> bool {
        true
    }
}

// `bigInteger` and `bigDecimal` map to `aws_smithy_types`, which the generated crates do not
// depend on, so a model using either would not compile today. Neither IAM nor STS has one. They
// carry no validator: `BigDecimal` had one comparing against an integer literal, which would not
// have compiled either, and it was unreachable.
impl ShapeInfo for SmithyBigInteger {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "::aws_smithy_types::BigInteger".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn is_primitive(&self) -> bool {
        true
    }
}

impl ShapeInfo for SmithyBigDecimal {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "::aws_smithy_types::BigDecimal".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn is_primitive(&self) -> bool {
        true
    }
}

impl ShapeInfo for SmithyTimestamp {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "::chrono::DateTime<::chrono::Utc>".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn is_primitive(&self) -> bool {
        true
    }
}

impl ShapeInfo for SmithyDocument {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        "::aws_smithy_types::Document".to_string()
    }

    fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
        self.base.resolve(shape_name);
    }
}

macro_rules! impl_numeric {
    ($shape:ident, $rust_type:ty, $range_json:ident) => {
        impl ShapeInfo for $shape {
            fn smithy_name(&self) -> String {
                self.base.smithy_name()
            }

            fn rust_typename(&self) -> String {
                stringify!($rust_type).to_string()
            }

            fn resolve(&mut self, shape_name: &str, _model: &SmithyModel) {
                self.base.resolve(shape_name);
            }

            fn validator_body(&self) -> Option<TokenStream> {
                let simple_name = self.simple_name();
                let range = self.base.traits.range_constraint()?;
                let mut checks = TokenStream::new();

                if let Some(min) = range.min {
                    let message = format!("{{field}} for {simple_name} must be >= {min}: {{value}}");
                    let min = Literal::i64_unsuffixed(min);
                    checks.extend(quote! {
                        if *value < #min {
                            return ::std::result::Result::Err(::std::format!(#message));
                        }
                    });
                }

                if let Some(max) = range.max {
                    let message = format!("{{field}} for {simple_name} must be <= {max}: {{value}}");
                    let max = Literal::i64_unsuffixed(max);
                    checks.extend(quote! {
                        if *value > #max {
                            return ::std::result::Result::Err(::std::format!(#message));
                        }
                    });
                }

                if checks.is_empty() {
                    None
                } else {
                    Some(checks)
                }
            }

            fn validator_fn_name(&self) -> Option<String> {
                if self.is_builtin() {
                    return None;
                }

                match self.base.traits.range_constraint() {
                    Some(rc) if rc.min.is_some() || rc.max.is_some() => {
                        Some(crate::validator_fn_name_for(&self.simple_name()))
                    }
                    _ => None,
                }
            }

            fn is_primitive(&self) -> bool {
                true
            }
        }
    };
}

impl_numeric!(SmithyByte, i8, as_i64);
impl_numeric!(SmithyShort, i16, as_i64);
impl_numeric!(SmithyInteger, i32, as_i64);
impl_numeric!(SmithyLong, i64, as_i64);
impl_numeric!(SmithyFloat, f32, as_f64);
impl_numeric!(SmithyDouble, f64, as_f64);
