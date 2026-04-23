use {
    crate::{ShapeBase, ShapeInfo, TraitMap, forward_shape_info},
    indoc::formatdoc,
    serde::{Deserialize, Serialize},
    std::io::{Result as IoResult, Write},
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
    forward_shape_info!(SmithyUnit, base);

    fn clap_parser(&self) -> Option<String> {
        None
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        if !self.is_builtin() {
            self.base.traits.write_docs(output, "")?;
            writeln!(output, "pub type {} = ();", self.rust_typename())?;
        }
        Ok(())
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
    forward_shape_info!(SmithyBoolean, base);

    fn clap_parser(&self) -> Option<String> {
        None
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        if !self.is_builtin() {
            // Declaration
            let rust_typename = self.rust_typename();
            self.base.traits.write_docs(output, "")?;
            writeln!(output, "pub type {rust_typename} = bool;")?;
            writeln!(output)?;
        }
        Ok(())
    }
}

impl ShapeInfo for SmithyBlob {
    forward_shape_info!(SmithyBlob, base);

    fn clap_parser(&self) -> Option<String> {
        // TODO: Determine how we want to handle blobs on the command line.
        todo!("Determine how to handle blobs on the CLI")
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        if !self.is_builtin() {
            // Declaration
            let rust_typename = self.rust_typename();
            self.base.traits.write_docs(output, "")?;
            writeln!(output, "pub type {rust_typename} = Vec<u8>;")?;
            writeln!(output)?;

            // Clap parser
            let simple_name = self.simple_name();
            writeln!(output, "#[cfg(feature = \"clap\")]")?;
            writeln!(output, "#[allow(non_snake_case, unused)]")?;
            writeln!(output, "fn clap_parse_{rust_typename}(s: &str) -> Result<Vec<u8>, String> {{")?;
            writeln!(output, "    let value = ::base64::engine::Engine::decode(")?;
            writeln!(output, "        &::base64::engine::general_purpose::STANDARD, s)")?;
            writeln!(output, "        .map_err(|_| \"{simple_name} must be a valid base64 string\".to_string())?;")?;
            writeln!(output, "    Ok(value)")?;
            writeln!(output, "}}")?;
            writeln!(output)?;
        }
        Ok(())
    }
}

impl ShapeInfo for SmithyString {
    forward_shape_info!(SmithyString, base);

    #[inline(always)]
    fn clap_parser(&self) -> Option<String> {
        if self.is_builtin() {
            None
        } else {
            Some(format!("clap_parse_{}", self.rust_typename()))
        }
    }

    #[inline(always)]
    fn derive_builder_validator(&self, var: &str, field_name: &str) -> Option<String> {
        if self.is_builtin() {
            return None;
        }

        let simple_name = self.simple_name(); // Used in error messages
        let mut output = String::with_capacity(1024);

        if let Some(pat) = self.base.traits.pattern() {
            let escaped_pat = pat.replace("\\", "\\\\").replace("\"", "\\\"").replace("{", "{{").replace("}", "}}");
            output += &formatdoc!("
                static PAT: ::std::sync::LazyLock<::regex::Regex> = ::std::sync::LazyLock::new(||::regex::Regex::new(r\"{pat}\").expect(\"Invalid regex pattern in Smithy model\"));
                if !PAT.is_match({var}) {{
                    return Err(format!(\"{field_name} must match the regex {escaped_pat} for {simple_name}: {{{var}}}\"));
                }}
            ");
        }

        if let Some(lc) = self.base.traits.length_constraint() {
            if let Some(min) = lc.min
                && min > 0
            {
                let cond = if min > 1 {
                    format!("{var}.len() < {min}")
                } else {
                    format!("{var}.is_empty()")
                };

                output += &formatdoc!("
                    if {cond} {{
                        return Err(format!(\"{field_name} must be at least {min} characters long for {simple_name}: {{{var}}}\"));
                    }}
                ");
            }

            if let Some(max) = lc.max {
                output += &formatdoc!("
                    if {var}.len() > {max} {{
                        return Err(format!(\"{field_name} must be at most {max} characters long for {simple_name}: {{{var}}}\")); 
                    }}
                ");
            }
        }

        if !output.is_empty() {
            Some(output)
        } else {
            None
        }
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        if !self.is_builtin() {
            // Declaration
            let rust_typename = self.rust_typename();
            self.base.traits.write_docs(output, "")?;
            writeln!(output, "pub type {} = ::std::string::String;", rust_typename)?;
            writeln!(output)?;

            // Clap parser
            let rust_typename = self.rust_typename();
            let simple_name = self.simple_name();
            writeln!(output, "#[cfg(feature = \"clap\")]")?;
            writeln!(output, "#[allow(non_snake_case, unused)]")?;
            writeln!(output, "fn clap_parse_{rust_typename}(s: &str) -> Result<String, String> {{")?;

            if let Some(pat) = self.base.traits.pattern() {
                writeln!(
                    output,
                    "    static PAT: ::std::sync::LazyLock<::regex::Regex> = ::std::sync::LazyLock::new(||::regex::Regex::new(r\"{pat}\").expect(\"Invalid regex pattern in Smithy model\"));"
                )?;
                writeln!(output, "    if !PAT.is_match(s) {{")?;
                writeln!(output, "        return Err(r##\"{simple_name} must match the regex {pat}\"##.to_string());")?;
                writeln!(output, "    }}")?;
            }

            if let Some(lc) = self.base.traits.length_constraint() {
                if let Some(min) = lc.min
                    && min > 0
                {
                    if min == 1 {
                        writeln!(output, "    if s.is_empty() {{")?;
                    } else {
                        writeln!(output, "    if s.len() < {min} {{")?;
                    }
                    writeln!(
                        output,
                        "        return Err(\"{simple_name} must be at least {min} characters long\".to_string());"
                    )?;
                    writeln!(output, "    }}")?;
                }

                if let Some(max) = lc.max {
                    writeln!(output, "    if s.len() > {max} {{")?;
                    writeln!(
                        output,
                        "        return Err(\"{simple_name} must be at most {max} characters long\".to_string());"
                    )?;
                    writeln!(output, "    }}")?;
                }
            }

            writeln!(output, "    Ok(s.to_string())")?;
            writeln!(output, "}}")?;
            writeln!(output)?;
        }
        Ok(())
    }
}

impl ShapeInfo for SmithyBigInteger {
    forward_shape_info!(SmithyBigInteger, base);

    fn clap_parser(&self) -> Option<String> {
        todo!("Determine how to handle BigInteger arguments on the CLI")
    }
}

impl ShapeInfo for SmithyBigDecimal {
    forward_shape_info!(SmithyBigDecimal, base);

    fn clap_parser(&self) -> Option<String> {
        todo!("Determine how to handle BigDecimal arguments on the CLI")
    }
}

impl ShapeInfo for SmithyTimestamp {
    forward_shape_info!(SmithyTimestamp, base);

    fn clap_parser(&self) -> Option<String> {
        let rust_typename = self.rust_typename();
        Some(format!("{rust_typename}::try_from::<&str>"))
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        if !self.is_builtin() {
            // Declaration
            let rust_typename = self.rust_typename();
            self.base.traits.write_docs(output, "")?;
            writeln!(output, "pub type {} = ::chrono::DateTime<chrono::Utc>;", rust_typename)?;
            writeln!(output)?;

            // Clap parser
            let simple_name = self.simple_name();

            writeln!(output, "#[cfg(feature = \"clap\")]")?;
            writeln!(output, "#[allow(non_snake_case, unused)]")?;
            writeln!(
                output,
                "fn clap_parse_{rust_typename}(s: &str) -> Result<::chrono::DateTime<chrono::Utc>, String> {{"
            )?;
            writeln!(output, "    s.parse().map_err(|_| format!(\"{simple_name} must be a valid timestamp: {{s}}\"))")?;
            writeln!(output, "}}")?;
            writeln!(output)?;
        }

        Ok(())
    }
}

impl ShapeInfo for SmithyDocument {
    forward_shape_info!(SmithyDocument, base);

    fn clap_parser(&self) -> Option<String> {
        todo!("Figure out how to implement clap_parser for Document")
    }
}

macro_rules! impl_numeric {
    ($shape:ident, $rust_type:ty, $range_json:ident) => {
        impl ShapeInfo for $shape {
            forward_shape_info!($shape, base);

            fn clap_parser(&self) -> Option<String> {
                if self.is_builtin() {
                    None
                } else {
                    Some(format!("clap_parse_{}", self.rust_typename()))
                }
            }

            fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
                if !self.is_builtin() {
                    self.write_rust_decl(output)?;
                    self.write_clap_parser(output)?;
                }
                Ok(())
            }

            fn derive_builder_validator(&self, var: &str, field_name: &str) -> Option<String> {
                let simple_name = self.simple_name();
                let mut output = String::new();

                if let Some(rc) = self.base.traits.range_constraint() {
                    if let Some(min) = rc.min {
                        output += &format!("if *{var} < {min} {{ return Err(format!(\"{field_name} for {simple_name} must be >= {min}: {{{var}}}\")); }}\n");
                    }
                    if let Some(max) = rc.max {
                        output += &format!("if *{var} > {max} {{ return Err(format!(\"{field_name} for {simple_name} must be <= {max}: {{{var}}}\")); }}\n");
                    }
                }

                Some(output)
            }
        }

        impl $shape {
            /// Writes the Rust declaration for the type alias.
            fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
                if !self.is_builtin() {
                    self.base.traits.write_docs(output, "")?;
                    let rust_typename = self.rust_typename();
                    writeln!(output, "pub type {} = {};", rust_typename, stringify!($rust_type))?;
                    writeln!(output)?;
                }
                Ok(())
            }

            /// Writes the clap parser for this type.
            fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
                let rust_typename = self.rust_typename();
                let simple_name = self.simple_name();
                let return_type = stringify!($rust_type).to_string();

                writeln!(output, "#[cfg(feature = \"clap\")]")?;
                writeln!(output, "#[allow(non_snake_case, unused)]")?;
                writeln!(output, "fn clap_parse_{rust_typename}(s: &str) -> Result<{return_type}, String> {{")?;
                writeln!(output, "    let value = s.parse().map_err(|_| format!(\"Invalid {simple_name}: {{s}}\"))?;")?;

                if let Some(rc) = self.base.traits.range_constraint() {
                    if let Some(min) = rc.min {
                        writeln!(output, "    if value < {min} {{")?;
                        writeln!(output, "        return Err(format!(\"{simple_name} must be >= {min}: {{s}}\"));")?;
                        writeln!(output, "    }}")?;
                    }
                    if let Some(max) = rc.max {
                        writeln!(output, "    if value > {max} {{")?;
                        writeln!(output, "        return Err(format!(\"{simple_name} must be <= {max}: {{s}}\"));")?;
                        writeln!(output, "    }}")?;
                    }
                }

                writeln!(output, "    Ok(value)")?;
                writeln!(output, "}}")?;
                writeln!(output)?;
                Ok(())
            }
        }
    }
}

impl_numeric!(SmithyByte, i8, as_i64);
impl_numeric!(SmithyShort, i16, as_i64);
impl_numeric!(SmithyInteger, i32, as_i64);
impl_numeric!(SmithyLong, i64, as_i64);
impl_numeric!(SmithyFloat, f32, as_f64);
impl_numeric!(SmithyDouble, f64, as_f64);
