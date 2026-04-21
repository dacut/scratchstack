use {
    crate::{Primitive, Typed},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::io::{Result as IoResult, Write},
};

macro_rules! decl {
    ($shape:ident, $rust_type:ty) => {
        #[allow(missing_docs)]
        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct $shape {
            /// The name of this type in the Smithy model.
            ///
            /// This is resolved during a call to `SmithyModel::resolve`.
            #[serde(skip, default)]
            pub smithy_typename: ::std::option::Option<::std::string::String>,

            /// The Rust name of this type.
            ///
            /// This is resolved during a call to `SmithyModel::resolve`.
            #[serde(skip, default)]
            pub rust_typename: ::std::option::Option<::std::string::String>,

            /// Traits to apply to the type.
            #[serde(skip_serializing_if = "::std::collections::HashMap::is_empty", default)]
            pub traits: ::std::collections::HashMap<::std::string::String, Value>,
        }

        impl Primitive for $shape {}
    };
}

macro_rules! impl_numeric {
    ($shape:ident, $rust_type:ty, $range_json:ident) => {
        impl Typed for $shape {
            fn rust_typename(&self) -> ::std::string::String {
                self.rust_typename.clone().expect(concat!(stringify!($shape), " shape should have a Rust typename after resolution"))
            }

            #[inline(always)]
            fn is_primitive(&self) -> bool {
                true
            }

            fn get_clap_parser(&self) -> ::std::string::String {
                let rust_typename = self.rust_typename();
                format!("clap_parse_{rust_typename}")
            }

            fn write(&self, output: &mut dyn Write) -> IoResult<()> {
                self.write_rust_decl(output)?;
                self.write_clap_parser(output)?;
                Ok(())
            }

            #[inline(always)]
            fn mark_reachable_from_input(&mut self) {}

            fn get_derive_builder_validator(&self, var: &str) -> ::std::option::Option<::std::string::String> {
                let mut output = ::std::string::String::new();
                let smithy_typename = self.smithy_typename.as_ref().expect(concat!(stringify!($shape), " shape should have a Smithy typename after resolution"));
                let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
                let simple_typename = &smithy_typename[hash_pos + 1..];

                if let Some(rc) = self.traits.get("smithy.api#range") {
                    let rc = rc.as_object().expect("Range trait should be an object");
                    let min = rc.get("min").and_then(|v| v.$range_json());
                    let max = rc.get("max").and_then(|v| v.$range_json());

                    if let Some(min) = min {
                        output += &format!("if *{var} < {min} {{ return Err(format!(\"{simple_typename} must be >= {min}: {{{var}}}\")); }}\n");
                    }
                    if let Some(max) = max {
                        output += &format!("if *{var} > {max} {{ return Err(format!(\"{simple_typename} must be <= {max}: {{{var}}}\")); }}\n");
                    }
                }

                Some(output)
            }
        }

        impl $shape {
            /// Writes the Rust declaration for the type alias.
            fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
                let rust_typename = self.rust_typename();
                let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
                if let Some(docs) = docs {
                    for line in docs.lines() {
                        writeln!(output, "/// {}", line.trim())?;
                    }
                } else {
                    writeln!(output, "#[allow(missing_docs)]")?;
                }
                writeln!(output, "pub type {} = {};", rust_typename, stringify!($rust_type))?;
                writeln!(output)?;

                Ok(())
            }

            /// Writes the clap parser for this type.
            fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
                let smithy_typename = self.smithy_typename.as_ref().expect(concat!(stringify!($shape), " shape should have a Smithy typename after resolution"));
                let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
                let simple_typename = &smithy_typename[hash_pos + 1..];
                let rust_typename = self.rust_typename();
                let fn_name = format!("clap_parse_{}", rust_typename);
                let return_type = stringify!($rust_type).to_string();

                writeln!(output, "#[cfg(feature = \"clap\")]")?;
                writeln!(output, "#[allow(non_snake_case, unused)]")?;
                writeln!(output, "fn {fn_name}(s: &str) -> Result<{return_type}, String> {{")?;
                writeln!(output, "    let value = s.parse().map_err(|_| format!(\"Invalid {simple_typename}: {{s}}\"))?;")?;

                if let Some(rc) = self.traits.get("smithy.api#range") {
                    let rc = rc.as_object().expect("Range trait should be an object");
                    let min = rc.get("min").and_then(|v| v.$range_json());
                    let max = rc.get("max").and_then(|v| v.$range_json());

                    if let Some(min) = min {
                        writeln!(output, "    if value < {min} {{")?;
                        writeln!(output, "        return Err(format!(\"{simple_typename} must be >= {min}: {{s}}\"));")?;
                        writeln!(output, "    }}")?;
                    }
                    if let Some(max) = max {
                        writeln!(output, "    if value > {max} {{")?;
                        writeln!(output, "        return Err(format!(\"{simple_typename} must be <= {max}: {{s}}\"));")?;
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

macro_rules! make_int_type {
    ($shape:ident, $rust_type:ty) => {
        decl!($shape, $rust_type);
        impl_numeric!($shape, $rust_type, as_i64);
    };
}

macro_rules! make_float_type {
    ($shape:ident, $rust_type:ty) => {
        decl!($shape, $rust_type);
        impl_numeric!($shape, $rust_type, as_f64);
    };
}

make_int_type!(Byte, i8);
make_int_type!(Short, i16);
make_int_type!(Integer, i32);
make_int_type!(Long, i64);

make_int_type!(BigInteger, ::num_bigint::BigInt);

make_float_type!(Float, f32);
make_float_type!(Double, f64);
make_float_type!(BigDecimal, ::bigdecimal::BigDecimal);

decl!(Blob, Vec<u8>);
decl!(Boolean, bool);
decl!(String, ::std::string::String);
decl!(Timestamp, ::chrono::DateTime<::chrono::Utc>);
decl!(Unit, ());

impl Typed for Blob {
    fn rust_typename(&self) -> ::std::string::String {
        self.rust_typename.clone().expect("Blob shape should have a Rust typename after resolution")
    }

    #[inline(always)]
    fn is_primitive(&self) -> bool {
        true
    }

    fn get_clap_parser(&self) -> ::std::string::String {
        unimplemented!("blob type does not have a clap parser")
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)?;
        self.write_clap_parser(output)?;
        Ok(())
    }

    #[inline(always)]
    fn mark_reachable_from_input(&mut self) {}
}

impl Blob {
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }

        writeln!(output, "pub type {} = Vec<u8>;", rust_typename)?;
        writeln!(output)?;
        Ok(())
    }

    fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let smithy_typename =
            self.smithy_typename.as_ref().expect("Blob shape should have a Smithy typename after resolution");
        let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
        let simple_typename = &smithy_typename[hash_pos + 1..];
        let rust_typename = self.rust_typename();
        let fn_name = format!("clap_parse_{}", rust_typename);

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "#[allow(non_snake_case, unused)]")?;
        writeln!(output, "fn {fn_name}(s: &str) -> Result<Vec<u8>, String> {{")?;
        writeln!(
            output,
            "    let value = ::base64::engine::Engine::decode(&::base64::engine::general_purpose::STANDARD, s).map_err(|_| \"{simple_typename} must be a valid base64 string\".to_string())?;"
        )?;
        writeln!(output, "    Ok(value)")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }
}

impl Typed for Boolean {
    fn rust_typename(&self) -> ::std::string::String {
        self.rust_typename.clone().expect("Boolean shape should have a Rust typename after resolution")
    }

    #[inline(always)]
    fn is_primitive(&self) -> bool {
        true
    }

    fn get_clap_parser(&self) -> ::std::string::String {
        let rust_typename = self.rust_typename();
        format!("clap_parse_{rust_typename}")
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)?;
        self.write_clap_parser(output)?;
        Ok(())
    }

    #[inline(always)]
    fn mark_reachable_from_input(&mut self) {}
}

impl Boolean {
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }
        writeln!(output, "pub type {} = bool;", rust_typename)?;
        writeln!(output)?;

        Ok(())
    }

    fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let smithy_typename =
            self.smithy_typename.as_ref().expect("Boolean shape should have a Smithy typename after resolution");
        let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
        let simple_typename = &smithy_typename[hash_pos + 1..];
        let rust_typename = self.rust_typename();
        let fn_name = format!("clap_parse_{}", rust_typename);

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "#[allow(non_snake_case, unused)]")?;
        writeln!(output, "fn {fn_name}(s: &str) -> Result<bool, String> {{")?;
        writeln!(output, "    s.parse().map_err(|_| format!(\"{simple_typename} must be a valid boolean: {{s}}\"))")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }
}

impl Typed for String {
    fn rust_typename(&self) -> ::std::string::String {
        self.rust_typename.clone().expect("String shape should have a Rust typename after resolution")
    }

    #[inline(always)]
    fn is_primitive(&self) -> bool {
        true
    }

    fn get_clap_parser(&self) -> ::std::string::String {
        let rust_typename = self.rust_typename();
        format!("clap_parse_{rust_typename}")
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)?;
        self.write_clap_parser(output)?;
        Ok(())
    }

    #[inline(always)]
    fn mark_reachable_from_input(&mut self) {}

    fn get_derive_builder_validator(&self, field: &str) -> ::std::option::Option<::std::string::String> {
        let mut output = ::std::string::String::new();
        let smithy_typename =
            self.smithy_typename.as_ref().expect("String shape should have a Smithy typename after resolution");
        let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
        let simple_typename = &smithy_typename[hash_pos + 1..];

        if let Some(pat) = self.traits.get("smithy.api#pattern").and_then(|v| v.as_str()) {
            let escaped_pat = pat.replace("\\", "\\\\").replace("\"", "\\\"").replace("{", "{{").replace("}", "}}");
            output += &format!(
                "static PAT: ::std::sync::LazyLock<::regex::Regex> = ::std::sync::LazyLock::new(||::regex::Regex::new(r\"{pat}\").expect(\"Invalid regex pattern in Smithy model\"));\n"
            );
            output += &format!(
                "if !PAT.is_match({field}) {{ return Err(format!(\"{simple_typename} must match the regex {escaped_pat}: {{{field}}}\")); }}\n"
            );
        }

        if let Some(lc) = self.traits.get("smithy.api#length") {
            let lc = lc.as_object().expect("Length trait should be an object");
            let min = lc.get("min").and_then(|v| v.as_u64());
            let max = lc.get("max").and_then(|v| v.as_u64());

            if let Some(min) = min
                && min > 0
            {
                if min > 1 {
                    output += &format!("if {field}.len() < {min} ");
                } else {
                    output += &format!("if {field}.is_empty() ");
                }

                output += &format!(
                    "{{ return Err(format!(\"{simple_typename} must be at least {min} characters long: {{{field}}}\")); }}\n"
                );
            }

            if let Some(max) = max {
                output += &format!(
                    "if {field}.len() > {max} {{ return Err(format!(\"{simple_typename} must be at most {max} characters long: {{{field}}}\")); }}\n"
                );
            }
        }

        if !output.is_empty() {
            Some(output)
        } else {
            None
        }
    }
}

impl String {
    /// Writes the Rust declaration for the type alias.
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }
        writeln!(output, "pub type {} = String;", rust_typename)?;
        writeln!(output)?;

        Ok(())
    }

    /// Writes the clap parser for this type.
    fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let smithy_typename =
            self.smithy_typename.as_ref().expect("String shape should have a Smithy typename after resolution");
        let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
        let simple_typename = &smithy_typename[hash_pos + 1..];
        let rust_typename = self.rust_typename();
        let fn_name = format!("clap_parse_{}", rust_typename);

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "#[allow(non_snake_case, unused)]")?;
        writeln!(output, "fn {fn_name}(s: &str) -> Result<String, String> {{")?;

        if let Some(pat) = self.traits.get("smithy.api#pattern").and_then(|v| v.as_str()) {
            writeln!(
                output,
                "    static PAT: ::std::sync::LazyLock<::regex::Regex> = ::std::sync::LazyLock::new(||::regex::Regex::new(r\"{pat}\").expect(\"Invalid regex pattern in Smithy model\"));"
            )?;
            writeln!(output, "    if !PAT.is_match(s) {{")?;
            writeln!(output, "        return Err(r##\"{simple_typename} must match the regex {pat}\"##.to_string());")?;
            writeln!(output, "    }}")?;
        }

        if let Some(lc) = self.traits.get("smithy.api#length") {
            let lc = lc.as_object().expect("Length trait should be an object");
            let min = lc.get("min").and_then(|v| v.as_u64());
            let max = lc.get("max").and_then(|v| v.as_u64());

            if let Some(min) = min
                && min > 0
            {
                if min == 1 {
                    writeln!(output, "    if s.is_empty() {{")?;
                } else {
                    writeln!(output, "    if s.len() < {min} {{")?;
                }
                writeln!(
                    output,
                    "        return Err(\"{simple_typename} must be at least {min} characters long\".to_string());"
                )?;
                writeln!(output, "    }}")?;
            }

            if let Some(max) = max {
                writeln!(output, "    if s.len() > {max} {{")?;
                writeln!(
                    output,
                    "        return Err(\"{simple_typename} must be at most {max} characters long\".to_string());"
                )?;
                writeln!(output, "    }}")?;
            }
        }

        writeln!(output, "    Ok(s.to_string())")?;
        writeln!(output, "}}")?;
        writeln!(output)?;

        Ok(())
    }
}

impl Typed for Timestamp {
    fn rust_typename(&self) -> ::std::string::String {
        self.rust_typename.clone().expect("Timestamp shape should have a Rust typename after resolution")
    }

    #[inline(always)]
    fn is_primitive(&self) -> bool {
        true
    }

    fn get_clap_parser(&self) -> ::std::string::String {
        let rust_typename = self.rust_typename();
        format!("{rust_typename}::try_from::<&str>")
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl_body(output)?;
        self.write_clap_parser(output)?;
        Ok(())
    }

    #[inline(always)]
    fn mark_reachable_from_input(&mut self) {}
}

impl Timestamp {
    /// Writes the Rust declaration for the type alias.
    fn write_rust_decl_body(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }
        writeln!(output, "pub type {} = chrono::DateTime<chrono::Utc>;", rust_typename)?;
        writeln!(output)?;

        Ok(())
    }

    /// Writes the clap parser for this type.
    fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let smithy_typename =
            self.smithy_typename.as_ref().expect("Timestamp shape should have a Smithy typename after resolution");
        let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
        let simple_typename = &smithy_typename[hash_pos + 1..];
        let rust_typename = self.rust_typename();
        let fn_name = format!("clap_parse_{}", rust_typename);

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "#[allow(non_snake_case, unused)]")?;
        writeln!(output, "fn {fn_name}(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {{")?;
        writeln!(output, "    s.parse().map_err(|_| format!(\"{simple_typename} must be a valid timestamp: {{s}}\"))")?;
        writeln!(output, "}}")?;
        writeln!(output)?;

        Ok(())
    }
}

impl Typed for Unit {
    fn rust_typename(&self) -> ::std::string::String {
        self.rust_typename.clone().expect("Unit shape should have a Rust typename after resolution")
    }

    #[inline(always)]
    fn is_primitive(&self) -> bool {
        true
    }

    fn get_clap_parser(&self) -> ::std::string::String {
        unimplemented!("unit type does not have a clap parser")
    }

    #[inline(always)]
    fn mark_reachable_from_input(&mut self) {}

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)
    }
}

impl Unit {
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }
        writeln!(output, "pub type {} = ();", self.rust_typename())?;
        writeln!(output)?;

        Ok(())
    }
}
