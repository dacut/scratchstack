use {
    super::{Member, ShapeBase, ShapeInfo, SmithyModel, StrExt},
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
        io::{Result as IoResult, Write},
    },
};

/// The structure type represents a fixed set of named, unordered, heterogeneous values. A
/// structure shape contains a set of named members, and each member name maps to exactly one
/// member definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Structure {
    /// Basic shape information for the `structure` type.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// The members of the structure. Each member name maps to exactly one member definition.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub members: BTreeMap<String, Member>,

    /// Whether this struct is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this struct.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,
}

impl ShapeInfo for Structure {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        self.base.rust_typename()
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);
        for member in self.members.values_mut() {
            member.resolve(shape_name, model);
        }
    }

    /// Returns the Clap parser for this structure, if it is reachable from an API input shape.
    fn clap_parser(&self) -> Option<String> {
        // TODO: Do we need this, or can it be elided? Or do we need shorthand magic?
        let typename = self.rust_typename();
        Some(format!("{typename}::from_str"))
    }

    fn mark_reachable_from_input(&mut self) {
        if self.reachable_from_input {
            return;
        }

        self.reachable_from_input = true;

        self.members.values_mut().for_each(|member| {
            member.mark_reachable_from_input();
        });
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)?;
        self.write_rust_impl(output)?;
        if self.reachable_from_input {
            self.write_rust_from_str_impl(output)?;
            self.write_rust_try_from_shorthand_value_impl(output)?;
        }

        if self.base.traits.is_aws_query_error() {
            self.write_rust_aws_query_error_impl(output)?;
        }

        self.write_builder_validate(output)?;
        Ok(())
    }
}

impl Structure {
    /// Writes the Rust declaration for the main body of this structure.
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let is_error = self.base.traits.is_error();

        // Write the documentation comments for the structure, if any.
        self.base.traits.write_docs(output, "")?;

        // Attributes for the structure.
        writeln!(output, "#[derive(::derive_builder::Builder)]")?;
        writeln!(output, "#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug)]")?;
        writeln!(output, "#[derive(::serde::Deserialize, ::serde::Serialize)]")?;
        writeln!(output, "#[builder(pattern = \"owned\", build_fn(validate = \"Self::validate\"), setter(into))]")?;
        if self.reachable_from_input {
            writeln!(output, "#[cfg_attr(feature = \"clap\", derive(::clap::Parser))]")?;
        }

        writeln!(output, "pub struct {rust_typename} {{")?;

        let mut is_first = true;
        for (member_name, member) in &self.members {
            if !is_first {
                writeln!(output)?;
            } else {
                is_first = false;
            }

            member.traits.write_docs(output, "    ")?;
            let is_optional = !member.traits.is_required();
            let is_list = member.is_list();
            if self.reachable_from_input {
                let mut clap_args = vec!["long".to_string()];
                if let Some(clap_parser) = member.clap_parser() {
                    clap_args.push(format!("value_parser = {clap_parser}"))
                }
                writeln!(output, "    #[cfg_attr(feature = \"clap\", clap({}))]", clap_args.join(", "))?;
            }

            let mut member_type = member.rust_typename();
            let rust_member_name = member_name.to_snake_case();

            if is_optional && !is_list {
                member_type = format!("Option<{}>", member_type);
            }

            writeln!(output, "    #[serde(rename = \"{member_name}\")]")?;
            if is_optional || is_list {
                writeln!(output, "    #[builder(default)]")?;
            }
            writeln!(output, "    pub {rust_member_name}: {member_type},")?;
        }

        // If this is an error type, add metadata to the structure for error handling.
        if is_error {
            writeln!(output)?;
            writeln!(output, "    /// Metadata about the error")?;
            writeln!(output, "    #[serde(skip)]")?;
            writeln!(output, "    pub meta: ::aws_smithy_types::error::ErrorMetadata,")?;
        }

        writeln!(output, "}}")?;
        writeln!(output)?;

        Ok(())
    }

    /// Writes the main impl of this structure, which just provides a builder method for constructing this structure.
    fn write_rust_impl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "impl {rust_typename} {{")?;
        writeln!(output, "    /// Returns a [`{rust_typename}Builder`] for constructing a `{rust_typename}`.")?;
        writeln!(output, "    pub fn builder() -> {rust_typename}Builder {{")?;
        writeln!(output, "        {rust_typename}Builder::default()")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    /// Writes the FromStr implementation for this structure, which is used for parsing this structure from a string
    /// when parsing Clap arguments.
    fn write_rust_from_str_impl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl FromStr for {rust_typename} {{")?;
        writeln!(output, "    type Err = String;")?;
        writeln!(output, "    fn from_str(s: &str) -> Result<Self, Self::Err> {{")?;
        writeln!(
            output,
            "        let value = ::scratchstack_cli_utils::parse_shorthand(s).map_err(|e| format!(\"Failed to parse {rust_typename} from '{{s}}': {{e}}\"))?;"
        )?;
        writeln!(
            output,
            "        let map = value.as_map().ok_or(format!(\"Expected a map/object to parse {rust_typename}, but got '{{value:?}}'\"))?;"
        )?;

        if !self.members.is_empty() {
            writeln!(output, "        let mut builder = {rust_typename}Builder::default();")?;
            writeln!(output, "        for (key, value) in map {{")?;
            writeln!(output, "            match key.as_str() {{")?;
            for (member_name, member) in self.members.iter() {
                let rust_member_name = member_name.to_snake_case();
                let rust_member_type = member.rust_typename();
                writeln!(output, "                \"{member_name}\" => {{")?;
                writeln!(
                    output,
                    "                    builder = builder.{rust_member_name}(::std::convert::TryInto::<{rust_member_type}>::try_into(value)?);"
                )?;
                writeln!(output, "                }}")?;
            }
            writeln!(
                output,
                "                other => return Err(format!(\"Unknown field '{{other}}' when parsing {rust_typename}\")),"
            )?;
            writeln!(output, "            }}")?;
            writeln!(output, "        }}")?;
            writeln!(
                output,
                "        builder.build().map_err(|e| format!(\"Failed to build {rust_typename} from '{{s}}': {{e}}\"))"
            )?;
        } else {
            writeln!(output, "        if let Some(key) = map.keys().next() {{")?;
            writeln!(
                output,
                "            return Err(format!(\"Unexpected field '{{key}}' when parsing {rust_typename}, which has no members\"));"
            )?;
            writeln!(output, "        }}")?;
            writeln!(output, "        Ok({rust_typename} {{}})")?;
        }
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    /// Write a rust implemenation of `TryFrom<&ShorthandValue>` for this structure.
    ///
    /// This allows the structure to be created from a `ShorthandValue`, used to parse parameters
    /// provided on the CLI in a shorthand format, e.g. `--tag Key=key,Value=value` instead of the
    /// more verbose JSON syntax `--tag [{"Key":"key","Value":"value"}]`.
    fn write_rust_try_from_shorthand_value_impl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl TryFrom<&::scratchstack_cli_utils::ShorthandValue> for {rust_typename} {{")?;
        writeln!(output, "    type Error = String;")?;
        writeln!(
            output,
            "    fn try_from(value: &::scratchstack_cli_utils::ShorthandValue) -> Result<Self, Self::Error> {{"
        )?;
        writeln!(
            output,
            "        let map = value.as_map().ok_or(format!(\"Expected a map/object to convert to {rust_typename}, but got '{{value:?}}'\"))?;"
        )?;

        if !self.members.is_empty() {
            writeln!(output, "        let mut builder = {rust_typename}Builder::default();")?;
            writeln!(output, "        for (key, value) in map {{")?;
            writeln!(output, "            match key.as_str() {{")?;
            for (member_name, member) in self.members.iter() {
                let rust_member_name = member_name.to_snake_case();
                let rust_member_type = member.rust_typename();
                writeln!(output, "                \"{member_name}\" => {{")?;
                writeln!(
                    output,
                    "                    builder = builder.{rust_member_name}(::std::convert::TryInto::<{rust_member_type}>::try_into(value)?);"
                )?;
                writeln!(output, "                }}")?;
            }
            writeln!(
                output,
                "                other => return Err(format!(\"Unknown field '{{other}}' when converting to {rust_typename}\")),"
            )?;
            writeln!(output, "            }}")?;
            writeln!(output, "        }}")?;
            writeln!(
                output,
                "        builder.build().map_err(|e| format!(\"Failed to build {rust_typename} from '{{value:?}}': {{e}}\"))"
            )?;
        } else {
            writeln!(output, "        if let Some(key) = map.keys().next() {{")?;
            writeln!(
                output,
                "            return Err(format!(\"Unexpected field '{{key}}' when converting to {rust_typename}, which has no members\"));"
            )?;
            writeln!(output, "        }}")?;
            writeln!(output, "        Ok({rust_typename} {{}})")?;
        }

        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    /// Writes implementations of the `Error`, `Display`, `RequestId`, `ProvideErrorKind`, and
    /// `ProvideErrorMetadata` traits for this structure.
    fn write_rust_aws_query_error_impl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let qe_any = self.base.traits.aws_query_error().unwrap();
        let qe_map = qe_any.as_object().unwrap();
        let code = qe_map.get("code").unwrap().as_str().unwrap();
        let error_type = self.base.traits.error().unwrap();

        writeln!(output, "impl ::std::fmt::Display for {rust_typename} {{")?;
        writeln!(output, "    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{")?;
        writeln!(output, "        f.write_str(\"{rust_typename}\")?;")?;
        writeln!(output, "        if let ::std::option::Option::Some(message) = &self.message {{")?;
        writeln!(output, "            ::std::write!(f, \": {{message}}\")?;")?;
        writeln!(output, "        }}")?;
        writeln!(output, "        ::std::result::Result::Ok(())")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        writeln!(output, "impl ::std::error::Error for {rust_typename} {{}}")?;
        writeln!(output)?;
        writeln!(output, "impl ::aws_types::request_id::RequestId for {rust_typename} {{")?;
        writeln!(output, "    #[inline(always)]")?;
        writeln!(output, "    fn request_id(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(output, "        ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(self).request_id()")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;

        writeln!(output)?;
        writeln!(output, "impl ::aws_smithy_types::retry::ProvideErrorKind for {rust_typename} {{")?;
        writeln!(output, "    #[inline(always)]")?;
        writeln!(
            output,
            "    fn retryable_error_kind(&self) -> ::std::option::Option<::aws_smithy_types::retry::ErrorKind> {{"
        )?;
        if error_type == "client" {
            writeln!(output, "        ::std::option::Option::Some(::aws_smithy_types::retry::ErrorKind::ClientError)")?;
        } else {
            writeln!(output, "        ::std::option::Option::Some(::aws_smithy_types::retry::ErrorKind::ServerError)")?;
        }
        writeln!(output, "    }}")?;
        writeln!(output)?;
        writeln!(output, "    #[inline(always)]")?;
        writeln!(output, "    fn code(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(output, "        ::std::option::Option::Some(\"{code}\")")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        writeln!(output, "impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for {rust_typename} {{")?;
        writeln!(output, "    #[inline(always)]")?;
        writeln!(output, "    fn meta(&self) -> &::aws_smithy_types::error::metadata::ErrorMetadata {{")?;
        writeln!(output, "        &self.meta")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;

        Ok(())
    }

    fn write_builder_validate(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        writeln!(output, "impl {rust_typename}Builder {{")?;
        writeln!(output, "    #[allow(clippy::collapsible_if)]")?;
        writeln!(output, "    fn validate(&self) -> Result<(), String> {{")?;
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_snake_case();
            let is_required = member.is_required();
            let is_list = member.is_list();

            if is_required && !is_list {
                writeln!(output, "        if self.{rust_member_name}.is_none() {{")?;
                writeln!(
                    output,
                    "            return Err(\"Missing required field '{member_name}' when building {rust_typename}\".to_string());"
                )?;
                writeln!(output, "        }}")?;
            }

            let member_validator = member.derive_builder_validator("value", &rust_typename);
            if let Some(mut validator) = member_validator
                && !validator.trim().is_empty()
            {
                validator = validator.trim().replace("\n", "\n            ");
                if is_required || is_list {
                    writeln!(output, "        if let Some(value) = &self.{rust_member_name} {{")?;
                    writeln!(output, "            {validator}")?;
                    writeln!(output, "        }}")?;
                } else {
                    writeln!(
                        output,
                        "        if let Some(value_opt) = &self.{rust_member_name} && let Some(value) = value_opt {{"
                    )?;
                    writeln!(output, "            {validator}")?;
                    writeln!(output, "        }}")?;
                }
            }
        }
        writeln!(output, "        Ok(())")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        Ok(())
    }
}
