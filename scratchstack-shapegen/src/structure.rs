use {
    super::{Member, ShapeBase, ShapeInfo, SmithyModel, StrExt, Writers},
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
}

impl ShapeInfo for Structure {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        if self.base.traits.is_error() {
            format!("crate::error::{}", self.base.rust_typename())
        } else {
            format!("crate::types::{}", self.base.rust_typename())
        }
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);
        for member in self.members.values_mut() {
            member.resolve(shape_name, model);
        }
    }

    /// Generates code that implements the structure.
    ///
    /// This can be in any number of modules; typically:
    /// * `crate::types` for regular structures
    /// * `crate::types::error` for structures that are marked with the error trait.
    /// * `crates::operation::<op-name>` for structures that are used as the input or output of an operation.`
    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        let is_error = self.base.traits.is_error();
        let is_input = self.base.traits.is_input();
        let is_output = self.base.traits.is_output();

        if is_error && (is_input || is_output) {
            panic!(
                "Structure shapes that are marked with the error trait cannot be used as input or output shapes for operations"
            );
        }

        if is_error {
            self.write_rust_decl(&mut w.types_error)?;
            self.write_rust_impl(&mut w.types_error)?;
            self.write_rust_aws_query_error_impl(&mut w.types_error)?;
            self.write_error_builder(&mut w.types_error)?;
        } else if is_input || is_output {
            self.write_rust_decl(&mut w.operation)?;
            self.write_rust_impl(&mut w.operation)?;
            self.write_builder_validate(&mut w.operation)?;

            if is_input {
                self.write_shorthand_parser(&mut w.operation)?;
            }
        } else {
            self.write_rust_decl(&mut w.types)?;
            self.write_rust_impl(&mut w.types)?;
            self.write_builder_validate(&mut w.types)?;
            self.write_shorthand_parser(&mut w.types)?;
        }

        Ok(())
    }
}

impl Structure {
    /// For error structures, returns the AWS error code (string) to use for this structure.
    #[must_use]
    fn error_code(&self) -> String {
        let default_error_code =
            self.base.rust_typename().strip_suffix("Exception").unwrap_or(&self.base.rust_typename()).to_string();

        if let Some(qe_any) = self.base.traits.aws_query_error() {
            if let Some(qe_map) = qe_any.as_object() {
                if let Some(code_any) = qe_map.get("code") {
                    if let Some(code) = code_any.as_str() {
                        code.to_string()
                    } else {
                        default_error_code
                    }
                } else {
                    default_error_code
                }
            } else {
                default_error_code
            }
        } else {
            default_error_code
        }
    }

    /// Indicates whether this structure is eligible for CLI shorthand parsing.
    ///
    /// To be eligible, the structure's members must all be primitive types, enums, lists of
    /// primitive types, or lists of enums.
    #[must_use]
    pub fn is_cli_shorthand_parsable(&self) -> bool {
        self.members.values().all(Member::is_struct_member_cli_shorthand_parseable)
    }

    /// Writes the Rust declaration for the main body of this structure.
    fn write_rust_decl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let is_error = self.base.traits.is_error();

        // Write the documentation comments for the structure, if any.
        self.base.traits.write_docs(w, "")?;

        // Attributes for the structure.
        if !is_error {
            writeln!(w, "#[derive(::derive_builder::Builder)]")?;
            writeln!(w, "#[builder(pattern = \"owned\", build_fn(validate = \"Self::validate\"), setter(into))]")?;
        }
        writeln!(w, "#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug)]")?;
        writeln!(w, "#[derive(::serde::Deserialize, ::serde::Serialize)]")?;
        writeln!(w, "pub struct {rust_typename} {{")?;

        let mut is_first = true;
        for (member_name, member) in &self.members {
            if !is_first {
                writeln!(w)?;
            } else {
                is_first = false;
            }

            member.traits.write_docs(w, "    ")?;
            let is_optional = !member.traits.is_required();
            let is_list = member.is_list();
            let mut member_type = member.rust_typename();
            let rust_member_name = member_name.to_snake_case();

            if is_optional && !is_list {
                member_type = format!("Option<{}>", member_type);
            }

            if is_optional && !is_list {
                writeln!(w, "    #[serde(rename = \"{member_name}\", skip_serializing_if = \"Option::is_none\")]")?;
            } else {
                writeln!(w, "    #[serde(rename = \"{member_name}\")]")?;
            }
            if !is_error && (is_optional || is_list) {
                writeln!(w, "    #[builder(default)]")?;
            }
            writeln!(w, "    pub {rust_member_name}: {member_type},")?;
        }

        // If this is an error type, add metadata to the structure for error handling.
        if is_error {
            writeln!(w)?;
            writeln!(w, "    /// Metadata about the error")?;
            writeln!(w, "    #[serde(skip)]")?;
            writeln!(w, "    pub meta: ::aws_smithy_types::error::ErrorMetadata,")?;
        }

        writeln!(w, "}}")?;

        writeln!(w)?;

        Ok(())
    }

    /// Writes the main impl of this structure, which just provides a builder method for constructing this structure.
    fn write_rust_impl(&self, w: &mut dyn Write) -> IoResult<()> {
        let is_error = self.base.traits.is_error();
        let rust_typename = self.base.rust_typename();

        writeln!(w, "impl {rust_typename} {{")?;
        writeln!(w, "    /// Returns a [`{rust_typename}Builder`] for constructing a `{rust_typename}`.")?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    pub fn builder() -> {rust_typename}Builder {{")?;
        writeln!(w, "        {rust_typename}Builder::default()")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        if is_error {
            writeln!(w, "    /// Returns the error message.")?;
            writeln!(w, "    #[inline(always)]")?;
            writeln!(w, "    pub fn message(&self) -> ::std::option::Option<&str> {{")?;
            writeln!(w, "        self.message.as_deref()")?;
            writeln!(w, "    }}")?;
        }
        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }

    /// Writes implementations of the `Error`, `Display`, `RequestId`, `ProvideErrorKind`, and
    /// `ProvideErrorMetadata` traits for this structure.
    fn write_rust_aws_query_error_impl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let code = if let Some(qe_any) = self.base.traits.aws_query_error() {
            let qe_map = qe_any.as_object().unwrap();
            qe_map.get("code").unwrap().as_str().unwrap().to_string()
        } else {
            rust_typename.strip_suffix("Exception").unwrap().to_string()
        };

        let error_type = self.base.traits.error().unwrap();

        writeln!(w, "impl ::std::fmt::Display for {rust_typename} {{")?;
        writeln!(w, "    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{")?;
        writeln!(w, "        f.write_str(\"{rust_typename}\")?;")?;
        writeln!(w, "        if let ::std::option::Option::Some(message) = &self.message {{")?;
        writeln!(w, "            ::std::write!(f, \": {{message}}\")?;")?;
        writeln!(w, "        }}")?;
        writeln!(w, "        ::std::result::Result::Ok(())")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        writeln!(w, "impl ::std::error::Error for {rust_typename} {{}}")?;
        writeln!(w)?;
        writeln!(w, "impl ::aws_types::request_id::RequestId for {rust_typename} {{")?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn request_id(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w, "        ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(self).request_id()")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;

        writeln!(w)?;
        writeln!(w, "impl ::aws_smithy_types::retry::ProvideErrorKind for {rust_typename} {{")?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(
            w,
            "    fn retryable_error_kind(&self) -> ::std::option::Option<::aws_smithy_types::retry::ErrorKind> {{"
        )?;
        if error_type == "client" {
            writeln!(w, "        ::std::option::Option::Some(::aws_smithy_types::retry::ErrorKind::ClientError)")?;
        } else {
            writeln!(w, "        ::std::option::Option::Some(::aws_smithy_types::retry::ErrorKind::ServerError)")?;
        }
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn code(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w, "        ::std::option::Option::Some(\"{code}\")")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        writeln!(w, "impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for {rust_typename} {{")?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn meta(&self) -> &::aws_smithy_types::error::metadata::ErrorMetadata {{")?;
        writeln!(w, "        &self.meta")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        Ok(())
    }

    /// Writes the derive_builder validation function for this structure, which checks that all
    /// required fields are set and that all fields satisfy any constraints specified in the model.
    fn write_builder_validate(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        writeln!(w, "impl {rust_typename}Builder {{")?;
        writeln!(w, "    #[allow(clippy::collapsible_if)]")?;
        writeln!(w, "    fn validate(&self) -> Result<(), String> {{")?;
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_snake_case();
            let is_required = member.is_required();
            let is_list = member.is_list();

            if is_required && !is_list {
                writeln!(w, "        if self.{rust_member_name}.is_none() {{")?;
                writeln!(
                    w,
                    "            return Err(\"Missing required field '{member_name}' when building {rust_typename}\".to_string());"
                )?;
                writeln!(w, "        }}")?;
            }

            let member_validator = member.derive_builder_validator("value", &rust_typename);
            if let Some(mut validator) = member_validator
                && !validator.trim().is_empty()
            {
                validator = validator.trim().replace("\n", "\n            ");
                if is_required || is_list {
                    writeln!(w, "        if let Some(value) = &self.{rust_member_name} {{")?;
                    writeln!(w, "            {validator}")?;
                    writeln!(w, "        }}")?;
                } else {
                    writeln!(
                        w,
                        "        if let Some(value_opt) = &self.{rust_member_name} && let Some(value) = value_opt {{"
                    )?;
                    writeln!(w, "            {validator}")?;
                    writeln!(w, "        }}")?;
                }
            }
        }
        writeln!(w, "        Ok(())")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }

    /// Writes a builder structure for this error type instead of using derive_builder.
    ///
    /// This is required because the builder needs to be infalliable to be compatible with the AWS
    /// SDK.
    fn write_error_builder(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let error_code = self.error_code();

        writeln!(w, "/// Builder for [`{rust_typename}`].")?;
        writeln!(w, "#[derive(::std::clone::Clone, ::std::fmt::Debug, ::std::default::Default)]")?;
        writeln!(w, "pub struct {rust_typename}Builder {{")?;
        writeln!(w, "    message: ::std::option::Option<::std::string::String>,")?;
        writeln!(w, "    meta: ::std::option::Option<::aws_smithy_types::error::ErrorMetadata>,")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        writeln!(w, "impl {rust_typename}Builder {{")?;
        writeln!(w, "    /// Sets the error message for this error.")?;
        writeln!(w, "    pub fn message(mut self, message: impl Into<::std::string::String>) -> Self {{")?;
        writeln!(w, "        self.message = Some(message.into());")?;
        writeln!(w, "        self")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    /// Sets or resets the message for this error.")?;
        writeln!(
            w,
            "    pub fn set_message(mut self, message: ::std::option::Option<::std::string::String>) -> Self {{"
        )?;
        writeln!(w, "        self.message = message;")?;
        writeln!(w, "        self")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    /// Returns the error message for this error, if any.")?;
        writeln!(w, "    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {{")?;
        writeln!(w, "        &self.message")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    /// Sets the error metadata for this error.")?;
        writeln!(w, "    pub fn meta(mut self, meta: ::aws_smithy_types::error::metadata::ErrorMetadata) -> Self {{")?;
        writeln!(w, "        self.meta = Some(meta);")?;
        writeln!(w, "        self")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    /// Sets or resets the error metadata for this error.")?;
        writeln!(
            w,
            "    pub fn set_meta(mut self, meta: ::std::option::Option<::aws_smithy_types::error::metadata::ErrorMetadata>) -> Self {{"
        )?;
        writeln!(w, "        self.meta = meta;")?;
        writeln!(w, "        self")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    /// Consumes the builder and constructs a [`{rust_typename}`].")?;
        writeln!(w, "    pub fn build(self) -> {rust_typename} {{")?;
        writeln!(w, "        let meta = match self.meta {{")?;
        writeln!(w, "            Some(meta) => meta,")?;
        writeln!(w, "            None => {{")?;
        writeln!(w, "                let message = self.message.clone();")?;
        writeln!(
            w,
            "                let mut builder = ::aws_smithy_types::error::metadata::ErrorMetadata::builder().code(\"{error_code}\");"
        )?;
        writeln!(w, "                if let Some(message) = message {{")?;
        writeln!(w, "                    builder = builder.message(message);")?;
        writeln!(w, "                }}")?;
        writeln!(w, "                builder.build()")?;
        writeln!(w, "            }}")?;
        writeln!(w, "        }};")?;
        writeln!(w)?;
        writeln!(w, "        {rust_typename} {{")?;
        writeln!(w, "            message: self.message,")?;
        writeln!(w, "            meta,")?;
        writeln!(w, "        }}")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;

        Ok(())
    }

    /// Writes a CLI shorthand syntax parser for this structure if it is eligible for shorthand
    /// parsing.
    ///
    /// To be shorthand eligible, a structure must not have any nested structures or lists of
    /// structures.
    fn write_shorthand_parser(&self, w: &mut dyn Write) -> IoResult<()> {
        for member in self.members.values() {
            if !member.is_enum() && !member.is_primitive() && !member.is_list_of_primitives() {
                let smithy_name = self.base.smithy_name();
                if smithy_name == "com.amazonaws.iam#Tag" || smithy_name == "com.amazonaws.iam#ListAccountsFilter" {
                    panic!()
                }
                return Ok(());
            }
        }

        let rust_typename = self.base.rust_typename();

        writeln!(w, "#[cfg(feature = \"clap\")]")?;
        writeln!(w, "impl ::std::str::FromStr for {rust_typename} {{")?;
        writeln!(w, "    type Err = ::std::string::String;")?;
        writeln!(w)?;
        writeln!(w, "    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {{")?;
        writeln!(w, "        let value = ::scratchstack_cli_utils::parse_shorthand(s).map_err(|e| e.to_string())?;")?;
        writeln!(w, "        (&value).try_into()")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        writeln!(w, "#[cfg(feature = \"clap\")]")?;
        writeln!(w, "impl ::std::convert::TryFrom<&::scratchstack_cli_utils::ShorthandValue> for {rust_typename} {{")?;
        writeln!(w, "    type Error = ::std::string::String;")?;
        writeln!(w)?;
        writeln!(
            w,
            "    fn try_from(value: &::scratchstack_cli_utils::ShorthandValue) -> ::std::result::Result<Self, Self::Error> {{"
        )?;
        writeln!(w, "        match value {{")?;
        writeln!(w, "            ::scratchstack_cli_utils::ShorthandValue::Map(m) => Self::try_from(m),")?;
        writeln!(
            w,
            "            other => ::std::result::Result::Err(format!(\"Expected a map for {rust_typename} but got '{{other:?}}\")),"
        )?;
        writeln!(w, "        }}")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        writeln!(w, "#[cfg(feature = \"clap\")]")?;
        writeln!(
            w,
            "impl ::std::convert::TryFrom<&std::collections::HashMap<String, ::scratchstack_cli_utils::ShorthandValue>> for {rust_typename} {{"
        )?;
        writeln!(w, "    type Error = ::std::string::String;")?;
        writeln!(w)?;
        writeln!(
            w,
            "    fn try_from(map: &std::collections::HashMap<String, ::scratchstack_cli_utils::ShorthandValue>) -> ::std::result::Result<Self, Self::Error> {{"
        )?;
        if self.members.is_empty() {
            writeln!(w, "        let builder = Self::builder();")?;
            writeln!(w, "        if let Some(key) = map.keys().next() {{")?;
            writeln!(
                w,
                "            return ::std::result::Result::Err(format!(\"Unexpected field '{{key}}' for {rust_typename}\"));"
            )?;
            writeln!(w, "        }}")?;
        } else {
            writeln!(w, "        let mut builder = Self::builder();")?;
            writeln!(w, "        for (key, value) in map {{")?;
            writeln!(w, "            match key.as_str() {{")?;
            for (member_name, member) in &self.members {
                let arg_name = member_name.to_pascal_case();
                let rust_member_name = member_name.to_snake_case();
                let rust_member_typename = member.rust_typename();
                writeln!(w, "                 \"{arg_name}\" => {{")?;
                writeln!(
                    w,
                    "                     let value: {rust_member_typename} = value.try_into().map_err(|e| format!(\"Failed to parse field '{member_name}' for {rust_typename} from '{{value:?}}': {{e}}\"))?;"
                )?;
                if member.is_required() || member.is_list() {
                    writeln!(w, "                     builder = builder.{rust_member_name}(value);")?;
                } else {
                    writeln!(
                        w,
                        "                     builder = builder.{rust_member_name}(::std::option::Option::Some(value));"
                    )?;
                }
                writeln!(w, "                 }}")?;
            }
            writeln!(
                w,
                "                 _ => return ::std::result::Result::Err(format!(\"Unknown field '{{key}}' for {rust_typename}\")),"
            )?;
            writeln!(w, "            }}")?;
            writeln!(w, "        }}")?;
        }
        writeln!(w)?;
        writeln!(w, "        builder.build().map_err(|e| format!(\"Failed to build {rust_typename}: {{e}}\"))")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }
}
