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
            self.write_error_decl(&mut w.types_error)?;
            self.write_error_impl(&mut w.types_error)?;
            self.write_error_builder_impl(&mut w.types_error)?;
        } else if is_input || is_output {
            self.write_rust_decl(&mut w.operation)?;
            self.write_rust_impl(&mut w.operation)?;
            self.write_builder(&mut w.operation)?;

            if is_input {
                self.write_shorthand_parser(&mut w.operation)?;
            }
        } else {
            self.write_rust_decl(&mut w.types)?;
            self.write_rust_impl(&mut w.types)?;
            self.write_builder(&mut w.types)?;
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

        // Write the documentation comments for the structure, if any.
        self.base.traits.write_docs(w, "")?;

        // Attributes for the structure.
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
            writeln!(w, "    pub {rust_member_name}: {member_type},")?;
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

    /// Writes a hand-rolled builder for this non-error structure.
    ///
    /// The builder mirrors the call-site contract of the previous `derive_builder`-based
    /// implementation: setters take `impl Into<T>` where `T` is the struct field type, all
    /// internal storage is `Option<T>`, and `build()` runs validation and returns a typed
    /// `ValidationError` on failure instead of an opaque builder error.
    fn write_builder(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        // 1. The builder struct itself.
        writeln!(w, "/// Builder for [`{rust_typename}`].")?;
        writeln!(w, "#[derive(::std::clone::Clone, ::std::fmt::Debug, ::std::default::Default)]")?;
        writeln!(w, "pub struct {rust_typename}Builder {{")?;
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_snake_case();
            let field_type = self.builder_field_type(member);
            writeln!(w, "    {rust_member_name}: ::std::option::Option<{field_type}>,")?;
        }
        writeln!(w, "}}")?;
        writeln!(w)?;

        writeln!(w, "impl {rust_typename}Builder {{")?;

        // 2. Per-field setters, matching derive_builder's `setter(into)` semantics.
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_snake_case();
            let field_type = self.builder_field_type(member);
            writeln!(w, "    /// Sets the `{member_name}` field.")?;
            writeln!(
                w,
                "    pub fn {rust_member_name}(mut self, value: impl ::std::convert::Into<{field_type}>) -> Self {{"
            )?;
            writeln!(w, "        self.{rust_member_name} = ::std::option::Option::Some(value.into());")?;
            writeln!(w, "        self")?;
            writeln!(w, "    }}")?;
            writeln!(w)?;
        }

        // 3. The private validate() method (kept verbatim from the prior implementation).
        writeln!(w, "    #[allow(clippy::collapsible_if)]")?;
        writeln!(w, "    fn validate(&self) -> ::std::result::Result<(), ::std::string::String> {{")?;
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_snake_case();
            let is_required = member.is_required();
            let is_list = member.is_list();

            if is_required && !is_list {
                writeln!(w, "        if self.{rust_member_name}.is_none() {{")?;
                writeln!(
                    w,
                    "            return ::std::result::Result::Err(\"Missing required field '{member_name}' when building {rust_typename}\".to_string());"
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
        writeln!(w, "        ::std::result::Result::Ok(())")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;

        // 4. The public build() method. validate() catches missing-required and per-field
        //    constraint failures, so required fields can be unwrapped safely once it returns Ok.
        writeln!(w, "    /// Consumes the builder and constructs a [`{rust_typename}`].")?;
        writeln!(
            w,
            "    pub fn build(self) -> ::std::result::Result<{rust_typename}, crate::types::error::ValidationError> {{"
        )?;
        writeln!(w, "        self.validate().map_err(|msg| {{")?;
        writeln!(w, "            crate::types::error::ValidationError::builder()")?;
        writeln!(w, "                .message(msg)")?;
        writeln!(w, "                .build()")?;
        writeln!(w, "        }})?;")?;
        writeln!(w, "        ::std::result::Result::Ok({rust_typename} {{")?;
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_snake_case();
            let is_required = member.is_required();
            let is_list = member.is_list();
            if is_required && !is_list {
                writeln!(
                    w,
                    "            {rust_member_name}: self.{rust_member_name}.expect(\"validate confirmed required field is set\"),"
                )?;
            } else {
                writeln!(w, "            {rust_member_name}: self.{rust_member_name}.unwrap_or_default(),")?;
            }
        }
        writeln!(w, "        }})")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }

    /// Writes the Rust declaration for the main body of an error struct.
    fn write_error_decl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        // Write the documentation comments for the structure, if any.
        self.base.traits.write_docs(w, "")?;

        // Error structure itself
        writeln!(w, "#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug)]")?;
        writeln!(w, "pub struct {rust_typename} {{")?;
        writeln!(w, "    /// Metadata for this request.")?;
        writeln!(w, "    pub meta: ::aws_smithy_types::error::metadata::ErrorMetadata,")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        // Error builder structure
        writeln!(w, "/// Builder for [`{rust_typename}`].")?;
        writeln!(w, "#[derive(::std::fmt::Debug)]")?;
        writeln!(w, "pub struct {rust_typename}Builder {{")?;
        writeln!(w, "    /// Metadata builder.")?;
        writeln!(w, "    meta: ::aws_smithy_types::error::metadata::Builder,")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        Ok(())
    }

    /// Writes implementations for the error struct.
    fn write_error_impl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let code = self.error_code();
        let error_type = self.base.traits.error().unwrap();

        // Struct impl, returning a builder
        writeln!(w, r#"impl {rust_typename} {{"#)?;
        writeln!(w, r#"    /// Returns a [`{rust_typename}Builder`] for constructing a `{rust_typename}`."#)?;
        writeln!(w, r#"    pub fn builder() -> {rust_typename}Builder {{"#)?;
        writeln!(w, r#"        {rust_typename}Builder::default()"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;

        // Default impl
        writeln!(w, r#"impl ::std::default::Default for {rust_typename} {{"#)?;
        writeln!(w, r#"    fn default() -> Self {{"#)?;
        writeln!(w, r#"        let meta = ::aws_smithy_types::error::metadata::ErrorMetadata::builder()"#)?;
        writeln!(w, r#"            .code("{code}")"#)?;
        writeln!(w, r#"            .build();"#)?;
        writeln!(w, r#"        Self {{"#)?;
        writeln!(w, r#"            meta,"#)?;
        writeln!(w, r#"        }}"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;

        // Deserialize impl
        writeln!(w, r#"impl<'de> ::serde::Deserialize<'de> for {rust_typename} {{"#)?;
        writeln!(
            w,
            r#"    fn deserialize<D: ::serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {{"#
        )?;
        writeln!(w, r#"        struct {rust_typename}Visitor;"#)?;
        writeln!(w, r#"        impl<'de> ::serde::de::Visitor<'de> for {rust_typename}Visitor {{"#)?;
        writeln!(w, r#"            type Value = {rust_typename};"#)?;
        writeln!(
            w,
            r#"            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {{"#
        )?;
        writeln!(w, r#"                formatter.write_str("{rust_typename}")"#)?;
        writeln!(w, r#"            }}"#)?;
        writeln!(w)?;
        writeln!(
            w,
            r#"            fn visit_map<A: ::serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {{"#
        )?;
        writeln!(
            w,
            r#"                let mut meta_builder = ::aws_smithy_types::error::metadata::ErrorMetadata::builder().code("{code}");"#
        )?;
        writeln!(w, r#"                while let Some(entry) = map.next_entry()? {{"#)?;
        writeln!(w, r#"                    let (key, value): (&'de str, String) = entry;"#)?;
        writeln!(w)?;
        writeln!(w, r#"                    match key {{"#)?;
        writeln!(w, r#"                        "Code" | "code" => meta_builder = meta_builder.code(value),"#)?;
        writeln!(w, r#"                        "Message" | "message" => meta_builder = meta_builder.message(value),"#)?;
        writeln!(
            w,
            r#"                        "RequestId" | "request_id" => meta_builder = meta_builder.custom("request_id", value),"#
        )?;
        writeln!(w, r#"                        _ => (),"#)?;
        writeln!(w, r#"                    }}"#)?;
        writeln!(w, r#"                }}"#)?;
        writeln!(w)?;
        writeln!(w, r#"                Ok({rust_typename} {{"#)?;
        writeln!(w, r#"                    meta: meta_builder.build(),"#)?;
        writeln!(w, r#"                }})"#)?;
        writeln!(w, r#"            }}"#)?;
        writeln!(w, r#"        }}"#)?;
        writeln!(w)?;

        writeln!(w, r#"        deserializer.deserialize_map({rust_typename}Visitor)"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;

        // Display impl
        writeln!(w, r#"impl ::std::fmt::Display for {rust_typename} {{"#)?;
        writeln!(w, r#"    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{"#)?;
        writeln!(w, r#"        f.write_str("{rust_typename}")?;"#)?;
        writeln!(w, r#"        if let ::std::option::Option::Some(message) = self.meta.message() {{"#)?;
        writeln!(w, r#"            ::std::write!(f, ": {{message}}")?;"#)?;
        writeln!(w, r#"        }}"#)?;
        writeln!(w, r#"        ::std::result::Result::Ok(())"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;

        // Error impl
        writeln!(w, r#"impl ::std::error::Error for {rust_typename} {{}}"#)?;
        writeln!(w)?;

        // RequestId impl
        writeln!(w, r#"impl ::aws_types::request_id::RequestId for {rust_typename} {{"#)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(w, r#"    fn request_id(&self) -> ::std::option::Option<&str> {{"#)?;
        writeln!(w, r#"        ::aws_smithy_types::error::metadata::ProvideErrorMetadata::meta(self).request_id()"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;

        // ProvideErrorKind impl
        writeln!(w, r#"impl ::aws_smithy_types::retry::ProvideErrorKind for {rust_typename} {{"#)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(
            w,
            r#"    fn retryable_error_kind(&self) -> ::std::option::Option<::aws_smithy_types::retry::ErrorKind> {{"#
        )?;
        if error_type == "client" {
            writeln!(w, r#"        ::std::option::Option::Some(::aws_smithy_types::retry::ErrorKind::ClientError)"#)?;
        } else {
            writeln!(w, r#"        ::std::option::Option::Some(::aws_smithy_types::retry::ErrorKind::ServerError)"#)?;
        }
        writeln!(w, r#"    }}"#)?;
        writeln!(w)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(w, r#"    fn code(&self) -> ::std::option::Option<&str> {{"#)?;
        writeln!(w, r#"        ::std::option::Option::Some("{code}")"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;

        // ProvideErrorMetadata impl
        writeln!(w, r#"impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for {rust_typename} {{"#)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(w, r#"    fn meta(&self) -> &::aws_smithy_types::error::metadata::ErrorMetadata {{"#)?;
        writeln!(w, r#"        &self.meta"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;

        Ok(())
    }

    fn write_error_builder_impl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let code = self.error_code();

        writeln!(w, r#"impl ::std::default::Default for {rust_typename}Builder {{"#)?;
        writeln!(w, r#"    fn default() -> Self {{"#)?;
        writeln!(
            w,
            r#"        Self {{ meta: ::aws_smithy_types::error::metadata::ErrorMetadata::builder().code("{code}") }}"#
        )?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;
        writeln!(w, r#"impl {rust_typename}Builder {{"#)?;
        writeln!(w, r#"    /// Sets the error code, overriding the default `"{code}"` value."#)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(w, r#"    pub fn code(mut self, code: impl ::std::convert::Into<::std::string::String>) -> Self {{"#)?;
        writeln!(w, r#"        self.meta = self.meta.code(code);"#)?;
        writeln!(w, r#"        self"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w)?;
        writeln!(w, r#"    /// Sets the error message."#)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(
            w,
            r#"    pub fn message(mut self, message: impl ::std::convert::Into<::std::string::String>) -> Self {{"#
        )?;
        writeln!(w, r#"        self.meta = self.meta.message(message);"#)?;
        writeln!(w, r#"        self"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w)?;
        writeln!(w, r#"    /// Set a custom field on the error metadata"#)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(
            w,
            r#"    pub fn custom(mut self, key: &'static str, value: impl ::std::convert::Into<::std::string::String>) -> Self {{"#
        )?;
        writeln!(w, r#"        self.meta = self.meta.custom(key, value);"#)?;
        writeln!(w, r#"        self"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w)?;
        writeln!(w, r#"    /// Creates the error."#)?;
        writeln!(w, r#"    #[inline(always)]"#)?;
        writeln!(w, r#"    pub fn build(self) -> {rust_typename} {{"#)?;
        writeln!(w, r#"        {rust_typename} {{"#)?;
        writeln!(w, r#"            meta: self.meta.build(),"#)?;
        writeln!(w, r#"        }}"#)?;
        writeln!(w, r#"    }}"#)?;
        writeln!(w, r#"}}"#)?;
        writeln!(w)?;

        Ok(())
    }

    /// Returns the struct's field Rust type for a member (matching `write_rust_decl`).
    fn builder_field_type(&self, member: &Member) -> String {
        let is_optional = !member.traits.is_required();
        let is_list = member.is_list();
        let mut t = member.rust_typename();
        if is_optional && !is_list {
            t = format!("::std::option::Option<{t}>");
        }
        t
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
