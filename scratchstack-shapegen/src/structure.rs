use {
    super::{Member, ShapeBase, ShapeInfo, SmithyModel, StrExt, Writers, status_code_const},
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

    /// The XML namespace of the service this structure belongs to.
    ///
    /// This is copied from the model during a call to `resolve`.
    #[serde(skip, default)]
    pub xmlns: Option<String>,
}

impl ShapeInfo for Structure {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        // These have to agree with where `generate` writes each structure: errors to
        // `types_error`, operation input/output to `operation`, and everything else to `types`.
        if self.base.traits.is_error() {
            format!("crate::error::{}", self.base.rust_typename())
        } else if self.base.traits.is_input() || self.base.traits.is_output() {
            format!("crate::operation::{}", self.base.rust_typename())
        } else {
            format!("crate::types::{}", self.base.rust_typename())
        }
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);
        for member in self.members.values_mut() {
            member.resolve(shape_name, model);
        }

        self.xmlns.clone_from(&model.xmlns);
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
            let rust_member_name = member_name.to_rust_ident();

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
            let rust_member_name = member_name.to_rust_ident();
            let field_type = self.builder_field_type(member);
            writeln!(w, "    {rust_member_name}: ::std::option::Option<{field_type}>,")?;
        }
        writeln!(w, "}}")?;
        writeln!(w)?;

        writeln!(w, "impl {rust_typename}Builder {{")?;

        // 2. Per-field setters.
        //
        //    The plain setter always takes the member's own type, so a caller with a value in hand
        //    writes `.path("/engineering/")` rather than `.path(Some("/engineering/".to_string()))`.
        //    Optional and list members additionally get a `set_` form for callers that already
        //    hold an `Option` or a `Vec` -- typically forwarding one straight through from a
        //    request -- and for lists the plain setter appends a single item.
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_rust_ident();
            let set_member_name = member_name.to_rust_ident_affixed("set_", "");
            let field_type = self.builder_field_type(member);
            let is_list = member.is_list();
            // For a list the field is `Vec<T>`; the plain setter appends a single `T`.
            let item_type = match member.as_list() {
                Some(list) => list.member.rust_typename(),
                None => member.rust_typename(),
            };
            let is_optional = !member.is_required() && !is_list;

            if is_list {
                writeln!(w, "    /// Appends a value to the `{member_name}` list.")?;
                writeln!(
                    w,
                    "    pub fn {rust_member_name}(mut self, value: impl ::std::convert::Into<{item_type}>) -> Self {{"
                )?;
                writeln!(
                    w,
                    "        self.{rust_member_name}.get_or_insert_with(::std::vec::Vec::new).push(value.into());"
                )?;
            } else {
                writeln!(w, "    /// Sets the `{member_name}` field.")?;
                writeln!(
                    w,
                    "    pub fn {rust_member_name}(mut self, value: impl ::std::convert::Into<{item_type}>) -> Self {{"
                )?;
                if is_optional {
                    writeln!(
                        w,
                        "        self.{rust_member_name} = ::std::option::Option::Some(::std::option::Option::Some(value.into()));"
                    )?;
                } else {
                    writeln!(w, "        self.{rust_member_name} = ::std::option::Option::Some(value.into());")?;
                }
            }
            writeln!(w, "        self")?;
            writeln!(w, "    }}")?;
            writeln!(w)?;

            if is_optional || is_list {
                writeln!(w, "    /// Sets the `{member_name}` field from a value the caller already holds.")?;
                writeln!(w, "    pub fn {set_member_name}(mut self, value: {field_type}) -> Self {{")?;
                writeln!(w, "        self.{rust_member_name} = ::std::option::Option::Some(value);")?;
                writeln!(w, "        self")?;
                writeln!(w, "    }}")?;
                writeln!(w)?;
            }
        }

        // 3. The private validate() method (kept verbatim from the prior implementation).
        writeln!(w, "    #[allow(clippy::collapsible_if)]")?;
        writeln!(w, "    fn validate(&self) -> ::std::result::Result<(), ::std::string::String> {{")?;
        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_rust_ident();
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
            let rust_member_name = member_name.to_rust_ident();
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

    /// Writes the Rust declaration for an error structure.
    ///
    /// Modelled errors carry only a message and a request id; everything else about them (code,
    /// HTTP status, sender/receiver) is fixed by the model and rendered as trait impls rather
    /// than stored per-instance.
    fn write_error_decl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        // Write the documentation comments for the structure, if any.
        self.base.traits.write_docs(w, "")?;

        writeln!(
            w,
            "#[derive(::bon::Builder, ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]"
        )?;
        writeln!(w, "pub struct {rust_typename} {{")?;
        writeln!(w, "    /// The human-readable error message, if any.")?;
        writeln!(w, "    #[builder(into)]")?;
        writeln!(w, "    pub message: ::std::option::Option<::std::string::String>,")?;
        writeln!(w)?;
        writeln!(w, "    /// The request id associated with the request, if available.")?;
        writeln!(w, "    #[builder(into)]")?;
        writeln!(w, "    pub request_id: ::std::option::Option<::std::string::String>,")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        Ok(())
    }

    /// Writes the `Display`, `Error`, `ProvideErrorMetadata`, `ProvideRequestId`, `Deserialize`,
    /// and `Serialize` implementations for an error structure.
    fn write_error_impl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let code = self.error_code();
        let xmlns = self.xmlns.as_deref().expect("XML namespace must be resolved before generating");
        let http_status = status_code_const(
            self.base
                .traits
                .http_error()
                .unwrap_or_else(|| panic!("No httpError trait set for error shape {rust_typename}")),
        );

        // Smithy spells these "client"/"server"; the AWS query protocol puts "Sender"/"Receiver"
        // on the wire. Map once, here, and use the result everywhere below -- deriving the two
        // spellings independently is how they drift apart.
        let error_type = match self.base.traits.error().as_deref() {
            Some("client") => "Sender",
            Some("server") => "Receiver",
            other => panic!("Unknown error type {other:?} for error shape {rust_typename}"),
        };

        // Display impl
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

        // Error impl
        writeln!(w, "impl ::std::error::Error for {rust_typename} {{}}")?;
        writeln!(w)?;

        // ProvideErrorMetadata impl
        writeln!(w, "impl ::scratchstack_core::error::ProvideErrorMetadata for {rust_typename} {{")?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn error_type(&self) -> ::scratchstack_core::error::ErrorType {{")?;
        writeln!(w, "        ::scratchstack_core::error::ErrorType::{error_type}")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn code(&self) -> &str {{")?;
        writeln!(w, "        \"{code}\"")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn message(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w, "        self.message.as_deref()")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn http_status(&self) -> ::std::option::Option<::scratchstack_core::http::StatusCode> {{")?;
        writeln!(w, "        ::std::option::Option::Some({http_status})")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        // ProvideRequestId impl
        writeln!(w, "impl ::scratchstack_core::ProvideRequestId for {rust_typename} {{")?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn request_id(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w, "        self.request_id.as_deref()")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        // Deserialize impl
        writeln!(w, "impl<'de> ::serde::Deserialize<'de> for {rust_typename} {{")?;
        writeln!(
            w,
            "    fn deserialize<D: ::serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {{"
        )?;
        writeln!(w, "        struct {rust_typename}Visitor;")?;
        writeln!(w, "        impl<'de> ::serde::de::Visitor<'de> for {rust_typename}Visitor {{")?;
        writeln!(w, "            type Value = {rust_typename};")?;
        writeln!(w, "            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {{")?;
        writeln!(w, "                formatter.write_str(\"{rust_typename}\")")?;
        writeln!(w, "            }}")?;
        writeln!(w)?;
        writeln!(
            w,
            "            fn visit_map<A: ::serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {{"
        )?;
        writeln!(w, "                let mut result = {rust_typename}::default();")?;
        writeln!(w, "                while let ::std::option::Option::Some(entry) = map.next_entry()? {{")?;
        writeln!(w, "                    let (key, value): (&'de str, ::std::string::String) = entry;")?;
        writeln!(w)?;
        writeln!(w, "                    match key {{")?;
        writeln!(
            w,
            "                        \"Message\" | \"message\" => result.message = ::std::option::Option::Some(value),"
        )?;
        writeln!(
            w,
            "                        \"RequestId\" | \"request_id\" => result.request_id = ::std::option::Option::Some(value),"
        )?;
        writeln!(w, "                        _ => (),")?;
        writeln!(w, "                    }}")?;
        writeln!(w, "                }}")?;
        writeln!(w)?;
        writeln!(w, "                ::std::result::Result::Ok(result)")?;
        writeln!(w, "            }}")?;
        writeln!(w, "        }}")?;
        writeln!(w)?;
        writeln!(w, "        deserializer.deserialize_map({rust_typename}Visitor)")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        // Serialize impl. This renders the inner `<Error>` element; the request id belongs to the
        // surrounding envelope and is deliberately not emitted here.
        //
        // The fields are named as a structure's rather than entered as a map's. An XML response is
        // rendered through a serializer that gives a map the query protocol's form -- `<entry>`
        // wrapping a `<key>` and a `<value>` -- and it cannot tell a structure spelled as a map
        // from a map of data, so an error spelled that way would go out as entry pairs.
        writeln!(w, "impl ::serde::Serialize for {rust_typename} {{")?;
        writeln!(
            w,
            "    fn serialize<S: ::serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {{"
        )?;
        writeln!(w, "        use ::serde::ser::SerializeStruct as _;")?;
        writeln!(w, "        let mut e = serializer.serialize_struct(\"Error\", 3)?;")?;
        writeln!(w, "        e.serialize_field(\"Type\", \"{error_type}\")?;")?;
        writeln!(w, "        e.serialize_field(\"Code\", \"{code}\")?;")?;
        writeln!(w, "        match self.message.as_ref() {{")?;
        writeln!(w, "            ::std::option::Option::Some(message) => e.serialize_field(\"Message\", message)?,")?;
        writeln!(w, "            ::std::option::Option::None => e.skip_field(\"Message\")?,")?;
        writeln!(w, "        }}")?;
        writeln!(w, "        e.end()")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        // ProvideXmlNamespace impl
        writeln!(w, "impl ::scratchstack_core::ProvideXmlNamespace for {rust_typename} {{")?;
        writeln!(w, "    #[inline(always)]")?;
        writeln!(w, "    fn xml_namespace(&self) -> &str {{")?;
        writeln!(w, "        \"{xmlns}\"")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;

        // Responder impl
        writeln!(w, "impl ::scratchstack_core::response::Responder for {rust_typename} {{")?;
        writeln!(
            w,
            "    fn respond(&self) -> ::scratchstack_core::http::Response<::scratchstack_core::axum::body::Body> {{"
        )?;
        writeln!(w, "        ::scratchstack_core::response::ErrorResponseEnvelope::new(self).respond()")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
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
                let rust_member_name = member_name.to_rust_ident();
                let set_member_name = member_name.to_rust_ident_affixed("set_", "");
                let rust_member_typename = member.rust_typename();
                writeln!(w, "                 \"{arg_name}\" => {{")?;
                writeln!(
                    w,
                    "                     let value: {rust_member_typename} = value.try_into().map_err(|e| format!(\"Failed to parse field '{member_name}' for {rust_typename} from '{{value:?}}': {{e}}\"))?;"
                )?;
                // The plain setter takes the member's own type in every case now: it sets the
                // value for a required member, wraps it for an optional one, and for a list the
                // parsed value is the whole list, so that goes through the `set_` form.
                if member.is_list() {
                    writeln!(w, "                     builder = builder.{set_member_name}(value);")?;
                } else {
                    writeln!(w, "                     builder = builder.{rust_member_name}(value);")?;
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
