use {
    super::{
        CliShorthand, Member, Modules, ShapeBase, ShapeInfo, SmithyModel, StrExt, doc_tokens, ident, status_code_const,
        type_tokens,
    },
    proc_macro2::TokenStream,
    quote::quote,
    serde::{Deserialize, Serialize},
    std::collections::BTreeMap,
};

/// The structure type represents a fixed set of named, unordered, heterogeneous values. A
/// structure shape contains a set of named members, and each member name maps to exactly one
/// member definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Structure {
    /// Basic shape information for the `structure` type.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// Which shapes get CLI shorthand parsers.
    ///
    /// This is copied from the model during a call to `resolve`.
    #[serde(skip, default)]
    pub cli_shorthand: CliShorthand,

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
        self.cli_shorthand = model.cli_shorthand;
    }

    /// Generates code that implements the structure.
    ///
    /// This can be in any number of modules; typically:
    /// * `crate::types` for regular structures
    /// * `crate::types::error` for structures that are marked with the error trait.
    /// * `crates::operation::<op-name>` for structures that are used as the input or output of an operation.`
    fn generate(&self, m: &mut Modules) {
        let is_error = self.base.traits.is_error();
        let is_input = self.base.traits.is_input();
        let is_output = self.base.traits.is_output();

        assert!(
            !(is_error && (is_input || is_output)),
            "shape {} is marked as an error and as an operation input or output; it can be only one",
            self.base.smithy_name()
        );

        if is_error {
            m.types_error.extend(self.error_decl());
            m.types_error.extend(self.error_impl());
        } else if is_input || is_output {
            m.operation.extend(self.rust_decl());
            m.operation.extend(self.rust_impl());
            m.operation.extend(self.builder());

            if is_input && self.cli_shorthand.includes_operation_inputs() {
                m.operation.extend(self.shorthand_parser());
            }
        } else {
            m.types.extend(self.rust_decl());
            m.types.extend(self.rust_impl());
            m.types.extend(self.builder());

            if self.cli_shorthand.includes_value_types() {
                m.types.extend(self.shorthand_parser());
            }
        }
    }
}

impl Structure {
    /// For error structures, returns the AWS error code (string) to use for this structure.
    #[must_use]
    fn error_code(&self) -> String {
        // An explicit awsQueryError code wins; otherwise the type name without its `Exception`
        // suffix, which is the convention the AWS models follow.
        if let Some(code) = self
            .base
            .traits
            .aws_query_error()
            .as_ref()
            .and_then(|query_error| query_error.get("code"))
            .and_then(|code| code.as_str())
        {
            return code.to_string();
        }

        let rust_typename = self.base.rust_typename();
        rust_typename.strip_suffix("Exception").unwrap_or(&rust_typename).to_string()
    }

    /// Indicates whether this structure is eligible for CLI shorthand parsing.
    ///
    /// To be eligible, every member must be something the shorthand grammar can express: a
    /// primitive, an enum, or a list of primitives.
    ///
    /// Lists of enums are deliberately excluded. The shorthand grammar could express them, and an
    /// earlier unused predicate here accepted them, but the parser this gates has never actually
    /// been emitted for one. Widening the rule would add a `FromStr` to two IAM request types, so
    /// it is a change to make on purpose rather than in passing.
    #[must_use]
    pub fn is_cli_shorthand_parsable(&self) -> bool {
        self.members.values().all(|member| member.is_primitive() || member.is_enum() || member.is_list_of_primitives())
    }

    /// Writes the Rust declaration for the main body of this structure.
    fn rust_decl(&self) -> TokenStream {
        let name = ident(&self.base.rust_typename());
        let docs = doc_tokens(self.base.traits.documentation());

        let fields = self.members.iter().map(|(member_name, member)| {
            let field = ident(&member_name.to_rust_ident());
            let field_docs = doc_tokens(member.traits.documentation());
            let field_type = type_tokens(&self.field_type(member));

            // An optional scalar is skipped when absent rather than serialized as an empty
            // element; a list is always present, empty or not.
            if member.is_required() || member.is_list() {
                quote! {
                    #field_docs
                    #[serde(rename = #member_name)]
                    pub #field: #field_type,
                }
            } else {
                quote! {
                    #field_docs
                    #[serde(rename = #member_name, skip_serializing_if = "Option::is_none")]
                    pub #field: #field_type,
                }
            }
        });

        quote! {
            #docs
            #[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug)]
            #[derive(::serde::Deserialize, ::serde::Serialize)]
            pub struct #name {
                #(#fields)*
            }
        }
    }

    /// The declared type of a member: its own type, wrapped in `Option` when optional.
    fn field_type(&self, member: &Member) -> String {
        let rust_typename = member.rust_typename();
        if member.is_required() || member.is_list() {
            rust_typename
        } else {
            format!("::std::option::Option<{rust_typename}>")
        }
    }

    /// Writes the main impl of this structure, which provides the builder entry point.
    fn rust_impl(&self) -> TokenStream {
        let type_name = self.base.rust_typename();
        let name = ident(&type_name);
        let builder = ident(&format!("{type_name}Builder"));
        let builder_doc = format!(" Returns a [`{type_name}Builder`] for constructing a `{type_name}`.");

        let message_accessor = if self.base.traits.is_error() {
            quote! {
                #[doc = " Returns the error message."]
                #[inline(always)]
                pub fn message(&self) -> ::std::option::Option<&str> {
                    self.message.as_deref()
                }
            }
        } else {
            quote!()
        };

        quote! {
            impl #name {
                #[doc = #builder_doc]
                #[inline(always)]
                pub fn builder() -> #builder {
                    #builder::default()
                }

                #message_accessor
            }
        }
    }

    /// Writes a hand-rolled builder for this non-error structure.
    ///
    /// Setters take `impl Into<T>` where `T` is the struct field type, internal storage is
    /// `Option<T>`, and `build()` validates before constructing, returning a typed
    /// `ValidationError` rather than an opaque builder error.
    fn builder(&self) -> TokenStream {
        let type_name = self.base.rust_typename();
        let name = ident(&type_name);
        let builder = ident(&format!("{type_name}Builder"));
        let builder_doc = format!(" Builder for [`{type_name}`].");

        let fields = self.members.iter().map(|(member_name, member)| {
            let field = ident(&member_name.to_rust_ident());
            let field_type = type_tokens(&self.field_type(member));
            quote!(#field: ::std::option::Option<#field_type>,)
        });

        let setters = self.members.iter().map(|(member_name, member)| self.setters(member_name, member));
        let validate = self.validate_fn();
        let build = self.build_fn(&name);

        quote! {
            #[doc = #builder_doc]
            #[derive(::std::clone::Clone, ::std::fmt::Debug, ::std::default::Default)]
            pub struct #builder {
                #(#fields)*
            }

            impl #builder {
                #(#setters)*
                #validate
                #build
            }
        }
    }

    /// The setters for one member.
    ///
    /// The plain setter always takes the member's own type, so a caller with a value in hand writes
    /// `.path("/engineering/")` rather than `.path(Some("/engineering/".to_string()))`. Optional and
    /// list members additionally get a `set_` form for callers that already hold an `Option` or a
    /// `Vec` -- typically forwarding one straight through from a request -- and for lists the plain
    /// setter appends a single item.
    fn setters(&self, member_name: &str, member: &Member) -> TokenStream {
        let field = ident(&member_name.to_rust_ident());
        let is_list = member.is_list();
        let is_optional = !member.is_required() && !is_list;

        // For a list the field is `Vec<T>`; the plain setter appends a single `T`.
        let item_type = type_tokens(&match member.as_list() {
            Some(list) => list.member.rust_typename(),
            None => member.rust_typename(),
        });

        let plain_doc = if is_list {
            format!(" Appends a value to the `{member_name}` list.")
        } else {
            format!(" Sets the `{member_name}` field.")
        };

        let assign = if is_list {
            quote!(self.#field.get_or_insert_with(::std::vec::Vec::new).push(value.into());)
        } else if is_optional {
            quote!(self.#field = ::std::option::Option::Some(::std::option::Option::Some(value.into()));)
        } else {
            quote!(self.#field = ::std::option::Option::Some(value.into());)
        };

        let plain = quote! {
            #[doc = #plain_doc]
            pub fn #field(mut self, value: impl ::std::convert::Into<#item_type>) -> Self {
                #assign
                self
            }
        };

        if !is_optional && !is_list {
            return plain;
        }

        let set_field = ident(&member_name.to_rust_ident_affixed("set_", ""));
        let set_doc = format!(" Sets the `{member_name}` field from a value the caller already holds.");
        let field_type = type_tokens(&self.field_type(member));

        quote! {
            #plain

            #[doc = #set_doc]
            pub fn #set_field(mut self, value: #field_type) -> Self {
                self.#field = ::std::option::Option::Some(value);
                self
            }
        }
    }

    /// The private `validate` method: required-field checks, then per-field constraint checks.
    fn validate_fn(&self) -> TokenStream {
        let checks = self.members.iter().map(|(member_name, member)| {
            let field = ident(&member_name.to_rust_ident());
            let is_required = member.is_required();
            let is_list = member.is_list();

            let required_check = if is_required && !is_list {
                let message =
                    format!("Missing required field '{member_name}' when building {}", self.base.rust_typename());
                quote! {
                    if self.#field.is_none() {
                        return ::std::result::Result::Err(#message.to_string());
                    }
                }
            } else {
                quote!()
            };

            // The check itself lives in the target shape's validator function; the member name is
            // passed so the error names the field rather than the structure.
            let Some(validator_fn) = member.validator_fn_name() else {
                return required_check;
            };
            let validator = ident(&validator_fn);

            let constraint_check = if is_required || is_list {
                quote! {
                    if let ::std::option::Option::Some(value) = &self.#field {
                        crate::types::#validator(value, #member_name)?;
                    }
                }
            } else {
                quote! {
                    if let ::std::option::Option::Some(value_opt) = &self.#field
                        && let ::std::option::Option::Some(value) = value_opt
                    {
                        crate::types::#validator(value, #member_name)?;
                    }
                }
            };

            quote! {
                #required_check
                #constraint_check
            }
        });

        quote! {
            fn validate(&self) -> ::std::result::Result<(), ::std::string::String> {
                #(#checks)*
                ::std::result::Result::Ok(())
            }
        }
    }

    /// The public `build` method.
    ///
    /// `validate` catches missing required fields, so they can be unwrapped safely once it returns.
    fn build_fn(&self, name: &proc_macro2::Ident) -> TokenStream {
        let build_doc = format!(" Consumes the builder and constructs a [`{}`].", self.base.rust_typename());

        let fields = self.members.iter().map(|(member_name, member)| {
            let field = ident(&member_name.to_rust_ident());
            if member.is_required() && !member.is_list() {
                let message = format!("validate confirmed {member_name} is set");
                quote!(#field: self.#field.expect(#message),)
            } else {
                quote!(#field: self.#field.unwrap_or_default(),)
            }
        });

        quote! {
            #[doc = #build_doc]
            pub fn build(self) -> ::std::result::Result<#name, crate::types::error::ValidationError> {
                self.validate().map_err(|msg| {
                    crate::types::error::ValidationError::builder().message(msg).build()
                })?;
                ::std::result::Result::Ok(#name {
                    #(#fields)*
                })
            }
        }
    }

    /// The Rust declaration for an error structure.
    fn error_decl(&self) -> TokenStream {
        let name = ident(&self.base.rust_typename());
        let docs = doc_tokens(self.base.traits.documentation());

        quote! {
            #docs
            #[derive(
                ::bon::Builder, ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq,
                ::std::default::Default, ::std::fmt::Debug
            )]
            pub struct #name {
                #[doc = " The human-readable error message, if any."]
                #[builder(into)]
                pub message: ::std::option::Option<::std::string::String>,

                #[doc = " The request id associated with the request, if available."]
                #[builder(into)]
                pub request_id: ::std::option::Option<::std::string::String>,
            }
        }
    }

    /// The `Display`, `Error`, `ProvideErrorMetadata`, `ProvideRequestId`, `Deserialize`,
    /// `Serialize`, `ProvideXmlNamespace` and `Responder` implementations for an error structure.
    fn error_impl(&self) -> TokenStream {
        let type_name = self.base.rust_typename();
        let name = ident(&type_name);
        let visitor = ident(&format!("{type_name}Visitor"));
        let code = self.error_code();
        let xmlns = self
            .xmlns
            .as_deref()
            .unwrap_or_else(|| panic!("error shape {type_name} has no XML namespace; resolve() before generate()"));
        let http_status = type_tokens(status_code_const(
            self.base
                .traits
                .http_error()
                .unwrap_or_else(|| panic!("No httpError trait set for error shape {type_name}")),
        ));

        // Smithy spells these "client"/"server"; the AWS query protocol puts "Sender"/"Receiver"
        // on the wire. Map once, here, and use the result everywhere below -- deriving the two
        // spellings independently is how they drift apart.
        let error_type_name = match self.base.traits.error().as_deref() {
            Some("client") => "Sender",
            Some("server") => "Receiver",
            other => panic!("Unknown error type {other:?} for error shape {type_name}"),
        };
        let error_type = ident(error_type_name);
        let display_prefix = type_name.clone();

        quote! {
            impl ::std::fmt::Display for #name {
                fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    f.write_str(#display_prefix)?;
                    if let ::std::option::Option::Some(message) = &self.message {
                        ::std::write!(f, ": {message}")?;
                    }
                    ::std::result::Result::Ok(())
                }
            }

            impl ::std::error::Error for #name {}

            impl ::scratchstack_core::error::ProvideErrorMetadata for #name {
                fn error_type(&self) -> ::scratchstack_core::error::ErrorType {
                    ::scratchstack_core::error::ErrorType::#error_type
                }

                fn code(&self) -> &str {
                    #code
                }

                fn message(&self) -> ::std::option::Option<&str> {
                    self.message.as_deref()
                }

                fn http_status(&self) -> ::std::option::Option<::scratchstack_core::http::StatusCode> {
                    ::std::option::Option::Some(#http_status)
                }
            }

            impl ::scratchstack_core::ProvideRequestId for #name {
                fn request_id(&self) -> ::std::option::Option<&str> {
                    self.request_id.as_deref()
                }
            }

            impl<'de> ::serde::Deserialize<'de> for #name {
                fn deserialize<D: ::serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    struct #visitor;
                    impl<'de> ::serde::de::Visitor<'de> for #visitor {
                        type Value = #name;

                        fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                            formatter.write_str(#display_prefix)
                        }

                        fn visit_map<A: ::serde::de::MapAccess<'de>>(
                            self,
                            mut map: A,
                        ) -> Result<Self::Value, A::Error> {
                            let mut result = #name::default();
                            while let ::std::option::Option::Some(entry) = map.next_entry()? {
                                let (key, value): (&'de str, ::std::string::String) = entry;

                                match key {
                                    "Message" | "message" => {
                                        result.message = ::std::option::Option::Some(value)
                                    }
                                    "RequestId" | "request_id" => {
                                        result.request_id = ::std::option::Option::Some(value)
                                    }
                                    _ => (),
                                }
                            }

                            ::std::result::Result::Ok(result)
                        }
                    }

                    deserializer.deserialize_map(#visitor)
                }
            }

            // This renders the inner `<Error>` element; the request id belongs to the surrounding
            // envelope and is deliberately not emitted here.
            //
            // The fields are named as a structure's rather than entered as a map's. An XML response
            // is rendered through a serializer that gives a map the query protocol's form --
            // `<entry>` wrapping a `<key>` and a `<value>` -- and it cannot tell a structure spelled
            // as a map from a map of data, so an error spelled that way would go out as entry pairs.
            impl ::serde::Serialize for #name {
                fn serialize<S: ::serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    use ::serde::ser::SerializeStruct as _;
                    let mut e = serializer.serialize_struct("Error", 3)?;
                    e.serialize_field("Type", #error_type_name)?;
                    e.serialize_field("Code", #code)?;
                    match self.message.as_ref() {
                        ::std::option::Option::Some(message) => e.serialize_field("Message", message)?,
                        ::std::option::Option::None => e.skip_field("Message")?,
                    }
                    e.end()
                }
            }

            impl ::scratchstack_core::ProvideXmlNamespace for #name {
                fn xml_namespace(&self) -> &str {
                    #xmlns
                }
            }

            impl ::scratchstack_core::response::Responder for #name {
                fn respond(&self) -> ::scratchstack_core::http::Response<::scratchstack_core::axum::body::Body> {
                    ::scratchstack_core::response::ErrorResponseEnvelope::new(self).respond()
                }
            }
        }
    }

    /// Writes a CLI shorthand syntax parser for this structure if it is eligible for shorthand
    /// parsing.
    ///
    /// To be shorthand eligible, a structure must not have any nested structures or lists of
    /// structures.
    fn shorthand_parser(&self) -> TokenStream {
        if !self.is_cli_shorthand_parsable() {
            return TokenStream::new();
        }

        let type_name = self.base.rust_typename();
        let name = ident(&type_name);
        let expected_map = format!("Expected a map for {type_name} but got '{{other:?}}");
        let build_failed = format!("Failed to build {type_name}: {{e}}");

        let from_map = if self.members.is_empty() {
            let unexpected = format!("Unexpected field '{{key}}' for {type_name}");
            quote! {
                let builder = Self::builder();
                if let Some(key) = map.keys().next() {
                    return ::std::result::Result::Err(::std::format!(#unexpected));
                }
            }
        } else {
            let unknown = format!("Unknown field '{{key}}' for {type_name}");
            let arms = self.members.iter().map(|(member_name, member)| {
                let arg_name = member_name.to_pascal_case();
                let member_type = type_tokens(&member.rust_typename());
                let parse_failed =
                    format!("Failed to parse field '{member_name}' for {type_name} from '{{value:?}}': {{e}}");

                // The plain setter takes the member's own type in every case: it sets the value for
                // a required member, wraps it for an optional one, and for a list the parsed value
                // is the whole list, so that goes through the `set_` form.
                let set = if member.is_list() {
                    let setter = ident(&member_name.to_rust_ident_affixed("set_", ""));
                    quote!(builder = builder.#setter(value);)
                } else {
                    let setter = ident(&member_name.to_rust_ident());
                    quote!(builder = builder.#setter(value);)
                };

                quote! {
                    #arg_name => {
                        let value: #member_type = value
                            .try_into()
                            .map_err(|e| ::std::format!(#parse_failed))?;
                        #set
                    }
                }
            });

            quote! {
                let mut builder = Self::builder();
                for (key, value) in map {
                    match key.as_str() {
                        #(#arms)*
                        _ => return ::std::result::Result::Err(::std::format!(#unknown)),
                    }
                }
            }
        };

        quote! {
            #[cfg(feature = "clap")]
            impl ::std::str::FromStr for #name {
                type Err = ::std::string::String;

                fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                    let value = ::scratchstack_cli_utils::parse_shorthand(s).map_err(|e| e.to_string())?;
                    (&value).try_into()
                }
            }

            #[cfg(feature = "clap")]
            impl ::std::convert::TryFrom<&::scratchstack_cli_utils::ShorthandValue> for #name {
                type Error = ::std::string::String;

                fn try_from(
                    value: &::scratchstack_cli_utils::ShorthandValue,
                ) -> ::std::result::Result<Self, Self::Error> {
                    match value {
                        ::scratchstack_cli_utils::ShorthandValue::Map(m) => Self::try_from(m),
                        other => ::std::result::Result::Err(::std::format!(#expected_map)),
                    }
                }
            }

            #[cfg(feature = "clap")]
            impl ::std::convert::TryFrom<
                &std::collections::HashMap<String, ::scratchstack_cli_utils::ShorthandValue>,
            > for #name {
                type Error = ::std::string::String;

                fn try_from(
                    map: &std::collections::HashMap<String, ::scratchstack_cli_utils::ShorthandValue>,
                ) -> ::std::result::Result<Self, Self::Error> {
                    #from_map

                    builder.build().map_err(|e| ::std::format!(#build_failed))
                }
            }
        }
    }
}
