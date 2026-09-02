use {
    crate::{CliShorthand, Member, Modules, ShapeBase, ShapeInfo, StrExt, doc_tokens, ident},
    proc_macro2::TokenStream,
    quote::quote,
    serde::{Deserialize, Serialize},
    serde_json::Value as JsonValue,
    std::collections::BTreeMap,
};

/// The _enum_ shape is used to represent a fixed set of one or more string values. Each value
/// listed in the enum is a member that implicitly targets the unit type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enum {
    /// Basic shape information for the enum.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// Which shapes get CLI shorthand parsers.
    ///
    /// This is copied from the model during a call to `resolve`.
    #[serde(skip, default)]
    pub cli_shorthand: CliShorthand,

    /// The members of the enum. Each member implicitly targets the unit type.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub members: BTreeMap<String, Member>,
}

impl ShapeInfo for Enum {
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

    fn resolve(&mut self, shape_name: &str, model: &crate::SmithyModel) {
        self.base.resolve(shape_name);
        self.cli_shorthand = model.cli_shorthand;
    }

    fn generate(&self, m: &mut Modules) {
        if self.base.traits.is_error() {
            m.types_error.extend(self.rust_decl());
            m.types_error.extend(self.display_impl());
        } else {
            m.types.extend(self.rust_decl());
            m.types.extend(self.display_impl());
            m.types.extend(self.str_parse_impl());

            // An enum is a value type, so the policy governs it exactly as it governs a structure.
            // `ValueEnum` is not gated: it is how clap turns a scalar argument into an enum, which
            // a command line can use without any shorthand at all.
            if self.cli_shorthand.includes_value_types() {
                m.types.extend(self.shorthand_parser());
            }

            m.types.extend(self.clap_value_enum());
        }
    }
}

impl Enum {
    /// The wire value of a member: its `enumValue` trait, or the member name.
    fn wire_value(member_name: &str, member: &Member) -> String {
        match member.traits.enum_value() {
            Some(JsonValue::String(enum_value)) => enum_value,
            _ => member_name.to_string(),
        }
    }

    /// The Rust declaration for this enum.
    fn rust_decl(&self) -> TokenStream {
        let name = ident(&self.base.rust_typename());
        let docs = doc_tokens(self.base.traits.documentation());

        let variants = self.members.iter().map(|(member_name, member)| {
            let variant_name = member_name.to_pascal_case();
            let variant = ident(&variant_name);
            let variant_docs = doc_tokens(member.traits.documentation());

            // Rename to the *wire* value, not the Smithy member name. `enumValue` is what goes on
            // the wire -- IAM's `ContextKeyTypeEnum` member `STRING` has the value `string` -- and
            // renaming to the member name made serde disagree with `Display` and `FromStr`, which
            // use `enumValue`. Serialization emitted a value AWS never sends, and deserialization
            // rejected the one it does.
            let wire_value = Self::wire_value(member_name, member);
            let rename = if wire_value == variant_name {
                quote!()
            } else {
                quote!(#[serde(rename = #wire_value)])
            };

            quote! {
                #variant_docs
                #rename
                #variant,
            }
        });

        quote! {
            #docs
            #[derive(::serde::Deserialize, ::serde::Serialize)]
            #[derive(
                ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq,
                ::std::cmp::PartialOrd, ::std::fmt::Debug, ::std::hash::Hash, ::std::marker::Copy
            )]
            #[non_exhaustive]
            pub enum #name {
                #(#variants)*
            }
        }
    }

    /// The `Display` implementation, writing each variant's wire value.
    fn display_impl(&self) -> TokenStream {
        let name = ident(&self.base.rust_typename());
        let arms = self.members.iter().map(|(member_name, member)| {
            let variant = ident(&member_name.to_pascal_case());
            let wire_value = Self::wire_value(member_name, member);
            quote!(Self::#variant => f.write_str(#wire_value),)
        });

        quote! {
            impl ::std::fmt::Display for #name {
                fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                    match self {
                        #(#arms)*
                    }
                }
            }
        }
    }

    /// The `FromStr` implementation, accepting each variant's wire value.
    fn str_parse_impl(&self) -> TokenStream {
        let name = ident(&self.base.rust_typename());
        let invalid = format!("Invalid value '{{s}}' for {}", self.base.rust_typename());
        let arms = self.members.iter().map(|(member_name, member)| {
            let variant = ident(&member_name.to_pascal_case());
            let wire_value = Self::wire_value(member_name, member);
            quote!(#wire_value => Ok(Self::#variant),)
        });

        quote! {
            impl ::std::str::FromStr for #name {
                type Err = String;
                fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                    match s {
                        #(#arms)*
                        _ => Err(::std::format!(#invalid)),
                    }
                }
            }
        }
    }

    /// A `TryFrom<ShorthandValue>` implementation, so the enum can be parsed from CLI shorthand.
    fn shorthand_parser(&self) -> TokenStream {
        let name = ident(&self.base.rust_typename());
        let expected = format!("Expected a string for {} but got '{{value:?}}", self.base.rust_typename());

        quote! {
            #[cfg(feature = "clap")]
            impl ::std::convert::TryFrom<&::scratchstack_cli_utils::ShorthandValue> for #name {
                type Error = ::std::string::String;
                fn try_from(
                    value: &::scratchstack_cli_utils::ShorthandValue,
                ) -> ::std::result::Result<Self, Self::Error> {
                    let ::scratchstack_cli_utils::ShorthandValue::Scalar(value) = value else {
                        return ::std::result::Result::Err(::std::format!(#expected));
                    };

                    <Self as ::std::str::FromStr>::from_str(value.as_str())
                }
            }
        }
    }

    /// A `clap::ValueEnum` implementation, so the enum can be a command-line argument type.
    fn clap_value_enum(&self) -> TokenStream {
        let name = ident(&self.base.rust_typename());
        let variants = self.members.keys().map(|member_name| {
            let variant = ident(&member_name.to_pascal_case());
            quote!(Self::#variant,)
        });
        let arms = self.members.iter().map(|(member_name, member)| {
            let variant = ident(&member_name.to_pascal_case());
            let wire_value = Self::wire_value(member_name, member);
            quote!(Self::#variant => #wire_value,)
        });

        quote! {
            #[cfg(feature = "clap")]
            impl ::clap::ValueEnum for #name {
                fn value_variants<'a>() -> &'a [Self] {
                    &[#(#variants)*]
                }

                fn to_possible_value(&self) -> ::std::option::Option<::clap::builder::PossibleValue> {
                    let s = match self {
                        #(#arms)*
                    };

                    ::std::option::Option::Some(::clap::builder::PossibleValue::new(s))
                }
            }
        }
    }
}
