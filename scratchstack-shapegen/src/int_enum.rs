use {
    crate::{Member, Modules, ShapeBase, ShapeInfo, StrExt, doc_tokens, ident},
    proc_macro2::{Literal, TokenStream},
    quote::quote,
    serde::{Deserialize, Serialize},
    std::collections::BTreeMap,
};

/// An `intEnum` is used to represent an enumerated set of one or more integer values. The members
/// of intEnum MUST be marked with the enumValue trait set to a unique integer value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntEnum {
    /// Basic shape information for the enum.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// The members of the intEnum. Each member MUST be marked with the enumValue trait set to a
    /// unique integer value.
    pub members: BTreeMap<String, Member>,
}

impl ShapeInfo for IntEnum {
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

    fn resolve(&mut self, shape_name: &str, _model: &crate::SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn generate(&self, m: &mut Modules) {
        let module = if self.base.traits.is_error() {
            &mut m.types_error
        } else {
            &mut m.types
        };
        module.extend(self.rust_decl());
    }
}

impl IntEnum {
    /// The Rust declaration for this enum, a discriminant per variant.
    fn rust_decl(&self) -> TokenStream {
        // The bare name: `rust_typename` is module-qualified, for naming the type from elsewhere.
        let type_name = self.base.rust_typename();
        let name = ident(&type_name);
        let docs = doc_tokens(self.base.traits.documentation());

        let variants = self.members.iter().map(|(member_name, member)| {
            let variant_name = member_name.to_pascal_case();
            let variant = ident(&variant_name);
            let variant_docs = doc_tokens(member.traits.documentation());
            let value = member.traits.enum_value_as_i64().unwrap_or_else(|| {
                panic!("intEnum {type_name} variant {member_name} has no integer smithy.api#enumValue")
            });
            let value = Literal::i64_unsuffixed(value);
            let rename = if variant_name == *member_name {
                quote!()
            } else {
                quote!(#[serde(rename = #member_name)])
            };

            quote! {
                #variant_docs
                #rename
                #variant = #value,
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
}
