use {
    super::{Member, Modules, ShapeBase, ShapeInfo, SmithyModel, StrExt as _, doc_tokens, ident, type_tokens},
    quote::quote,
    serde::{Deserialize, Serialize},
    std::collections::BTreeMap,
};

/// The union type represents a tagged union data structure that can take on several different,
/// but fixed, types. Unions function similarly to structures except that only one member can
/// be used at any one time. Each member in the union is a variant of the tagged union, where
/// member names are the tags of each variant, and the shapes targeted by members are the values
/// of each variant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Union {
    /// Basic shape information for the `union` type.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// The members of the union. Each member is a variant of the tagged union, where member names
    /// are the tags of each variant, and the shapes targeted by members are the values of each
    /// variant.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub members: BTreeMap<String, Member>,
}

impl ShapeInfo for Union {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        format!("crate::types::{}", self.base.rust_typename())
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);
        for member in self.members.values_mut() {
            member.resolve(shape_name, model);
        }
    }

    fn generate(&self, m: &mut Modules) {
        let name = ident(&self.base.rust_typename());
        let docs = doc_tokens(self.base.traits.documentation());
        let variants = self.members.iter().map(|(member_name, member)| {
            let variant = ident(&member_name.to_pascal_case());
            let variant_type = type_tokens(&member.rust_typename());
            quote! {
                #[serde(tag = #member_name)]
                #variant(#variant_type),
            }
        });

        m.types.extend(quote! {
            #docs
            #[derive(Debug, ::serde::Deserialize, ::serde::Serialize)]
            #[non_exhaustive]
            pub enum #name {
                #(#variants)*
            }
        });
    }
}
