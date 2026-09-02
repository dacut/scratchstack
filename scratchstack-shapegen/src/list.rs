use {
    crate::{Member, Shape, ShapeBase, ShapeInfo, SmithyModel, ident, usize_literal},
    proc_macro2::TokenStream,
    quote::quote,
    serde::{Deserialize, Serialize},
    std::{cell::RefCell, rc::Rc},
};

/// The list type represents an ordered homogeneous collection of values. A list shape requires
/// a single member named member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct List {
    /// Basic shape information for the `list` type.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// The inner type of the list.
    pub member: Member,
}

impl ShapeInfo for List {
    fn resolve(&mut self, smithy_name: &str, model: &SmithyModel) {
        self.base.resolve(smithy_name);
        self.member.resolve(smithy_name, model);
    }

    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        format!("::std::vec::Vec::<{}>", self.member.rust_typename())
    }

    fn validator_body(&self) -> Option<TokenStream> {
        if self.is_builtin() {
            return None;
        }

        let simple_name = self.simple_name();
        let mut checks = TokenStream::new();

        if let Some(length) = self.base.traits.length_constraint() {
            if let Some(min) = length.min
                && min > 0
            {
                let message =
                    format!("{{field}} must have at least {min} elements for {simple_name}: {{}} elements found");
                let too_short = if min == 1 {
                    quote!(value.is_empty())
                } else {
                    let min = usize_literal(min);
                    quote!(value.len() < #min)
                };

                checks.extend(quote! {
                    if #too_short {
                        return ::std::result::Result::Err(::std::format!(#message, value.len()));
                    }
                });
            }

            if let Some(max) = length.max {
                let message =
                    format!("{{field}} must have at most {max} elements for {simple_name}: {{}} elements found");
                let max = usize_literal(max);

                checks.extend(quote! {
                    if value.len() > #max {
                        return ::std::result::Result::Err(::std::format!(#message, value.len()));
                    }
                });
            }
        }

        // The element shape validates itself; call its function rather than inlining its checks
        // once per list that happens to contain it.
        if let Some(element_fn) = self.inner().borrow().validator_fn_name() {
            let element_fn = ident(&element_fn);
            checks.extend(quote! {
                for el in value.iter() {
                    crate::types::#element_fn(el, field)?;
                }
            });
        }

        if checks.is_empty() {
            None
        } else {
            Some(checks)
        }
    }

    fn validator_fn_name(&self) -> Option<String> {
        if self.is_builtin() {
            return None;
        }

        let has_length = self
            .base
            .traits
            .length_constraint()
            .is_some_and(|lc| lc.max.is_some() || lc.min.is_some_and(|min| min > 0));

        if has_length || self.inner().borrow().validator_fn_name().is_some() {
            Some(crate::validator_fn_name_for(&self.simple_name()))
        } else {
            None
        }
    }

    fn validator_value_type(&self) -> String {
        // A slice parameter, not `&Vec<T>`: callers hold a `Vec` and it coerces, and clippy's
        // ptr_arg lint fires on the generated code otherwise.
        format!("[{}]", self.member.rust_typename())
    }
}

impl List {
    /// Returns the shape of the elements of this list.
    ///
    /// Panics if this `List` hasn't been resolved yet.
    pub fn inner(&self) -> Rc<RefCell<Shape>> {
        self.member.inner()
    }
}
