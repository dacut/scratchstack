use {
    crate::{Member, Shape, ShapeBase, ShapeInfo, SmithyModel},
    indoc::formatdoc,
    serde::{Deserialize, Serialize},
    std::{
        cell::RefCell,
        io::{Result as IoResult, Write},
        rc::Rc,
    },
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

    fn derive_builder_validator(&self, var: &str, field_name: &str) -> Option<String> {
        if self.is_builtin() {
            return None;
        }

        let mut output = String::with_capacity(1024);
        let simple_name = self.simple_name();
        if let Some(lc) = self.base.traits.length_constraint() {
            if let Some(min) = lc.min
                && min > 0
            {
                let cond = if min == 1 {
                    format!("{var}.is_empty()")
                } else {
                    format!("{var}.len() < {min}")
                };

                output += &formatdoc! {"
                    if {cond} {{
                        return ::std::result::Result::Err(
                            format!(
                                \"{field_name} must have at least {min} elements for {simple_name}: {{}} elements found\",
                                {var}.len()
                            )
                        );
                    }}
                "};
            }

            if let Some(max) = lc.max {
                output += &formatdoc! {"
                    if {var}.len() > {max} {{
                        return ::std::result::Result::Err(
                            format!(
                                \"{field_name} must have at most {max} elements for {simple_name}: {{}} elements found\",
                                {var}.len()
                            )
                        );
                    }}
                "};
            }
        }

        // The element shape validates itself; call its function rather than inlining its checks
        // once per list that happens to contain it.
        if let Some(el_fn) = self.inner().borrow().validator_fn_name() {
            output += &formatdoc! {"
                for el in {var}.iter() {{
                    crate::types::{el_fn}(el, {field_name_expr})?;
                }}
            ", field_name_expr = field_name_expr(field_name)};
        }

        if output.is_empty() {
            None
        } else {
            Some(output)
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

    fn write_validator_fn(&self, w: &mut dyn Write) -> IoResult<()> {
        let Some(fn_name) = self.validator_fn_name() else {
            return Ok(());
        };
        let Some(body) = self.derive_builder_validator("value", "{field}") else {
            return Ok(());
        };

        // A slice parameter, not `&Vec<T>`: callers hold a `Vec` and it coerces, and clippy's
        // ptr_arg lint fires on the generated code otherwise.
        let value_type = format!("[{}]", self.member.rust_typename());
        crate::write_validator_fn(w, &fn_name, &value_type, &self.simple_name(), &body)
    }
}

/// Renders `field_name` as a Rust expression of type `&str`.
///
/// A validator function passes its own `field` parameter straight through to the element check; any
/// other caller is naming a literal field.
fn field_name_expr(field_name: &str) -> String {
    if field_name == "{field}" {
        "field".to_string()
    } else {
        format!("\"{field_name}\"")
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
