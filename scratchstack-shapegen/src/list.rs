use {
    crate::{Member, Shape, ShapeBase, ShapeInfo, SmithyModel},
    indoc::formatdoc,
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

    /// Whether this struct is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this struct.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,
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
        if self.is_builtin() {
            format!("::std::vec::Vec<{}>", self.member.rust_typename())
        } else {
            self.base.rust_typename().to_string()
        }
    }

    fn clap_parser(&self) -> Option<String> {
        let member_typename = self.member.rust_typename();
        Some(format!("crate::clap_utils::parse_list::<{member_typename}>"))
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

        let el_validator = self.inner().borrow().derive_builder_validator("el", field_name);
        if let Some(el_validator) = el_validator {
            output += &formatdoc! {"
                for el in {var}.iter() {{
                    {el_validator}
                }}
            "};
        }

        if output.is_empty() {
            None
        } else {
            Some(output)
        }
    }

    fn mark_reachable_from_input(&mut self) {
        if self.reachable_from_input {
            return;
        }
        self.reachable_from_input = true;
        self.member.mark_reachable_from_input();
    }

    fn generate(&self, output: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.is_builtin() {
            return Ok(());
        }

        self.base.traits.write_docs(output, "")?;
        writeln!(output, "pub type {} = ::std::vec::Vec<{}>;", self.base.rust_typename(), self.member.rust_typename())?;
        writeln!(output)?;
        Ok(())
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
