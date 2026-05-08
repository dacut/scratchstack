use {
    crate::{Member, ShapeBase, ShapeInfo, StrExt, Writers},
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
        io::{Result as IoResult, Write},
    },
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

    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        let module = if self.base.traits.is_error() {
            &mut w.types_error
        } else {
            &mut w.types
        };
        self.generate_types(module)
    }
}

impl IntEnum {
    /// Generates code that belogs in `crate::types` for this enum.
    pub fn generate_types(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_type = self.rust_typename();

        self.base.traits.write_docs(w, "")?;

        writeln!(w, "#[derive(::serde::Deserialize, ::serde::Serialize,)]")?;
        writeln!(
            w,
            "#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug, ::std::hash::Hash, ::std::marker::Copy)]"
        )?;
        writeln!(w, "#[non_exhaustive]")?;
        writeln!(w, "pub enum {rust_type} {{")?;

        for (member_name, member) in self.members.iter() {
            member.traits.write_docs(w, "    ")?;
            let rust_member_name = member_name.to_pascal_case();
            let value = member.traits.enum_value_as_i64().expect("enumValue trait must be an integer");

            if &rust_member_name != member_name {
                writeln!(w, "    #[serde(rename = \"{member_name}\")]")?;
            }
            writeln!(w, "    {rust_member_name} = {value},")?;
        }

        writeln!(w, "}}")?;

        Ok(())
    }
}
