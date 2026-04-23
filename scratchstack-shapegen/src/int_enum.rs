use {
    crate::{Member, ShapeBase, ShapeInfo, StrExt, forward_shape_info},
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
    forward_shape_info!(IntEnum, base);

    fn clap_parser(&self) -> Option<String> {
        let typename = self.rust_typename();
        Some(format!("{typename}::parse"))
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_type = self.rust_typename();

        self.base.traits.write_docs(output, "")?;

        writeln!(output, "#[derive(::serde::Deserialize, ::serde::Serialize,)]")?;
        writeln!(
            output,
            "#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug, ::std::hash::Hash, ::std::marker::Copy)]"
        )?;
        writeln!(output, "#[cfg_attr(feature = \"clap\", derive(::clap::ValueEnum))]")?;
        writeln!(output, "#[non_exhaustive]")?;
        writeln!(output, "pub enum {rust_type} {{")?;

        for (member_name, member) in self.members.iter() {
            member.traits.write_docs(output, "    ")?;
            let rust_member_name = member_name.to_pascal_case();
            let value = member.traits.enum_value_as_i64().expect("enumValue trait must be an integer");

            if &rust_member_name != member_name {
                writeln!(output, "    #[serde(rename = \"{member_name}\")]")?;
            }
            writeln!(output, "    {rust_member_name} = {value},")?;
        }

        writeln!(output, "}}")?;

        Ok(())
    }
}
