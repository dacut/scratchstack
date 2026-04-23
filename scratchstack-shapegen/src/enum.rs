use {
    crate::{Member, ShapeBase, ShapeInfo, StrExt, forward_shape_info},
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
        io::{Result as IoResult, Write},
    },
};

/// The _enum_ shape is used to represent a fixed set of one or more string values. Each value
/// listed in the enum is a member that implicitly targets the unit type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enum {
    /// Basic shape information for the enum.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// The members of the enum. Each member implicitly targets the unit type.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub members: BTreeMap<String, Member>,

    /// Whether this enum is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this enum.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,
}

impl ShapeInfo for Enum {
    forward_shape_info!(Enum, base);

    fn clap_parser(&self) -> Option<String> {
        let rust_typename = self.rust_typename();
        Some(format!("{rust_typename}::from_str"))
    }

    fn mark_reachable_from_input(&mut self) {
        self.reachable_from_input = true;
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)?;
        self.write_shorthand_parser(output)?;
        self.write_clap_parser(output)?;
        Ok(())
    }
}

impl Enum {
    /// Writes the Rust declaration for this enum.
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();

        self.base.traits.write_docs(output, "")?;

        // Attributes for the enum.
        writeln!(output, "#[derive(::serde::Deserialize, ::serde::Serialize)]")?;
        writeln!(
            output,
            "#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug, ::std::hash::Hash, ::std::marker::Copy)]"
        )?;
        if self.reachable_from_input {
            writeln!(output, "#[cfg_attr(feature = \"clap\", derive(::clap::ValueEnum))]")?;
        }
        writeln!(output, "#[non_exhaustive]")?;
        writeln!(output, "pub enum {rust_typename} {{")?;

        let mut is_first = true;
        for (member_name, member) in self.members.iter() {
            if !is_first {
                writeln!(output)?;
            } else {
                is_first = false;
            }

            member.traits.write_docs(output, "    ")?;

            let rust_member_name = member_name.to_pascal_case();
            if &rust_member_name != member_name {
                writeln!(output, "    #[serde(rename = \"{member_name}\")]")?;
            }
            writeln!(output, "    {rust_member_name},")?;
        }

        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    /// Write a rust implemenation of `TryFrom<&ShorthandValue>` for this structure.
    ///
    /// This allows the structure to be created from a `ShorthandValue`, used to parse parameters
    /// provided on the CLI in a shorthand format, e.g. `--tag Key=key,Value=value` instead of the
    /// more verbose JSON syntax `--tag [{"Key":"key","Value":"value"}]`.
    fn write_shorthand_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let simple_name = self.simple_name();
        let rust_typename = self.rust_typename();

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl TryFrom<&::scratchstack_cli_utils::ShorthandValue> for {rust_typename} {{")?;
        writeln!(output, "    type Error = String;")?;
        writeln!(
            output,
            "    fn try_from(value: &::scratchstack_cli_utils::ShorthandValue) -> Result<Self, Self::Error> {{"
        )?;
        writeln!(output, "        if let ::scratchstack_cli_utils::ShorthandValue::Scalar(s) = value {{")?;
        writeln!(output, "            match s.as_str() {{")?;
        for (member_name, _) in self.members.iter() {
            let rust_member_name = member_name.to_pascal_case();
            writeln!(output, "                \"{member_name}\" => Ok(Self::{rust_member_name}),")?;
        }
        writeln!(output, "                _ => Err(format!(\"Invalid value '{{s}}' for enum {simple_name}\")),")?;
        writeln!(output, "            }}")?;
        writeln!(output, "        }} else {{")?;
        writeln!(
            output,
            "            Err(format!(\"Expected a string value to parse {simple_name}, but got '{{value:?}}'\"))"
        )?;
        writeln!(output, "        }}")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let simple_typename = self.simple_name();
        let rust_typename = self.rust_typename();

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl ::std::str::FromStr for {rust_typename} {{")?;
        writeln!(output, "    type Err = String;")?;
        writeln!(output, "    fn from_str(s: &str) -> Result<Self, Self::Err> {{")?;
        writeln!(output, "        match s {{")?;
        for (member_name, _) in self.members.iter() {
            let rust_member_name = member_name.to_pascal_case();
            writeln!(output, "            \"{member_name}\" => Ok(Self::{rust_member_name}),")?;
        }
        writeln!(output, "            _ => Err(format!(\"Invalid value '{{s}}' for enum {simple_typename}\")),")?;
        writeln!(output, "        }}")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }
}
