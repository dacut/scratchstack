use {
    crate::{Member, ShapeBase, ShapeInfo, StrExt, Writers},
    serde::{Deserialize, Serialize},
    serde_json::Value as JsonValue,
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

    fn resolve(&mut self, shape_name: &str, _model: &crate::SmithyModel) {
        self.base.resolve(shape_name);
    }

    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        if self.base.traits.is_error() {
            self.write_rust_decl(&mut w.types_error)?;
            self.write_display_impl(&mut w.types_error)?;
        } else {
            self.write_rust_decl(&mut w.types)?;
            self.write_display_impl(&mut w.types)?;
            self.write_from_str_impl(&mut w.types)?;
            self.write_shorthand_parser(&mut w.types)?;
            self.write_clap_value_enum(&mut w.types)?;
        }
        Ok(())
    }
}

impl Enum {
    /// Writes the Rust declaration for this enum.
    fn write_rust_decl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        self.base.traits.write_docs(w, "")?;

        // Attributes for the enum.
        writeln!(w, "#[derive(::serde::Deserialize, ::serde::Serialize)]")?;
        writeln!(
            w,
            "#[derive(::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug, ::std::hash::Hash, ::std::marker::Copy)]"
        )?;
        writeln!(w, "#[non_exhaustive]")?;
        writeln!(w, "pub enum {rust_typename} {{")?;

        let mut is_first = true;
        for (member_name, member) in self.members.iter() {
            if !is_first {
                writeln!(w)?;
            } else {
                is_first = false;
            }

            member.traits.write_docs(w, "    ")?;

            let rust_member_name = member_name.to_pascal_case();
            if &rust_member_name != member_name {
                writeln!(w, "    #[serde(rename = \"{member_name}\")]")?;
            }
            writeln!(w, "    {rust_member_name},")?;
        }

        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }

    /// Writes the Display implementation for this enum.
    fn write_display_impl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        writeln!(w, "impl ::std::fmt::Display for {rust_typename} {{")?;
        writeln!(w, "    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{")?;
        writeln!(w, "        match self {{")?;

        for (member_name, member) in self.members.iter() {
            let rust_member_name = member_name.to_pascal_case();
            if let Some(enum_value) = member.traits.enum_value()
                && let JsonValue::String(enum_value) = enum_value
            {
                writeln!(w, "            Self::{rust_member_name} => f.write_str(\"{enum_value}\"),")?;
            } else {
                writeln!(w, "            Self::{rust_member_name} => f.write_str(\"{member_name}\"),")?;
            }
        }

        writeln!(w, "        }}")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }

    /// Writes the FromStr implementation for this enum.
    fn write_from_str_impl(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        writeln!(w, "impl ::std::str::FromStr for {rust_typename} {{")?;
        writeln!(w, "    type Err = String;")?;
        writeln!(w, "    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {{")?;
        writeln!(w, "        match s {{")?;
        for (member_name, member) in self.members.iter() {
            let rust_member_name = member_name.to_pascal_case();
            if let Some(enum_value) = member.traits.enum_value()
                && let JsonValue::String(enum_value) = enum_value
            {
                writeln!(w, "            \"{enum_value}\" => Ok(Self::{rust_member_name}),")?;
            } else {
                writeln!(w, "            \"{member_name}\" => Ok(Self::{rust_member_name}),")?;
            }
        }
        writeln!(w, "            _ => Err(format!(\"Invalid value '{{s}}' for {rust_typename}\")),")?;
        writeln!(w, "        }}")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }

    /// Writes a TryFrom<ShorthandValue> implementation for this enum that allows it to be parsed
    /// from a string in shorthand form.
    fn write_shorthand_parser(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        writeln!(w, "impl ::std::convert::TryFrom<&::scratchstack_cli_utils::ShorthandValue> for {rust_typename} {{")?;
        writeln!(w, "    type Error = ::std::string::String;")?;
        writeln!(
            w,
            "    fn try_from(value: &::scratchstack_cli_utils::ShorthandValue) -> ::std::result::Result<Self, Self::Error> {{"
        )?;
        writeln!(w, "        let ::scratchstack_cli_utils::ShorthandValue::Scalar(value) = value else {{")?;
        writeln!(
            w,
            "            return ::std::result::Result::Err(format!(\"Expected a string for {rust_typename} but got '{{value:?}}\"));"
        )?;
        writeln!(w, "         }};")?;
        writeln!(w)?;
        writeln!(w, "        <Self as ::std::str::FromStr>::from_str(value.as_str())")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        writeln!(w)?;
        Ok(())
    }

    /// Writes a ValueEnum implementation for this enum that allows it to be used as a clap value enum when the "clap"
    /// feature is enabled.
    fn write_clap_value_enum(&self, w: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();

        writeln!(w, "#[cfg(feature = \"clap\")]")?;
        writeln!(w, "impl ::clap::ValueEnum for {rust_typename} {{")?;
        writeln!(w, "    fn value_variants<'a>() -> &'a [Self] {{")?;
        writeln!(w, "        &[")?;
        for member_name in self.members.keys() {
            let rust_member_name = member_name.to_pascal_case();
            writeln!(w, "            Self::{rust_member_name},")?;
        }
        writeln!(w, "        ]")?;
        writeln!(w, "    }}")?;
        writeln!(w)?;
        writeln!(w, "    fn to_possible_value(&self) -> ::std::option::Option<::clap::builder::PossibleValue> {{")?;
        writeln!(w, "        let s = match self {{")?;
        for (member_name, member) in self.members.iter() {
            let rust_member_name = member_name.to_pascal_case();
            if let Some(enum_value) = member.traits.enum_value()
                && let JsonValue::String(enum_value) = enum_value
            {
                writeln!(w, "            Self::{rust_member_name} => \"{enum_value}\",")?;
            } else {
                writeln!(w, "            Self::{rust_member_name} => \"{member_name}\",")?;
            }
        }
        writeln!(w, "        }};")?;
        writeln!(w)?;
        writeln!(w, "        ::std::option::Option::Some(::clap::builder::PossibleValue::new(s))")?;
        writeln!(w, "    }}")?;
        writeln!(w, "}}")?;
        Ok(())
    }
}
