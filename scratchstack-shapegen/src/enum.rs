use {
    super::{Member, Typed, to_pascal_case},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        collections::HashMap,
        io::{Result as IoResult, Write},
    },
};

/// The _enum_ shape is used to represent a fixed set of one or more string values. Each value
/// listed in the enum is a member that implicitly targets the unit type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enum {
    /// The name of this enum in the Smithy model.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub smithy_typename: Option<String>,

    /// The Rust name of this enum.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub rust_typename: Option<String>,

    /// Whether this enum is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this enum.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,

    /// The members of the enum. Each member implicitly targets the unit type.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub members: HashMap<String, Member>,

    /// Traits to apply to the type.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}

impl Enum {
    /// Writes the Rust declaration for this enum.
    fn write_rust_decl(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();

        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }

        writeln!(output, "#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]")?;

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

            let docs = member.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
            if let Some(docs) = docs {
                for line in docs.lines() {
                    writeln!(output, "    /// {}", line.trim())?;
                }
            } else {
                writeln!(output, "    #[allow(missing_docs)]")?;
            }

            let rust_member_name = to_pascal_case(member_name);
            if &rust_member_name != member_name {
                writeln!(output, "    #[serde(rename = \"{member_name}\")]")?;
            }
            writeln!(output, "    {rust_member_name},")?;
        }

        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    fn write_shorthand_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let smithy_typename =
            self.smithy_typename.as_ref().expect("Enum shape should have a Smithy typename after resolution");
        let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
        let simple_typename = &smithy_typename[hash_pos + 1..];
        let rust_typename = self.rust_typename();

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl TryFrom<&crate::shorthand::Value> for {rust_typename} {{")?;
        writeln!(output, "    type Error = String;")?;
        writeln!(output, "    fn try_from(value: &crate::shorthand::Value) -> Result<Self, Self::Error> {{")?;
        writeln!(output, "        if let crate::shorthand::Value::Scalar(s) = value {{")?;
        writeln!(output, "            match s.as_str() {{")?;
        for (member_name, _) in self.members.iter() {
            let rust_member_name = to_pascal_case(member_name);
            writeln!(output, "                \"{member_name}\" => Ok(Self::{rust_member_name}),")?;
        }
        writeln!(output, "                _ => Err(format!(\"Invalid value '{{s}}' for enum {simple_typename}\")),")?;
        writeln!(output, "            }}")?;
        writeln!(output, "        }} else {{")?;
        writeln!(
            output,
            "            Err(format!(\"Expected a string value to parse {simple_typename}, but got '{{value:?}}'\"))"
        )?;
        writeln!(output, "        }}")?;
        writeln!(output, "    }}")?;
        writeln!(output, "}}")?;
        writeln!(output)?;
        Ok(())
    }

    fn write_clap_parser(&self, output: &mut dyn Write) -> IoResult<()> {
        let smithy_typename =
            self.smithy_typename.as_ref().expect("Enum shape should have a Smithy typename after resolution");
        let hash_pos = smithy_typename.rfind("#").expect("Smithy typename should contain a '#' character");
        let simple_typename = &smithy_typename[hash_pos + 1..];
        let rust_typename = self.rust_typename();

        writeln!(output, "#[cfg(feature = \"clap\")]")?;
        writeln!(output, "impl ::std::str::FromStr for {rust_typename} {{")?;
        writeln!(output, "    type Err = String;")?;
        writeln!(output, "    fn from_str(s: &str) -> Result<Self, Self::Err> {{")?;
        writeln!(output, "        match s {{")?;
        for (member_name, _) in self.members.iter() {
            let rust_member_name = to_pascal_case(member_name);
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

impl Typed for Enum {
    fn rust_typename(&self) -> String {
        self.rust_typename.clone().expect("Enum type should be resolved before generating Rust code")
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        self.write_rust_decl(output)?;
        self.write_shorthand_parser(output)?;
        self.write_clap_parser(output)?;
        Ok(())
    }

    fn get_clap_parser(&self) -> String {
        let rust_typename = self.rust_typename();
        format!("{rust_typename}::from_str")
    }

    fn mark_reachable_from_input(&mut self) {
        self.reachable_from_input = true;
    }
}
