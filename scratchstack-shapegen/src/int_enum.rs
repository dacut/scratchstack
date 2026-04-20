use {
    super::{Member, Typed},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        collections::HashMap,
        io::{Result as IoResult, Write},
    },
};

/// An `intEnum` is used to represent an enumerated set of one or more integer values. The members
/// of intEnum MUST be marked with the enumValue trait set to a unique integer value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntEnum {
    /// The name of this enum in the Smithy model.
    #[serde(skip, default)]
    pub smithy_typename: Option<String>,

    /// The Rust name of this enum.
    #[serde(skip, default)]
    pub rust_typename: Option<String>,

    /// The members of the intEnum. Each member MUST be marked with the enumValue trait set to a
    /// unique integer value.
    pub members: HashMap<String, Member>,

    /// Traits to apply to the type.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}

impl Typed for IntEnum {
    fn rust_typename(&self) -> String {
        self.rust_typename.clone().expect("IntEnum type should be resolved before generating Rust code")
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_type = self.rust_typename();

        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }

        writeln!(
            output,
            "#[derive(::serde::Deserialize, ::serde::Serialize, ::std::clone::Clone, ::std::cmp::Eq, ::std::cmp::PartialEq, ::std::fmt::Debug, ::std::hash::Hash, ::std::marker::Copy)]"
        )?;
        writeln!(output, "#[cfg_attr(feature = \"clap\", derive(::clap::ValueEnum))]")?;
        writeln!(output, "#[non_exhaustive]")?;
        writeln!(output, "pub enum {rust_type} {{")?;

        for (member_name, member) in self.members.iter() {
            let docs = member.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
            if let Some(docs) = docs {
                for line in docs.lines() {
                    writeln!(output, "    /// {}", line.trim())?;
                }
            } else {
                writeln!(output, "    #[allow(missing_docs)]")?;
            }

            let evalue =
                member.traits.get("smithy.api#enumValue").expect("intEnum members must have an enumValue trait");
            let value = evalue.as_i64().expect("enumValue trait must be an integer");
            writeln!(output, "    #[serde(rename = \"{member_name}\")]")?;
            writeln!(output, "    {member_name} = {value},")?;
        }

        writeln!(output, "}}")?;

        Ok(())
    }

    fn get_clap_parser(&self, option: bool) -> String {
        let typename = self.rust_typename();
        if option {
            format!("{typename}::parse_opt")
        } else {
            format!("{typename}::parse")
        }
    }

    fn mark_reachable_from_input(&mut self) {}
}
