use {
    super::{Member, Typed, to_pascal_case},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        collections::HashMap,
        io::{Result as IoResult, Write},
    },
};

/// The union type represents a tagged union data structure that can take on several different,
/// but fixed, types. Unions function similarly to structures except that only one member can
/// be used at any one time. Each member in the union is a variant of the tagged union, where
/// member names are the tags of each variant, and the shapes targeted by members are the values
/// of each variant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Union {
    /// The name of this union in the Smithy model.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub smithy_typename: Option<String>,

    /// The Rust name of this union.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub rust_typename: Option<String>,

    /// Whether this union is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this union.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,

    /// The members of the union. Each member is a variant of the tagged union, where member names
    /// are the tags of each variant, and the shapes targeted by members are the values of each
    /// variant.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub members: HashMap<String, Member>,

    /// Traits to apply to the type.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}

impl Typed for Union {
    fn rust_typename(&self) -> String {
        self.rust_typename.clone().expect("Union type should be resolved before generating Rust code")
    }

    fn write(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();

        let docs = self.traits.get("smithy.api#documentation").and_then(|v| v.as_str());
        if let Some(docs) = docs {
            for line in docs.lines() {
                writeln!(output, "/// {}", line.trim())?;
            }
        } else {
            writeln!(output, "#[allow(missing_docs)]")?;
        }

        writeln!(output, "#[derive(Debug, ::serde::Deserialize, ::serde::Serialize)]")?;
        writeln!(output, "#[non_exhaustive]")?;
        writeln!(output, "pub enum {rust_typename} {{")?;

        for (member_name, member) in &self.members {
            let rust_member_name = to_pascal_case(member_name);
            let member_type = member.rust_typename();
            writeln!(output, "    #[serde(tag = \"{member_name}\")]")?;
            writeln!(output, "    {rust_member_name}({member_type}),")?;
        }

        writeln!(output, "}}")?;
        Ok(())
    }

    fn get_clap_parser(&self) -> String {
        let typename = self.rust_typename();
        format!("{typename}::parse")
    }

    fn mark_reachable_from_input(&mut self) {
        if self.reachable_from_input {
            return;
        }
        self.reachable_from_input = true;
        for member in self.members.values_mut() {
            member.mark_reachable_from_input();
        }
    }
}
