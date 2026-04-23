use {
    super::{Member, ShapeBase, ShapeInfo, StrExt as _, forward_shape_info},
    serde::{Deserialize, Serialize},
    std::{
        collections::BTreeMap,
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
    /// Basic shape information for the `union` type.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// The members of the union. Each member is a variant of the tagged union, where member names
    /// are the tags of each variant, and the shapes targeted by members are the values of each
    /// variant.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub members: BTreeMap<String, Member>,

    /// Whether this union is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this union.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,
}

impl ShapeInfo for Union {
    forward_shape_info!(Union, base);

    fn clap_parser(&self) -> Option<String> {
        let typename = self.rust_typename();
        Some(format!("{typename}::parse"))
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

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        self.base.traits.write_docs(output, "")?;

        writeln!(output, "#[derive(Debug, ::serde::Deserialize, ::serde::Serialize)]")?;
        writeln!(output, "#[non_exhaustive]")?;
        writeln!(output, "pub enum {rust_typename} {{")?;

        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_pascal_case();
            let member_type = member.rust_typename();
            writeln!(output, "    #[serde(tag = \"{member_name}\")]")?;
            writeln!(output, "    {rust_member_name}({member_type}),")?;
        }

        writeln!(output, "}}")?;
        Ok(())
    }
}
