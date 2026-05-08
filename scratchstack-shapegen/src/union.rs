use {
    super::{Member, ShapeBase, ShapeInfo, SmithyModel, StrExt as _, Writers},
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
}

impl ShapeInfo for Union {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        format!("crate::types::{}", self.base.rust_typename())
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);
        for member in self.members.values_mut() {
            member.resolve(shape_name, model);
        }
    }

    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        self.base.traits.write_docs(&mut w.types, "")?;

        writeln!(w.types, "#[derive(Debug, ::serde::Deserialize, ::serde::Serialize)]")?;
        writeln!(w.types, "#[non_exhaustive]")?;
        writeln!(w.types, "pub enum {rust_typename} {{")?;

        for (member_name, member) in &self.members {
            let rust_member_name = member_name.to_pascal_case();
            let member_type = member.rust_typename();
            writeln!(w.types, "    #[serde(tag = \"{member_name}\")]")?;
            writeln!(w.types, "    {rust_member_name}({member_type}),")?;
        }

        writeln!(w.types, "}}")?;
        Ok(())
    }
}
