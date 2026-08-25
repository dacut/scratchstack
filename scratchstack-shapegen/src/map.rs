use {
    crate::{Member, ShapeBase, ShapeInfo, SmithyModel, Writers},
    serde::{Deserialize, Serialize},
    std::io::{Result as IoResult, Write},
};

/// The map type represents a map data structure that maps string keys to homogeneous values. A
/// map requires a member named key that MUST target a string shape and a member named value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Map {
    /// Basic shape information for the `map` type.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// The key member of the map. This member MUST target a string shape.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    pub key: Member,

    /// The value member of the map.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    pub value: Member,
}

impl ShapeInfo for Map {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        format!("::std::collections::BTreeMap<{}, {}>", self.key.rust_typename(), self.value.rust_typename())
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);
        self.key.resolve(shape_name, model);
        self.value.resolve(shape_name, model);
    }

    fn generate<W: Write>(&self, _: &mut Writers<W>) -> IoResult<()> {
        Ok(())
    }
}

impl Map {
    /// Generates code that belogs in `crate::types` for this map.
    pub fn generate_types(&self, w: &mut dyn Write) -> IoResult<()> {
        if !self.is_builtin() {
            // Declaration
            let rust_typename = self.rust_typename();
            self.base.traits.write_docs(w, "")?;
            writeln!(
                w,
                "pub type {rust_typename} = ::std::collections::BTreeMap<{}, {}>;",
                self.key.rust_typename(),
                self.value.rust_typename()
            )?;
        }
        Ok(())
    }
}
