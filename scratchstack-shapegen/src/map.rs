use {
    crate::{Member, Modules, ShapeBase, ShapeInfo, SmithyModel},
    serde::{Deserialize, Serialize},
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

    fn generate(&self, _: &mut Modules) {}
}
