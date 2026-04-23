use {
    crate::{Member, ShapeBase, ShapeInfo, SmithyModel},
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

    /// Whether this map is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this map.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,
}

impl ShapeInfo for Map {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        self.base.rust_typename()
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);
        self.key.resolve(shape_name, model);
        self.value.resolve(shape_name, model);
    }

    fn clap_parser(&self) -> Option<String> {
        let key_parser = self.key.clap_parser().unwrap();
        let value_parser = self.value.clap_parser().unwrap();
        Some(format!("crate::clap_utils::parse_map({key_parser}, {value_parser})"))
    }

    fn mark_reachable_from_input(&mut self) {
        if self.reachable_from_input {
            return;
        }
        self.reachable_from_input = true;
        self.key.mark_reachable_from_input();
        self.value.mark_reachable_from_input();
    }

    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        if !self.is_builtin() {
            // Declaration
            let rust_typename = self.rust_typename();
            self.base.traits.write_docs(output, "")?;
            writeln!(
                output,
                "pub type {rust_typename} = ::std::collections::HashMap<{}, {}>;",
                self.key.rust_typename(),
                self.value.rust_typename()
            )?;
        }
        Ok(())
    }
}
