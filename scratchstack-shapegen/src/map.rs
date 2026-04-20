use {
    super::{Member, Typed},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        collections::HashMap,
        io::{Result as IoResult, Write},
    },
};

/// The map type represents a map data structure that maps string keys to homogeneous values. A
/// map requires a member named key that MUST target a string shape and a member named value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Map {
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

    /// Traits to apply to the map.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}

impl Typed for Map {
    fn rust_typename(&self) -> String {
        let key_typename = self.key.rust_typename();
        let value_typename = self.value.rust_typename();
        format!("HashMap<{key_typename}, {value_typename}>")
    }

    fn write(&self, _output: &mut dyn Write) -> IoResult<()> {
        Ok(())
    }

    fn get_clap_parser(&self, option: bool) -> String {
        let key_parser = self.key.get_clap_parser(false);
        let value_parser = self.value.get_clap_parser(false);
        if option {
            format!("crate::clap_utils::parse_opt_map({key_parser}, {value_parser})")
        } else {
            format!("crate::clap_utils::parse_map({key_parser}, {value_parser})")
        }
    }

    fn mark_reachable_from_input(&mut self) {
        if self.reachable_from_input {
            return;
        }
        self.reachable_from_input = true;
        self.key.mark_reachable_from_input();
        self.value.mark_reachable_from_input();
    }
}
