use {
    super::{Member, Typed},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        collections::HashMap,
        io::{Result as IoResult, Write},
    },
};

/// The list type represents an ordered homogeneous collection of values. A list shape requires
/// a single member named member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct List {
    /// The name of this list in the Smithy model.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub smithy_typename: Option<String>,

    /// The Rust name of this list.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub rust_typename: Option<String>,

    /// Whether this struct is reachable from an API input shape. This is used to determine
    /// whether to generate Clap parsers for this struct.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip, default)]
    pub reachable_from_input: bool,

    /// The member of the list.
    pub member: Member,

    /// Traits to apply to the type.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}

impl Typed for List {
    fn rust_typename(&self) -> String {
        let member_typename = self.member.rust_typename();
        format!("Vec<{member_typename}>")
    }

    fn write(&self, _output: &mut dyn Write) -> IoResult<()> {
        Ok(())
    }

    fn get_clap_parser(&self, option: bool) -> String {
        let member_typename = self.member.rust_typename();
        if option {
            format!("crate::clap_utils::parse_opt_list::<{member_typename}>")
        } else {
            format!("crate::clap_utils::parse_list::<{member_typename}>")
        }
    }

    fn mark_reachable_from_input(&mut self) {
        if self.reachable_from_input {
            return;
        }
        self.reachable_from_input = true;
        self.member.mark_reachable_from_input();
    }
}
