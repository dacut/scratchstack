use {
    super::ShapeRef,
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::collections::HashMap,
};

/// The operation type represents the input, output, and possible errors of an API operation.
/// Operation shapes are bound to resource shapes and service shapes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    /// Defines the optional input structure of the operation. The `input` of an operation MUST
    /// resolve to a [`Structure`][crate::Shape::Structure].
    pub input: ShapeRef,

    /// Defines the optional output structure of the operation. The `output` of an operation MUST
    /// resolve to a [`Structure`][crate::Shape::Structure].
    pub output: ShapeRef,

    /// Defines the list of errors that MAY be encountered when invoking the operation. Each
    /// reference MUST resolve to a [`Structure`][crate::Shape::Structure] shape that is marked with the
    /// error trait.
    #[serde(default)]
    pub errors: Vec<ShapeRef>,

    /// Traits to apply to the operation.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,
}
