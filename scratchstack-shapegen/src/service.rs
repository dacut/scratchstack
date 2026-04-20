use {
    super::ShapeRef,
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::collections::HashMap,
};

/// A service is the entry point of an API that aggregates resources and operations together.
/// The resources and operations of an API are bound within the closure of a service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    /// Defines the version of the service. The version can be provided in any format (e.g.,
    /// `2017-02-11`, `2.0`, etc).
    #[serde(default)]
    pub version: String,

    /// Binds a list of operations to the service. Each reference MUST target an operation.
    #[serde(default)]
    pub operations: Vec<ShapeRef>,

    /// Binds a list of resources to the service. Each reference MUST target a resource.
    #[serde(default)]
    pub resources: Vec<ShapeRef>,

    /// Defines a list of common errors that every operation bound within the closure of the
    /// service can return. Each provided shape ID MUST target a structure shape that is marked
    /// with the error trait.
    #[serde(default)]
    pub errors: Vec<ShapeRef>,

    /// Traits to apply to the service
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub traits: HashMap<String, Value>,

    /// Disambiguates shape name conflicts in the service closure.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub rename: HashMap<String, String>,
}
