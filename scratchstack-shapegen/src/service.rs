use {
    super::{ShapeBase, ShapeInfo, ShapeRef, forward_shape_info},
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
};

/// A service is the entry point of an API that aggregates resources and operations together.
/// The resources and operations of an API are bound within the closure of a service.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    /// Basic shape information for this service.
    #[serde(flatten)]
    pub base: ShapeBase,

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

    /// Disambiguates shape name conflicts in the service closure.
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub rename: HashMap<String, String>,
}

impl ShapeInfo for Service {
    forward_shape_info!(Service, base);

    fn clap_parser(&self) -> Option<String> {
        unimplemented!("clap_parser cannot be called on Service types")
    }

    fn derive_builder_validator(&self, _: &str, _: &str) -> Option<String> {
        unimplemented!("derive_builder_validator cannot be called on Service types")
    }
}
