use {
    super::{ShapeBase, ShapeInfo, ShapeRef, forward_shape_info},
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
};

/// Smithy defines a resource as an entity with an identity that has a set of operations. A
/// resource shape is defined in the IDL using a resource_statement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    /// Basic shape information for this resource.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// Defines identifier names and shape IDs used to identify the resource.
    #[serde(default)]
    pub identifiers: HashMap<String, ShapeRef>,

    /// Defines a map of property string names to shape IDs that enumerate the properties of the
    /// resource.
    #[serde(default)]
    pub properties: HashMap<String, ShapeRef>,

    /// Defines the lifecycle operation used to create a resource using one or more identifiers
    /// created by the service.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub create: Option<ShapeRef>,

    /// Defines an idempotent lifecycle operation used to create a resource using identifiers
    /// provided by the client.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub put: Option<ShapeRef>,

    /// Defines the lifecycle operation used to retrieve the resource.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub read: Option<ShapeRef>,

    /// Defines the lifecycle operation used to update the resource.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub update: Option<ShapeRef>,

    /// Defines the lifecycle operation used to delete the resource.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub delete: Option<ShapeRef>,

    /// Defines the lifecycle operation used to list resources of this type.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub list: Option<ShapeRef>,

    /// Binds a list of non-lifecycle instance operations to the resource. Each reference MUST
    /// target an operation.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub operations: Vec<ShapeRef>,

    /// Binds a list of non-lifecycle collection operations to the resource. Each reference MUST
    /// target an operation.
    #[serde(rename = "collectionOperations", skip_serializing_if = "Vec::is_empty", default)]
    pub collection_operations: Vec<ShapeRef>,

    /// Binds a list of resources to this resource as a child resource, forming a containment
    /// relationship. The resources MUST NOT have a cyclical containment hierarchy, and a resource
    /// can not be bound more than once in the entire closure of a resource or service. Each
    /// reference MUST target a resource.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub resources: Vec<ShapeRef>,
}

impl ShapeInfo for Resource {
    forward_shape_info!(Resource, base);

    fn clap_parser(&self) -> Option<String> {
        unimplemented!("clap_parser cannot be called on Resource types")
    }

    fn derive_builder_validator(&self, _: &str, _: &str) -> Option<String> {
        unimplemented!("derive_builder_validator cannot be called on Resource types")
    }
}
