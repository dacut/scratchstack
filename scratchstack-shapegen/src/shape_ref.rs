use serde::{Deserialize, Serialize};

/// An AST shape reference is an object with a single property, target that maps to an absolute
/// shape ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShapeRef {
    /// The target shape ID of the reference.
    pub target: String,
}
