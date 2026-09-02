use {
    crate::{StrExt as _, TraitMap},
    serde::{Deserialize, Serialize},
};

/// Basic features of a shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShapeBase {
    /// The Smithy name of the shape.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip)]
    pub smithy_name: Option<String>,

    /// The Rust type name of the shape.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip)]
    pub rust_typename: Option<String>,

    /// Traits associated with the shape.
    #[serde(default)]
    pub traits: TraitMap,
}

impl ShapeBase {
    /// Resolves the stored names of this shape.
    ///
    /// # Panics
    ///
    /// Panics if this shape has already been resolved, or if `smithy_name` is not an absolute shape
    /// id -- one of the form `namespace#Name`. Relative ids are not resolvable: shapegen has no
    /// notion of a current namespace to complete them against.
    pub fn resolve(&mut self, smithy_name: &str) {
        assert!(self.smithy_name.is_none(), "shape {smithy_name} has already been resolved");
        assert!(self.rust_typename.is_none(), "shape {smithy_name} has already been resolved");

        let hash_pos = smithy_name.find('#').unwrap_or_else(|| {
            panic!("shape id {smithy_name} is not absolute; it has no '#' separating the namespace")
        });
        let simple_typename = &smithy_name[hash_pos + 1..];
        let rust_typename = simple_typename.to_pascal_case();

        self.smithy_name = Some(smithy_name.to_string());
        self.rust_typename = Some(rust_typename);
    }

    /// Returns the Smithy name of this shape.
    ///
    /// # Panics
    ///
    /// Panics if the shape has not been resolved. Built-in `smithy.api#` shapes are skipped by
    /// [`SmithyModel::resolve`](crate::SmithyModel::resolve), so reaching this on one means
    /// something is generating code for a shape that has no declaration of its own.
    #[inline(always)]
    pub fn smithy_name(&self) -> String {
        self.smithy_name.clone().expect("shape has no Smithy name; it was not resolved")
    }

    /// Returns the Rust typename of this shape.
    ///
    /// # Panics
    ///
    /// Panics if the shape has not been resolved.
    #[inline(always)]
    pub fn rust_typename(&self) -> String {
        self.rust_typename.clone().unwrap_or_else(|| {
            panic!(
                "shape {} has no Rust type name; it was not resolved",
                self.smithy_name.as_deref().unwrap_or("(unnamed)")
            )
        })
    }
}
