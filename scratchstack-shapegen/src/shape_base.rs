use {
    crate::{StrExt as _, TraitMap},
    serde::{Deserialize, Serialize},
    std::io::{Result as IoResult, Write},
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
    /// Resolves the stored names of this shape, panicking if they are already set.
    pub fn resolve(&mut self, smithy_name: &str) {
        assert!(self.smithy_name.is_none());
        assert!(self.rust_typename.is_none());

        let hash_pos = smithy_name.find('#').unwrap();
        let simple_typename = &smithy_name[hash_pos + 1..];
        let rust_typename = simple_typename.to_pascal_case();

        self.smithy_name = Some(smithy_name.to_string());
        self.rust_typename = Some(rust_typename);
    }

    /// Returns the Smithy name of this shape, panicking if it is not set.
    #[inline(always)]
    pub fn smithy_name(&self) -> String {
        self.smithy_name.clone().expect("ShapeBase should have a Smithy name after resolution")
    }

    /// Returns the Rust typename of this shape, panicking if it is not set.
    #[inline(always)]
    pub fn rust_typename(&self) -> String {
        self.rust_typename.clone().expect("ShapeBase should have a Rust typename after resolution")
    }

    /// Writes documentation for this shape to the provided writer.
    #[inline(always)]
    pub fn write_docs(&self, writer: &mut impl Write, indent: &str) -> IoResult<()> {
        self.traits.write_docs(writer, indent)
    }
}
