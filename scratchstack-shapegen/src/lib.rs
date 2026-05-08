//! Rust code generation library for Smithy shape models.
use {
    derive_builder::Builder,
    std::io::{Result as IoResult, Write},
};

/// Primitive Smithy types.
pub mod primitive;

mod r#enum;
mod int_enum;
mod length_constraint;
mod list;
mod map;
mod member;
mod operation;
mod range_constraint;
mod resource;
mod service;
mod shape;
mod shape_base;
mod shape_ref;
mod smithy_model;
mod str_ext;
mod structure;
mod trait_id;
mod trait_map;
mod r#union;

#[allow(unused_imports)]
pub use {
    r#enum::*, int_enum::*, length_constraint::*, list::*, map::*, member::*, operation::*, range_constraint::*,
    resource::*, service::*, shape::*, shape_base::*, shape_ref::*, smithy_model::*, str_ext::*, structure::*,
    trait_id::*, trait_map::*, r#union::*,
};

/// Writers that will write generated code into the appropriate module.
#[derive(Builder, Debug)]
#[builder(pattern = "owned")]
pub struct Writers<W: Write> {
    pub error_meta: W,
    pub operation: W,
    pub types: W,
    pub types_error: W,
}

impl<W: Write> Writers<W> {
    pub fn builder() -> WritersBuilder<W> {
        WritersBuilder::default()
    }
}

/// Trait for all named shapes.
pub trait ShapeInfo {
    /// Resolve this shape, setting the Smithy name internally.
    fn resolve(&mut self, smithy_name: &str, model: &SmithyModel);

    /// Returns the Smithy name of this shape.
    fn smithy_name(&self) -> String;

    /// Indicates whether this shape is a built-in Smithy type.
    fn is_builtin(&self) -> bool {
        self.smithy_name().starts_with("smithy.api#")
    }

    /// Indicates whether this shape is a primitive type.
    fn is_primitive(&self) -> bool {
        false
    }

    /// Returns the simple name of this shape.
    ///
    /// This is the portion of the Smithy name after the '#' character.
    fn simple_name(&self) -> String {
        let rpos = self.smithy_name().rfind('#');
        if let Some(pos) = rpos {
            self.smithy_name()[pos + 1..].to_string()
        } else {
            self.smithy_name()
        }
    }

    /// Returns the Rust type name of this shape.
    fn rust_typename(&self) -> String;

    /// If this shape has custom code to validate its value from a builder type, returns it.
    /// Otherwise returns `None`.
    ///
    /// # Parameters
    /// * `var` — the variable holding the value to be validated.
    /// * `field_name` — the name of the field being evaluated (for use in error messages).
    #[allow(unused)]
    fn derive_builder_validator(&self, var: &str, field_name: &str) -> Option<String> {
        None
    }

    /// Generate Rust code for this shape, writing it to the appropriate module in `w`.
    #[allow(unused_variables)] // Makes code completion show `w` instead of `_w`.
    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        Ok(())
    }
}

/// Macro that forwards the implementation of the `ShapeInfo` trait to a contained `ShapeBase` field.
#[macro_export]
macro_rules! forward_shape_info {
    ($ty:ty, $field:ident) => {
        fn resolve(&mut self, smithy_name: &str, _: &$crate::SmithyModel) {
            self.$field.resolve(smithy_name)
        }

        #[inline(always)]
        fn smithy_name(&self) -> String {
            self.$field.smithy_name()
        }

        #[inline(always)]
        fn rust_typename(&self) -> String {
            self.$field.rust_typename()
        }
    };
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::io::{Result as IoResult, Write},
    };

    const IAM_MODEL: &str = include_str!("iam-2010-05-08.json");
    struct NullWriter;
    impl Write for NullWriter {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    #[test]
    fn test_deserialize_service_model() {
        let m: SmithyModel = serde_json::from_str(IAM_MODEL).expect("Failed to deserialize IAM service model");
        m.resolve();
        let mut w = Writers::builder()
            .error_meta(NullWriter)
            .operation(NullWriter)
            .types(NullWriter)
            .types_error(NullWriter)
            .build()
            .unwrap();
        m.generate(&mut w).expect("Failed to generate Rust code for IAM service model");
    }
}
