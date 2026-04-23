//! Rust code generation library for Smithy shape models.
use std::io::{Result as IoResult, Write};

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

    /// If this shape has a function or method to parse a Clap argument, returns it. Otherwise
    /// returns `None`.
    fn clap_parser(&self) -> Option<String>;

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

    /// Mark this shape as being reachable from an input structure.
    fn mark_reachable_from_input(&mut self) {}

    /// Generate all code needed for this shape.
    #[allow(unused)]
    fn generate(&self, w: &mut dyn Write) -> IoResult<()> {
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
    use {super::*, std::io::stdout};

    const IAM_MODEL: &str = include_str!("iam-2010-05-08.json");

    #[test]
    fn test_deserialize_service_model() {
        let m: SmithyModel = serde_json::from_str(IAM_MODEL).expect("Failed to deserialize IAM service model");
        m.resolve();
        m.generate(&mut stdout()).expect("Failed to generate Rust code for IAM service model");
    }
}
