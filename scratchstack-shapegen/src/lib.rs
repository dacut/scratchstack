use std::io::{Result as IoResult, Write};

pub mod primitive;

mod r#enum;
mod int_enum;
mod list;
mod map;
mod member;
mod operation;
mod resource;
mod service;
mod shape;
mod shape_ref;
mod smithy_model;
mod structure;
mod r#union;

#[allow(unused_imports)]
pub use {
    r#enum::*, int_enum::*, list::*, map::*, member::*, operation::*, resource::*, service::*, shape::*, shape_ref::*,
    smithy_model::*, structure::*, r#union::*,
};

/// Rust keywords that cannot be used as identifiers. These are used to determine when to use raw
/// identifiers in the generated code.
const RUST_IDENTS: &[&str] = &[
    "abstract", "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while",
];

/// Convert an identifier to snake case. This is used to convert Smithy member names to Rust field names.
pub fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    let mut prev_char_was_uppercase = false;

    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 && !prev_char_was_uppercase {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
            prev_char_was_uppercase = true;
        } else {
            result.push(c);
            prev_char_was_uppercase = false;
        }
    }

    if RUST_IDENTS.contains(&result.as_str()) {
        result = format!("r#{result}");
    }

    result
}

/// Indicates whether this identifier is a SCREAMING_SNAKE_CASE constant.
pub fn is_screaming_snake_case(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_uppercase() || c == '_')
}

/// Convert an identifier to Pascal case. This is used to convert Smithy shape names to Rust type names.
pub fn to_pascal_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;

    if is_screaming_snake_case(s) {
        // Change SCREAMING_SNAKE_CASE to ScreamingSnakeCase.
        for c in s.chars() {
            if c == '_' {
                capitalize_next = true;
            } else if capitalize_next {
                result.push(c.to_ascii_uppercase());
                capitalize_next = false;
            } else {
                result.push(c.to_ascii_lowercase());
            }
        }
    } else {
        for c in s.chars() {
            if c == '_' {
                capitalize_next = true;
            } else if capitalize_next {
                result.push(c.to_ascii_uppercase());
                capitalize_next = false;
            } else {
                result.push(c);
            }
        }
    }

    if RUST_IDENTS.contains(&result.as_str()) {
        result = format!("r#{result}");
    }

    result
}

/// The `Typed` trait indicates that a shape is a Smithy type.
pub trait Typed {
    /// Returns the Rust type to use when referring to an instance of this shape.
    fn rust_typename(&self) -> String;

    /// Writes the implementation details of this shape to the given output.
    fn write(&self, _output: &mut dyn Write) -> IoResult<()>;

    /// Indicates whether this shape has a declaration in the generated code.
    #[inline(always)]
    fn has_decl(&self, _model: &SmithyModel) -> bool {
        false
    }

    /// Indicates whether this shape is a primitive type.
    #[inline(always)]
    fn is_primitive(&self) -> bool {
        false
    }

    /// Returns the Clap value parser to use for this shape
    fn get_clap_parser(&self, option: bool) -> String;

    /// Returns the derive_builder validator, if any, to use for this shape.
    fn get_derive_builder_validator(&self, _var: &str) -> Option<String> {
        None
    }

    /// Marks this type as reachable from the input, and recursively marks any shapes targeted by this type as
    /// reachable from the input as well.
    fn mark_reachable_from_input(&mut self);
}

/// The `Primitive` trait indicates that a shape is a primitive Smithy type.
pub trait Primitive: Typed {}

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
