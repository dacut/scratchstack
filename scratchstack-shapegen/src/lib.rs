//! Rust code generation library for Smithy shape models.
use {
    bon::Builder,
    std::{
        fs::File,
        io::{BufWriter, Result as IoResult, Write},
        path::Path,
    },
};

/// Primitive Smithy types.
pub mod primitive;

mod cli_shorthand;
mod common_errors;
mod r#enum;
mod generator;
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
mod transform;
mod r#union;

#[allow(unused_imports)]
pub use {
    cli_shorthand::*, common_errors::*, r#enum::*, generator::*, int_enum::*, length_constraint::*, list::*, map::*,
    member::*, operation::*, range_constraint::*, resource::*, service::*, shape::*, shape_base::*, shape_ref::*,
    smithy_model::*, str_ext::*, structure::*, trait_id::*, trait_map::*, transform::*, r#union::*,
};

/// Writers that will write generated code into the appropriate module.
#[derive(Builder, Debug)]
pub struct Writers<W: Write> {
    pub action: W,
    pub error_meta: W,
    pub operation: W,
    pub types: W,
    pub types_error: W,
}

impl Writers<BufWriter<File>> {
    /// Creates the five generated modules in `dir`, each buffered.
    ///
    /// Generation writes a line at a time -- around 94,000 of them for the IAM model -- so the
    /// buffering is not incidental.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the files cannot be created.
    pub fn create_in(dir: &Path) -> IoResult<Self> {
        fn create(dir: &Path, name: &str) -> IoResult<BufWriter<File>> {
            let path = dir.join(name);
            let file = std::fs::File::create(&path)
                .map_err(|e| std::io::Error::new(e.kind(), format!("could not create {}: {e}", path.display())))?;
            Ok(BufWriter::new(file))
        }

        Ok(Self {
            action: create(dir, "action.rs")?,
            error_meta: create(dir, "error_meta.rs")?,
            operation: create(dir, "operation.rs")?,
            types: create(dir, "types.rs")?,
            types_error: create(dir, "types_error.rs")?,
        })
    }
}

impl<W: Write> Writers<W> {
    /// Flushes every sink.
    ///
    /// # Errors
    ///
    /// Returns the first flush error encountered.
    pub fn flush(&mut self) -> IoResult<()> {
        self.action.flush()?;
        self.error_meta.flush()?;
        self.operation.flush()?;
        self.types.flush()?;
        self.types_error.flush()
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
    /// This is the *body* of a check, not a whole function. It is emitted once, into the shape's
    /// validator function; builders call that function rather than repeating the body. See
    /// [`validator_fn_name`][Self::validator_fn_name].
    ///
    /// # Parameters
    /// * `var` — the variable holding the value to be validated.
    /// * `field_name` — the name of the field being evaluated (for use in error messages). Callers
    ///   emitting a validator function pass the literal `{field}`, which resolves to that
    ///   function's `field` parameter when the generated `format!` runs.
    #[allow(unused)]
    fn derive_builder_validator(&self, var: &str, field_name: &str) -> Option<String> {
        None
    }

    /// The name of this shape's validator function, if it constrains its values.
    ///
    /// Constraints belong to the shape, not to the fields targeting it: `accountIdType` is one
    /// regular expression however many requests carry an account id. Emitting the check once per
    /// shape and calling it per field keeps IAM from compiling the same twelve-digit pattern 153
    /// times.
    fn validator_fn_name(&self) -> Option<String> {
        None
    }

    /// Writes this shape's validator function, if it has one, into `crate::types`.
    #[allow(unused_variables)] // Makes code completion show `w` instead of `_w`.
    fn write_validator_fn(&self, w: &mut dyn Write) -> IoResult<()> {
        Ok(())
    }

    /// Generate Rust code for this shape, writing it to the appropriate module in `w`.
    #[allow(unused_variables)] // Makes code completion show `w` instead of `_w`.
    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        Ok(())
    }
}

/// Renders an HTTP status code as a `scratchstack_core::http::StatusCode` constant expression.
///
/// `StatusCode::from_u16` is not `const`, so generated code names the constant directly. Codes
/// outside the set below panic here, at generation time, rather than producing code that fails to
/// compile or -- worse -- parses the status at runtime on every call.
pub(crate) fn status_code_const(code: u16) -> &'static str {
    match code {
        400 => "::scratchstack_core::http::StatusCode::BAD_REQUEST",
        401 => "::scratchstack_core::http::StatusCode::UNAUTHORIZED",
        403 => "::scratchstack_core::http::StatusCode::FORBIDDEN",
        404 => "::scratchstack_core::http::StatusCode::NOT_FOUND",
        405 => "::scratchstack_core::http::StatusCode::METHOD_NOT_ALLOWED",
        409 => "::scratchstack_core::http::StatusCode::CONFLICT",
        410 => "::scratchstack_core::http::StatusCode::GONE",
        412 => "::scratchstack_core::http::StatusCode::PRECONDITION_FAILED",
        413 => "::scratchstack_core::http::StatusCode::PAYLOAD_TOO_LARGE",
        429 => "::scratchstack_core::http::StatusCode::TOO_MANY_REQUESTS",
        500 => "::scratchstack_core::http::StatusCode::INTERNAL_SERVER_ERROR",
        501 => "::scratchstack_core::http::StatusCode::NOT_IMPLEMENTED",
        503 => "::scratchstack_core::http::StatusCode::SERVICE_UNAVAILABLE",
        504 => "::scratchstack_core::http::StatusCode::GATEWAY_TIMEOUT",
        _ => panic!("Unsupported HTTP status code in model: {code}; add it to status_code_const()"),
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

/// Writes a validator function for one shape into `crate::types`.
///
/// The function takes the value and the name of the field being checked, so one function serves
/// every field targeting the shape and each still names itself in the error. `body` comes from
/// [`ShapeInfo::derive_builder_validator`] rendered with `{field}` as the field name, which the
/// generated `format!` calls resolve against the `field` parameter.
pub(crate) fn write_validator_fn(
    w: &mut dyn Write,
    fn_name: &str,
    value_type: &str,
    simple_name: &str,
    body: &str,
) -> IoResult<()> {
    writeln!(w, "/// Validates a value against the constraints of the `{simple_name}` shape.")?;
    writeln!(w, "///")?;
    writeln!(w, "/// `field` names the field being checked and appears in the error message.")?;
    writeln!(
        w,
        "pub(crate) fn {fn_name}(value: &{value_type}, field: &str) -> ::std::result::Result<(), ::std::string::String> {{"
    )?;
    for line in body.trim_end().lines() {
        if line.trim().is_empty() {
            writeln!(w)?;
        } else {
            writeln!(w, "    {line}")?;
        }
    }
    writeln!(w, "    ::std::result::Result::Ok(())")?;
    writeln!(w, "}}")?;
    writeln!(w)?;
    Ok(())
}

/// The validator function name for a shape with the given simple name.
pub(crate) fn validator_fn_name_for(simple_name: &str) -> String {
    simple_name.to_rust_ident_affixed("validate_", "")
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
        let mut m: SmithyModel = serde_json::from_str(IAM_MODEL).expect("Failed to deserialize IAM service model");
        m.resolve();
        let mut w = Writers::builder()
            .action(NullWriter)
            .error_meta(NullWriter)
            .operation(NullWriter)
            .types(NullWriter)
            .types_error(NullWriter)
            .build();
        m.generate(&mut w).expect("Failed to generate Rust code for IAM service model");
    }
}
