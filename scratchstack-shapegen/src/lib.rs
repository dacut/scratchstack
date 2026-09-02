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
        let mut smithy_name = self.smithy_name();
        if let Some(pos) = smithy_name.rfind('#') {
            smithy_name.drain(..=pos);
        }
        smithy_name
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
    use {super::*, std::path::Path};

    /// A model exercising the constructs the generators actually branch on: a service, an
    /// operation, a constrained string reused by two fields, a length-constrained list, an enum,
    /// and an error.
    const FIXTURE: &str = r##"{
      "smithy": "2.0",
      "shapes": {
        "com.example#Example": {
          "type": "service",
          "version": "2020-01-01",
          "operations": [{"target": "com.example#CreateWidget"}],
          "traits": {"smithy.api#xmlNamespace": {"uri": "https://example.amazonaws.com/doc/2020-01-01/"}}
        },
        "com.example#CreateWidget": {
          "type": "operation",
          "input": {"target": "com.example#CreateWidgetRequest"},
          "output": {"target": "com.example#CreateWidgetResponse"}
        },
        "com.example#CreateWidgetRequest": {
          "type": "structure",
          "traits": {"smithy.api#input": {}},
          "members": {
            "WidgetName": {"target": "com.example#widgetNameType", "traits": {"smithy.api#required": {}}},
            "OwnerName": {"target": "com.example#widgetNameType"},
            "Tags": {"target": "com.example#tagListType"},
            "Size": {"target": "com.example#sizeType"}
          }
        },
        "com.example#CreateWidgetResponse": {
          "type": "structure",
          "traits": {"smithy.api#output": {}},
          "members": {"Widget": {"target": "com.example#Widget"}}
        },
        "com.example#Widget": {
          "type": "structure",
          "members": {"Name": {"target": "com.example#widgetNameType"}}
        },
        "com.example#widgetNameType": {
          "type": "string",
          "traits": {"smithy.api#pattern": "^[\\w+=,.@-]+$", "smithy.api#length": {"min": 1, "max": 64}}
        },
        "com.example#tagListType": {
          "type": "list",
          "member": {"target": "com.example#widgetNameType"},
          "traits": {"smithy.api#length": {"max": 50}}
        },
        "com.example#sizeType": {
          "type": "integer",
          "traits": {"smithy.api#range": {"min": 1, "max": 100}}
        },
        "com.example#Colour": {
          "type": "enum",
          "members": {"RED": {"target": "smithy.api#Unit", "traits": {"smithy.api#enumValue": "red"}}}
        },
        "com.example#NoSuchWidget": {
          "type": "structure",
          "traits": {"smithy.api#error": "client", "smithy.api#httpError": 404},
          "members": {"message": {"target": "com.example#errorMessageType"}}
        },
        "com.example#errorMessageType": {"type": "string"}
      }
    }"##;

    /// The five generated modules, as strings.
    struct Generated {
        action: String,
        error_meta: String,
        operation: String,
        types: String,
        types_error: String,
    }

    fn generate(model_json: &str) -> Generated {
        let mut model: SmithyModel = serde_json::from_str(model_json).expect("fixture should deserialize");
        model.add_default_shapes();
        model.resolve();

        let mut w = Writers::builder()
            .action(Vec::new())
            .error_meta(Vec::new())
            .operation(Vec::new())
            .types(Vec::new())
            .types_error(Vec::new())
            .build();
        model.generate(&mut w).expect("generation should succeed");

        let to_string = |bytes: Vec<u8>| String::from_utf8(bytes).expect("generated code should be UTF-8");
        Generated {
            action: to_string(w.action),
            error_meta: to_string(w.error_meta),
            operation: to_string(w.operation),
            types: to_string(w.types),
            types_error: to_string(w.types_error),
        }
    }

    #[test]
    fn constrained_shape_gets_exactly_one_validator() {
        let generated = generate(FIXTURE);

        // One function and one compiled pattern for the shape, however many fields target it --
        // three do here, across two structures.
        assert_eq!(generated.types.matches("pub(crate) fn validate_widget_name_type").count(), 1);
        assert_eq!(generated.types.matches("::regex::Regex::new").count(), 1);
        assert_eq!(generated.operation.matches("::regex::Regex::new").count(), 0);
    }

    #[test]
    fn validators_are_called_with_the_field_name_not_the_struct_name() {
        let generated = generate(FIXTURE);

        assert!(generated.operation.contains(r#"validate_widget_name_type(value, "WidgetName")"#));
        assert!(generated.operation.contains(r#"validate_widget_name_type(value, "OwnerName")"#));
        assert!(
            !generated.operation.contains("CreateWidgetRequest must match"),
            "the error should name the field, not the structure"
        );
    }

    #[test]
    fn list_validator_delegates_to_its_element() {
        let generated = generate(FIXTURE);

        assert!(generated.types.contains("pub(crate) fn validate_tag_list_type"));
        assert!(generated.types.contains("validate_widget_name_type(el, field)"));
        // A slice, so clippy's ptr_arg lint does not fire on the generated code.
        assert!(generated.types.contains("validate_tag_list_type(value: &[::std::string::String]"));
    }

    #[test]
    fn numeric_range_constraints_are_validated() {
        let generated = generate(FIXTURE);

        assert!(generated.types.contains("pub(crate) fn validate_size_type"));
        assert!(generated.types.contains("*value < 1"));
        assert!(generated.types.contains("*value > 100"));
    }

    #[test]
    fn string_length_counts_code_points_not_bytes() {
        let generated = generate(FIXTURE);

        assert!(generated.types.contains("value.chars().count() > 64"));
        assert!(!generated.types.contains("value.len() > 64"), "Smithy length counts code points");
    }

    #[test]
    fn action_enum_lists_operations_bound_to_the_service() {
        let generated = generate(FIXTURE);

        assert!(generated.action.contains(r#"pub const VERSION: &str = "2020-01-01";"#));
        assert!(generated.action.contains("    CreateWidget,"));
        assert!(generated.action.contains(r#""CreateWidget" => ::std::result::Result::Ok(Self::CreateWidget)"#));
    }

    #[test]
    fn errors_reach_both_the_error_module_and_the_union_enum() {
        let generated = generate(FIXTURE);

        assert!(generated.types_error.contains("pub struct NoSuchWidget"));
        assert!(generated.error_meta.contains("NoSuchWidget(::std::boxed::Box<crate::types::error::NoSuchWidget>)"));
        assert!(generated.types_error.contains("::scratchstack_core::http::StatusCode::NOT_FOUND"));
    }

    #[test]
    fn cli_shorthand_policy_decides_which_shapes_get_parsers() {
        let mut model: SmithyModel = serde_json::from_str(FIXTURE).expect("fixture should deserialize");
        model.add_default_shapes();
        model.cli_shorthand = CliShorthand::All;
        model.resolve();

        let mut w = Writers::builder()
            .action(Vec::new())
            .error_meta(Vec::new())
            .operation(Vec::new())
            .types(Vec::new())
            .types_error(Vec::new())
            .build();
        model.generate(&mut w).expect("generation should succeed");
        let operation = String::from_utf8(w.operation).expect("generated code should be UTF-8");

        // `All` reaches request structures; the default `ValueTypes` does not.
        assert!(operation.contains("ShorthandValue> for CreateWidgetRequest"));
        assert!(!generate(FIXTURE).operation.contains("ShorthandValue> for CreateWidgetRequest"));
    }

    /// Generation over the real IAM model: 749 shapes, and the only coverage of constructs the
    /// fixture does not reach.
    ///
    /// The model belongs to `scratchstack-shapes-iam`; shapegen used to keep its own copy, which
    /// was a megabyte of duplicated JSON with nothing keeping the two in sync.
    #[test]
    fn generates_the_iam_model() {
        let model_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scratchstack-shapes-iam/iam-2010-05-08.json");
        let model_json = std::fs::read_to_string(&model_path)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", model_path.display()));

        let generated = generate(&model_json);

        assert!(generated.action.contains("    CreateUser,"));
        assert!(generated.types.contains("pub(crate) fn validate_account_id_type"));
        assert!(generated.operation.contains("pub struct CreateUserRequest"));
    }
}
