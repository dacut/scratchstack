//! Rust code generation library for Smithy shape models.
use proc_macro2::TokenStream;

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
mod modules;
mod operation;
mod protocol;
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
    member::*, modules::*, operation::*, protocol::*, range_constraint::*, resource::*, service::*, shape::*,
    shape_base::*, shape_ref::*, smithy_model::*, str_ext::*, structure::*, trait_id::*, trait_map::*, transform::*,
    r#union::*,
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

    /// The checks this shape's values must pass, if it constrains them.
    ///
    /// This is the *body* of a validator function, not a whole one: it may refer to `value`, the
    /// value under test, and `field`, the name of the field being checked. It is emitted once, into
    /// the shape's validator function, and builders call that function rather than repeating it.
    fn validator_body(&self) -> Option<TokenStream> {
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

    /// This shape's validator function, if it has one, for `crate::types`.
    fn validator_fn(&self) -> Option<TokenStream> {
        let fn_name = self.validator_fn_name()?;
        let body = self.validator_body()?;
        Some(validator_fn_tokens(&fn_name, &self.validator_value_type(), &self.simple_name(), &body))
    }

    /// The type a validator function takes by reference. Defaults to the shape's own Rust type.
    fn validator_value_type(&self) -> String {
        self.rust_typename()
    }

    /// Appends this shape's generated code to the appropriate module in `m`.
    #[allow(unused_variables)] // Makes code completion show `m` instead of `_m`.
    fn generate(&self, model: &SmithyModel, m: &mut Modules) {}
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

/// Builds a validator function for one shape.
///
/// The function takes the value and the name of the field being checked, so one function serves
/// every field targeting the shape and each still names itself in the error.
#[must_use]
pub fn validator_fn_tokens(fn_name: &str, value_type: &str, simple_name: &str, body: &TokenStream) -> TokenStream {
    let name = ident(fn_name);
    let value_type = type_tokens(value_type);
    let doc = format!(" Validates a value against the constraints of the `{simple_name}` shape.");

    quote::quote! {
        #[doc = #doc]
        #[doc = ""]
        #[doc = " `field` names the field being checked and appears in the error message."]
        pub(crate) fn #name(
            value: &#value_type,
            field: &str,
        ) -> ::std::result::Result<(), ::std::string::String> {
            #body
            ::std::result::Result::Ok(())
        }
    }
}

/// The validator function name for a shape with the given simple name.
pub(crate) fn validator_fn_name_for(simple_name: &str) -> String {
    simple_name.to_rust_ident_affixed("validate_", "")
}

#[cfg(test)]
mod tests {
    use {super::*, std::path::Path};

    /// A model exercising the constructs the generators actually branch on: a service, an
    /// operation, a second operation whose output is the unit type -- the branch that writes an
    /// envelope with no result in it -- a constrained string reused by several fields, a
    /// length-constrained list, an enum, and an error.
    const FIXTURE: &str = r##"{
      "smithy": "2.0",
      "shapes": {
        "com.example#Example": {
          "type": "service",
          "version": "2020-01-01",
          "operations": [{"target": "com.example#CreateWidget"}, {"target": "com.example#DeleteWidget"}],
          "traits": {
            "aws.protocols#awsQuery": {},
            "smithy.api#xmlNamespace": {"uri": "https://example.amazonaws.com/doc/2020-01-01/"}
          }
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
        "com.example#DeleteWidget": {
          "type": "operation",
          "input": {"target": "com.example#DeleteWidgetRequest"},
          "output": {"target": "smithy.api#Unit"}
        },
        "com.example#DeleteWidgetRequest": {
          "type": "structure",
          "traits": {"smithy.api#input": {}},
          "members": {"WidgetName": {"target": "com.example#widgetNameType", "traits": {"smithy.api#required": {}}}}
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
        "com.example#Color": {
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
        generate_with(model_json, CliShorthand::default())
    }

    /// Whether `haystack` contains `needle`, ignoring how the formatter wrapped either.
    ///
    /// `prettyplease` breaks long signatures across lines, so an assertion written as one line
    /// would otherwise be testing the formatter rather than the generator.
    fn contains(haystack: &str, needle: &str) -> bool {
        fn squash(text: &str) -> String {
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        }

        squash(haystack).contains(&squash(needle))
    }

    fn generate_with(model_json: &str, cli_shorthand: CliShorthand) -> Generated {
        let mut model: SmithyModel = serde_json::from_str(model_json).expect("fixture should deserialize");
        model.add_default_shapes();
        model.cli_shorthand = cli_shorthand;
        model.resolve();

        let mut m = Modules::new();
        model.generate(&mut m);

        // Rendering is the assertion that the generators produced parseable Rust at all.
        Generated {
            action: render("action.rs", &m.action),
            error_meta: render("error_meta.rs", &m.error_meta),
            operation: render("operation.rs", &m.operation),
            types: render("types.rs", &m.types),
            types_error: render("types_error.rs", &m.types_error),
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

        assert!(contains(&generated.operation, r#"validate_widget_name_type(value, "WidgetName")"#));
        assert!(contains(&generated.operation, r#"validate_widget_name_type(value, "OwnerName")"#));
        assert!(
            !contains(&generated.operation, "CreateWidgetRequest must match"),
            "the error should name the field, not the structure"
        );
    }

    #[test]
    fn list_validator_delegates_to_its_element() {
        let generated = generate(FIXTURE);

        assert!(contains(&generated.types, "pub(crate) fn validate_tag_list_type"));
        assert!(contains(&generated.types, "validate_widget_name_type(el, field)"));
        // A slice, so clippy's ptr_arg lint does not fire on the generated code.
        assert!(
            contains(&generated.types, "value: &[::std::string::String]"),
            "list validators take a slice, not &Vec: {}",
            generated.types
        );
    }

    #[test]
    fn numeric_range_constraints_are_validated() {
        let generated = generate(FIXTURE);

        assert!(contains(&generated.types, "pub(crate) fn validate_size_type"));
        assert!(contains(&generated.types, "*value < 1"));
        assert!(contains(&generated.types, "*value > 100"));
    }

    #[test]
    fn string_length_counts_code_points_not_bytes() {
        let generated = generate(FIXTURE);

        assert!(contains(&generated.types, "value.chars().count() > 64"));
        assert!(!contains(&generated.types, "value.len() > 64"), "Smithy length counts code points");
    }

    #[test]
    fn action_enum_lists_operations_bound_to_the_service() {
        let generated = generate(FIXTURE);

        assert!(contains(&generated.action, r#"pub const VERSION: &str = "2020-01-01";"#));
        assert!(contains(&generated.action, "CreateWidget,"));
        assert!(contains(&generated.action, r#""CreateWidget" => ::std::result::Result::Ok(Self::CreateWidget)"#));
    }

    /// The query protocol's wire form, which the JSON test below is the counterpart to: the
    /// envelope names the namespace and wraps the request id, and the error carries its type and
    /// code in the body.
    #[test]
    fn query_protocol_wraps_responses_in_the_xml_envelope() {
        let generated = generate(FIXTURE);

        assert!(contains(&generated.operation, r#"s.serialize_field("@xmlns""#));
        assert!(contains(&generated.operation, r#"s.serialize_field("CreateWidgetResult", &self.result)"#));
        assert!(contains(&generated.operation, "ResponseMetadata"));
        assert!(contains(&generated.operation, "::scratchstack_core::response::xml_response"));
        assert!(contains(&generated.operation, "impl ::scratchstack_core::ProvideXmlNamespace"));

        // An operation with no output keeps the envelope, minus the result element: two fields
        // rather than three. The needles stop short of the closing parenthesis, since
        // `prettyplease` may break the call's arguments across lines.
        assert!(contains(&generated.operation, r#""DeleteWidgetResponse", 2"#));
        assert!(!contains(&generated.operation, "DeleteWidgetResult"), "wrote a result element for a unit output");

        assert!(contains(&generated.types_error, r#"e.serialize_field("Type", "Sender")"#));
        assert!(contains(&generated.types_error, r#"e.serialize_field("Code", "NoSuchWidget")"#));
        assert!(contains(&generated.types_error, r#"e.serialize_field("Message", message)"#));
        assert!(contains(&generated.types_error, "ErrorResponseEnvelope::new(self)"));
        assert!(contains(&generated.error_meta, "ErrorResponseEnvelope::new_with_xmlns"));
    }

    /// The JSON protocols have no envelope and no namespace: a response is the result shape itself
    /// and an error is its message alone, with the code and the request id going out as headers.
    /// The fixture is the query one with its protocol trait swapped, so the protocol is the only
    /// thing these differ by.
    #[test]
    fn json_protocol_responses_carry_no_envelope() {
        let generated = generate(&FIXTURE.replace("aws.protocols#awsQuery", "aws.protocols#awsJson1_1"));

        // Nothing anywhere claims an XML namespace, and nothing renders one.
        for module in [&generated.operation, &generated.types_error, &generated.error_meta] {
            assert!(!contains(module, "ProvideXmlNamespace"), "generated an XML namespace impl: {module}");
            assert!(!contains(module, "@xmlns"), "rendered an XML namespace: {module}");
        }

        // The envelope serializes as the result it carries, and responds as JSON.
        assert!(contains(&generated.operation, "::serde::Serialize::serialize(&self.result, serializer)"));
        assert!(contains(&generated.operation, "::scratchstack_core::response::json_response"));
        // The needles are separate because `prettyplease` may break the call across lines, which
        // leaves a space and a trailing comma inside the parentheses that a single needle misses.
        assert!(contains(&generated.operation, "HeaderValue::from_static"));
        assert!(contains(&generated.operation, r#""application/x-amz-json-1.1""#));
        assert!(!contains(&generated.operation, "ResponseMetadata"), "wrapped the request id in the body");

        // An operation with no output answers with an empty object rather than with nothing: a
        // struct of no fields, which serde_json renders as `{}`.
        assert!(contains(&generated.operation, r#""DeleteWidgetResponse", 0"#));
        assert!(!contains(&generated.operation, "DeleteWidgetResult"), "wrote a result element for a unit output");

        // The error body is the message under its lower-case name, and nothing else.
        assert!(contains(&generated.types_error, r#"e.serialize_field("message", message)"#));
        assert!(!contains(&generated.types_error, r#"serialize_field("Code""#), "wrote the code into the body");
        assert!(!contains(&generated.types_error, r#"serialize_field("Type""#), "wrote the type into the body");
        assert!(contains(&generated.types_error, "::scratchstack_core::response::json_error_response"));

        // An `Unhandled` error is a `GenericError`, which has to be rendered rather than serialized.
        assert!(contains(&generated.error_meta, "JsonErrorBody::new(inner)"));
    }

    /// Shapes outside the service's namespace are dropped rather than generated. A built model
    /// imports the definitions of the traits it used, and `aws.api#service` would otherwise
    /// generate a `Service` type colliding with the service's own.
    #[test]
    fn foreign_shapes_are_dropped_but_the_prelude_is_kept() {
        let mut model: SmithyModel = serde_json::from_str(FIXTURE).expect("fixture should deserialize");
        model.shapes.insert(
            "aws.api#service".to_string(),
            serde_json::from_str(r#"{"type": "structure", "members": {}}"#).expect("shape should deserialize"),
        );
        model.add_default_shapes();
        model.retain_namespace("com.example");

        assert!(!model.shapes.contains_key("aws.api#service"));
        assert!(model.shapes.contains_key("com.example#Widget"));
        assert!(model.shapes.contains_key("smithy.api#Unit"), "the prelude is what members target");
    }

    #[test]
    fn errors_reach_both_the_error_module_and_the_union_enum() {
        let generated = generate(FIXTURE);

        assert!(contains(&generated.types_error, "pub struct NoSuchWidget"));
        assert!(contains(&generated.error_meta, "NoSuchWidget(::std::boxed::Box<crate::types::error::NoSuchWidget>)"));
        assert!(contains(&generated.types_error, "::scratchstack_core::http::StatusCode::NOT_FOUND"));
    }

    #[test]
    fn enum_serde_rename_uses_the_wire_value() {
        let generated = generate(FIXTURE);

        // `enumValue` is the wire value, so serde has to agree with `Display` and `FromStr`.
        // Renaming to the Smithy member name instead made serialization emit a value the service
        // never sends and deserialization reject the one it does.
        assert!(contains(&generated.types, r#"#[serde(rename = "red")] Red,"#));
        assert!(!contains(&generated.types, r#"#[serde(rename = "RED")]"#));

        // The same value drives Display and FromStr.
        assert!(contains(&generated.types, r#"Self::Red => f.write_str("red")"#));
        assert!(contains(&generated.types, r#""red" => Ok(Self::Red)"#));
    }

    #[test]
    fn cli_shorthand_policy_decides_which_shapes_get_parsers() {
        let all = generate_with(FIXTURE, CliShorthand::All);
        let value_types = generate(FIXTURE);
        let none = generate_with(FIXTURE, CliShorthand::None);

        // `All` reaches request structures; the default `ValueTypes` does not.
        assert!(contains(&all.operation, "ShorthandValue> for CreateWidgetRequest"));
        assert!(!contains(&value_types.operation, "ShorthandValue> for CreateWidgetRequest"));

        // Value types -- structures and enums alike -- get one under `All` and `ValueTypes`.
        for generated in [&all, &value_types] {
            assert!(contains(&generated.types, "ShorthandValue> for Widget"));
            assert!(contains(&generated.types, "ShorthandValue> for Color"));
        }

        // `None` means none, for every shape kind and in every module.
        assert!(!contains(&none.types, "ShorthandValue>"), "no value type should get a parser");
        assert!(!contains(&none.operation, "ShorthandValue>"), "no request should get one either");

        // But `None` is about shorthand, not about clap: an enum keeps its `ValueEnum`.
        assert!(contains(&none.types, "impl ::clap::ValueEnum for Color"));
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

        assert!(contains(&generated.action, "CreateUser,"));
        assert!(contains(&generated.types, "pub(crate) fn validate_account_id_type"));
        assert!(contains(&generated.operation, "pub struct CreateUserRequest"));
    }
}
