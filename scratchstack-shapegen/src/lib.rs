//! Rust code generation library for Smithy shape models.
use {
    derive_builder::Builder,
    http::StatusCode,
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

/// Utility for converting a status code to an `http::StatusCode` constant string.
pub(crate) fn status_code_from_u16(code: u16) -> &'static str {
    let code = StatusCode::from_u16(code).expect("Invalid HTTP status code");

    match code {
        StatusCode::CONTINUE => "::scratchstack_core::http::StatusCode::CONTINUE",
        StatusCode::SWITCHING_PROTOCOLS => "::scratchstack_core::http::StatusCode::SWITCHING_PROTOCOLS",
        StatusCode::PROCESSING => "::scratchstack_core::http::StatusCode::PROCESSING",
        StatusCode::EARLY_HINTS => "::scratchstack_core::http::StatusCode::EARLY_HINTS",
        StatusCode::OK => "::scratchstack_core::http::StatusCode::OK",
        StatusCode::CREATED => "::scratchstack_core::http::StatusCode::CREATED",
        StatusCode::ACCEPTED => "::scratchstack_core::http::StatusCode::ACCEPTED",
        StatusCode::NON_AUTHORITATIVE_INFORMATION => {
            "::scratchstack_core::http::StatusCode::NON_AUTHORITATIVE_INFORMATION"
        }
        StatusCode::NO_CONTENT => "::scratchstack_core::http::StatusCode::NO_CONTENT",
        StatusCode::RESET_CONTENT => "::scratchstack_core::http::StatusCode::RESET_CONTENT",
        StatusCode::PARTIAL_CONTENT => "::scratchstack_core::http::StatusCode::PARTIAL_CONTENT",
        StatusCode::MULTI_STATUS => "::scratchstack_core::http::StatusCode::MULTI_STATUS",
        StatusCode::ALREADY_REPORTED => "::scratchstack_core::http::StatusCode::ALREADY_REPORTED",
        StatusCode::IM_USED => "::scratchstack_core::http::StatusCode::IM_USED",
        StatusCode::MULTIPLE_CHOICES => "::scratchstack_core::http::StatusCode::MULTIPLE_CHOICES",
        StatusCode::MOVED_PERMANENTLY => "::scratchstack_core::http::StatusCode::MOVED_PERMANENTLY",
        StatusCode::FOUND => "::scratchstack_core::http::StatusCode::FOUND",
        StatusCode::SEE_OTHER => "::scratchstack_core::http::StatusCode::SEE_OTHER",
        StatusCode::NOT_MODIFIED => "::scratchstack_core::http::StatusCode::NOT_MODIFIED",
        StatusCode::USE_PROXY => "::scratchstack_core::http::StatusCode::USE_PROXY",
        StatusCode::TEMPORARY_REDIRECT => "::scratchstack_core::http::StatusCode::TEMPORARY_REDIRECT",
        StatusCode::PERMANENT_REDIRECT => "::scratchstack_core::http::StatusCode::PERMANENT_REDIRECT",
        StatusCode::BAD_REQUEST => "::scratchstack_core::http::StatusCode::BAD_REQUEST",
        StatusCode::UNAUTHORIZED => "::scratchstack_core::http::StatusCode::UNAUTHORIZED",
        StatusCode::PAYMENT_REQUIRED => "::scratchstack_core::http::StatusCode::PAYMENT_REQUIRED",
        StatusCode::FORBIDDEN => "::scratchstack_core::http::StatusCode::FORBIDDEN",
        StatusCode::NOT_FOUND => "::scratchstack_core::http::StatusCode::NOT_FOUND",
        StatusCode::METHOD_NOT_ALLOWED => "::scratchstack_core::http::StatusCode::METHOD_NOT_ALLOWED",
        StatusCode::NOT_ACCEPTABLE => "::scratchstack_core::http::StatusCode::NOT_ACCEPTABLE",
        StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
            "::scratchstack_core::http::StatusCode::PROXY_AUTHENTICATION_REQUIRED"
        }
        StatusCode::REQUEST_TIMEOUT => "::scratchstack_core::http::StatusCode::REQUEST_TIMEOUT",
        StatusCode::CONFLICT => "::scratchstack_core::http::StatusCode::CONFLICT",
        StatusCode::GONE => "::scratchstack_core::http::StatusCode::GONE",
        StatusCode::LENGTH_REQUIRED => "::scratchstack_core::http::StatusCode::LENGTH_REQUIRED",
        StatusCode::PRECONDITION_FAILED => "::scratchstack_core::http::StatusCode::PRECONDITION_FAILED",
        StatusCode::PAYLOAD_TOO_LARGE => "::scratchstack_core::http::StatusCode::PAYLOAD_TOO_LARGE",
        StatusCode::URI_TOO_LONG => "::scratchstack_core::http::StatusCode::URI_TOO_LONG",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "::scratchstack_core::http::StatusCode::UNSUPPORTED_MEDIA_TYPE",
        StatusCode::RANGE_NOT_SATISFIABLE => "::scratchstack_core::http::StatusCode::RANGE_NOT_SATISFIABLE",
        StatusCode::EXPECTATION_FAILED => "::scratchstack_core::http::StatusCode::EXPECTATION_FAILED",
        StatusCode::IM_A_TEAPOT => "::scratchstack_core::http::StatusCode::IM_A_TEAPOT",
        StatusCode::MISDIRECTED_REQUEST => "::scratchstack_core::http::StatusCode::MISDIRECTED_REQUEST",
        StatusCode::UNPROCESSABLE_ENTITY => "::scratchstack_core::http::StatusCode::UNPROCESSABLE_ENTITY",
        StatusCode::LOCKED => "::scratchstack_core::http::StatusCode::LOCKED",
        StatusCode::FAILED_DEPENDENCY => "::scratchstack_core::http::StatusCode::FAILED_DEPENDENCY",
        StatusCode::TOO_EARLY => "::scratchstack_core::http::StatusCode::TOO_EARLY",
        StatusCode::UPGRADE_REQUIRED => "::scratchstack_core::http::StatusCode::UPGRADE_REQUIRED",
        StatusCode::PRECONDITION_REQUIRED => "::scratchstack_core::http::StatusCode::PRECONDITION_REQUIRED",
        StatusCode::TOO_MANY_REQUESTS => "::scratchstack_core::http::StatusCode::TOO_MANY_REQUESTS",
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE => {
            "::scratchstack_core::http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE"
        }
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS => {
            "::scratchstack_core::http::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS"
        }
        StatusCode::INTERNAL_SERVER_ERROR => "::scratchstack_core::http::StatusCode::INTERNAL_SERVER_ERROR",
        StatusCode::NOT_IMPLEMENTED => "::scratchstack_core::http::StatusCode::NOT_IMPLEMENTED",
        StatusCode::BAD_GATEWAY => "::scratchstack_core::http::StatusCode::BAD_GATEWAY",
        StatusCode::SERVICE_UNAVAILABLE => "::scratchstack_core::http::StatusCode::SERVICE_UNAVAILABLE",
        StatusCode::GATEWAY_TIMEOUT => "::scratchstack_core::http::StatusCode::GATEWAY_TIMEOUT",
        StatusCode::HTTP_VERSION_NOT_SUPPORTED => "::scratchstack_core::http::StatusCode::HTTP_VERSION_NOT_SUPPORTED",
        StatusCode::VARIANT_ALSO_NEGOTIATES => "::scratchstack_core::http::StatusCode::VARIANT_ALSO_NEGOTIATES",
        StatusCode::INSUFFICIENT_STORAGE => "::scratchstack_core::http::StatusCode::INSUFFICIENT_STORAGE",
        StatusCode::LOOP_DETECTED => "::scratchstack_core::http::StatusCode::LOOP_DETECTED",
        StatusCode::NOT_EXTENDED => "::scratchstack_core::http::StatusCode::NOT_EXTENDED",
        StatusCode::NETWORK_AUTHENTICATION_REQUIRED => {
            "::scratchstack_core::http::StatusCode::NETWORK_AUTHENTICATION_REQUIRED"
        }
        _ => panic!("Unsupported HTTP status code: {code}"),
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
