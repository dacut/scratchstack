//! Scratchstack STS service API shapes.
//!
//! This crate contains the shapes used in the API of the AWS STS service implemented by Scratchstack.
//! These shapes are used in the request and response bodies of the API. This crate is intended to
//! be used as a dependency by the service implementations and clients that need to interact with
//! the STS service.
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

/// Error metadata type that contains a union of all possible errors returned by operations in this service.
pub mod error_meta;

/// Operation input and output shapes.
pub mod operation;

/// General types used in the API.
pub mod types;

#[cfg(test)]
mod tests {
    use {
        crate::{
            operation::{GetCallerIdentityResponse, GetCallerIdentityResponseEnvelope},
            types::error::ExpiredTokenException,
        },
        scratchstack_core::{quick_xml, response::ErrorResponseEnvelope},
    };

    const STS_XMLNS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

    /// The response envelope is what actually goes on the wire, so pin its exact shape: the
    /// namespace on the root element, the `<{Operation}Result>` wrapper, and the request id
    /// as a sibling of the result rather than inside it.
    #[test_log::test]
    fn get_caller_identity_response_envelope_wire_format() {
        let result = GetCallerIdentityResponse::builder()
            .account("123456789012".to_string())
            .arn("arn:aws:iam::123456789012:user/alice".to_string())
            .user_id("AIDAQXZEAEXAMPLEUSER".to_string())
            .build()
            .expect("failed to build GetCallerIdentityResponse");

        let envelope = GetCallerIdentityResponseEnvelope::builder()
            .result(result)
            .request_id("11111111-2222-3333-4444-555555555555")
            .build();

        let xml = quick_xml::se::to_string(&envelope).expect("failed to serialize");
        assert_eq!(
            xml,
            format!(
                r#"<GetCallerIdentityResponse xmlns="{STS_XMLNS}"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/alice</Arn><UserId>AIDAQXZEAEXAMPLEUSER</UserId></GetCallerIdentityResult><RequestId>11111111-2222-3333-4444-555555555555</RequestId></GetCallerIdentityResponse>"#
            )
        );
    }

    /// Errors carry the service namespace too, and a client error must say `Sender`.
    #[test_log::test]
    fn error_response_envelope_wire_format() {
        let error = ExpiredTokenException::builder()
            .message("The security token included in the request is expired.")
            .request_id("11111111-2222-3333-4444-555555555555")
            .build();

        let xml = quick_xml::se::to_string(&ErrorResponseEnvelope::new(&error)).expect("failed to serialize");
        assert_eq!(
            xml,
            format!(
                r#"<ErrorResponse xmlns="{STS_XMLNS}"><Error><Type>Sender</Type><Code>ExpiredToken</Code><Message>The security token included in the request is expired.</Message></Error><RequestId>11111111-2222-3333-4444-555555555555</RequestId></ErrorResponse>"#
            )
        );
    }
}
