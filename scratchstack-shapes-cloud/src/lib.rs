//! Scratchstack Cloud service API shapes.
//!
//! This crate contains the shapes used in the API of the Scratchstack Cloud service.
//! These shapes are used in the request and response bodies of the API. This crate is intended to
//! be used as a dependency by the service implementations and clients that need to interact with
//! the Cloud service.
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

/// The actions (operation names) callable on this service, and the API version.
pub mod action {
    include!(concat!(env!("OUT_DIR"), "/action.rs"));
}

/// Error metadata type that contains a union of all possible errors returned by operations in this service.
pub mod error_meta {
    include!(concat!(env!("OUT_DIR"), "/error_meta.rs"));
}

/// Operation input and output shapes.
pub mod operation {
    include!(concat!(env!("OUT_DIR"), "/operation.rs"));
}

/// General types used in the API.
pub mod types {
    /// Error types used in the API.
    pub mod error {
        include!(concat!(env!("OUT_DIR"), "/types_error.rs"));
    }
    include!(concat!(env!("OUT_DIR"), "/types.rs"));
}

#[cfg(test)]
mod tests {
    use {
        crate::{operation::CreateQuotaDefinitionRequest, types::QuotaScope},
        bigdecimal::BigDecimal,
        pretty_assertions::assert_eq,
        std::str::FromStr as _,
    };

    /// Smithy's `bigDecimal` is a JSON number under the AWS JSON protocols. `BigDecimal`'s own
    /// Serde implementation writes a string, so without the numeric adapter these go out as
    /// `"1.5"` and a protocol-compatible client cannot read them.
    #[test]
    fn quota_values_are_json_numbers_not_strings() {
        let request = CreateQuotaDefinitionRequest::builder()
            .service_id("cloud")
            .quota_name("ExampleQuota")
            .scope(QuotaScope::Global)
            .unit("requests")
            .min_value(BigDecimal::from_str("1.5").expect("1.5 should parse"))
            .max_value(BigDecimal::from_str("1000").expect("1000 should parse"))
            .build()
            .expect("the request should build");

        let json = serde_json::to_string(&request).expect("the request should serialize");
        assert!(json.contains(r#""MinValue":1.5"#), "MinValue should be a number: {json}");
        assert!(json.contains(r#""MaxValue":1000"#), "MaxValue should be a number: {json}");
        assert!(!json.contains(r#""1.5""#), "no quota value should be quoted: {json}");
    }

    /// Every digit survives the round trip, which is the whole reason the shape is a `bigDecimal`
    /// rather than a double.
    #[test]
    fn a_quota_value_keeps_its_precision_through_a_round_trip() {
        let precise = "123456789012345678901234567890.123456789";
        let request = CreateQuotaDefinitionRequest::builder()
            .service_id("cloud")
            .quota_name("ExampleQuota")
            .scope(QuotaScope::Global)
            .unit("requests")
            .max_value(BigDecimal::from_str(precise).expect("the value should parse"))
            .build()
            .expect("the request should build");

        let json = serde_json::to_string(&request).expect("the request should serialize");
        assert!(json.contains(precise), "the digits should survive serialization: {json}");

        let back: CreateQuotaDefinitionRequest = serde_json::from_str(&json).expect("the request should deserialize");
        assert_eq!(back.max_value, request.max_value);
    }
}
