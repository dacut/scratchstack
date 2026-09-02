//! Compiles shapegen's output for every Smithy shape kind.
//!
//! `scratchstack-shapes-iam` and `scratchstack-shapes-sts` between them use structures, operations,
//! strings, lists, enums, integers, maps, booleans, blobs, timestamps and a service -- but no union
//! and no `intEnum`. Code generated for the kinds they leave out was never compiled by anything, and
//! three bugs lived there undetected:
//!
//! * unions carried `#[serde(tag = ...)]`, a *container* attribute serde rejects on a variant, so
//!   any model with a union produced code that would not build at all;
//! * unions derived only `Debug`, while a structure holding one derives `Clone`, `Eq` and
//!   `PartialEq`, so using a union as a member did not compile either;
//! * `intEnum` named its variants with `serde(rename)`, encoding the *name* where the wire carries
//!   the integer.
//!
//! `build.rs` generates from `conformance-model.json`, which exercises every kind, and this crate
//! compiles the result. A shape kind that generates uncompilable code now breaks the build rather
//! than waiting for a model to use it. The tests below pin the wire forms that compiling alone does
//! not check.

#![allow(missing_docs)]

/// The actions callable on the conformance service.
pub mod action {
    include!(concat!(env!("OUT_DIR"), "/action.rs"));
}

/// Error metadata for the conformance service.
pub mod error_meta {
    include!(concat!(env!("OUT_DIR"), "/error_meta.rs"));
}

/// Operation input and output shapes.
pub mod operation {
    include!(concat!(env!("OUT_DIR"), "/operation.rs"));
}

/// General types used in the conformance service.
pub mod types {
    /// Error types.
    pub mod error {
        include!(concat!(env!("OUT_DIR"), "/types_error.rs"));
    }

    include!(concat!(env!("OUT_DIR"), "/types.rs"));
}

#[cfg(test)]
mod tests {
    use crate::types::{Choice, LevelEnum};

    #[test]
    fn int_enum_encodes_its_discriminant_not_its_name() {
        assert_eq!(serde_json::to_string(&LevelEnum::High).expect("serialize"), "9");
        assert_eq!(serde_json::from_str::<LevelEnum>("1").expect("deserialize"), LevelEnum::Low);
        assert!(serde_json::from_str::<LevelEnum>("7").is_err(), "an undeclared discriminant is not a variant");
        assert!(serde_json::from_str::<LevelEnum>("\"HIGH\"").is_err(), "the wire value is the integer");
    }

    #[test]
    fn union_is_externally_tagged_by_member_name() {
        // The Smithy member is `managedPolicy`; the Rust variant is `ManagedPolicy`. The wire form
        // has to use the member name.
        let value = Choice::ManagedPolicy("arn:aws:iam::aws:policy/ReadOnly".to_string());
        let json = r#"{"managedPolicy":"arn:aws:iam::aws:policy/ReadOnly"}"#;

        assert_eq!(serde_json::to_string(&value).expect("serialize"), json);
        assert_eq!(serde_json::from_str::<Choice>(json).expect("deserialize"), value);
    }

    #[test]
    fn a_union_can_be_a_structure_member() {
        // Compiles only if the union derives what the containing structure derives.
        let request = crate::operation::DoThingRequest::builder()
            .name("widget")
            .choice(Choice::InlinePolicy("{}".to_string()))
            .build()
            .expect("build");

        assert_eq!(request.choice, Some(Choice::InlinePolicy("{}".to_string())));
    }
}
