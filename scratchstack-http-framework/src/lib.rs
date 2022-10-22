#![warn(clippy::all)]
#![deny(rustdoc::missing_crate_level_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]

//! This crate provides a set of utilities for writing an AWS-like service that uses SigV4 authentication and Aspen
//! (AWS IAM) authorization.

/// For services that have direct access to the authentication database, this module provides a GetSigningKeyProvider
/// implementation that queries the database for the secret key and converts it to a signing key.
#[cfg(feature = "gsk_direct")]
pub mod gsk_direct;

mod request_id;
mod service_spawn;
mod sigv4;
mod tls;

pub use {
    request_id::RequestId,
    service_spawn::{SpawnService, SpawnServiceBuilder},
    sigv4::{
        AwsSigV4VerifierService, AwsSigV4VerifierServiceBuilder, AwsSigV4VerifierServiceBuilderError, ErrorMapper,
        XmlErrorMapper,
    },
    tls::TlsIncoming,
};

#[cfg(feature = "gsk_direct")]
pub use gsk_direct::GetSigningKeyFromDatabase;
