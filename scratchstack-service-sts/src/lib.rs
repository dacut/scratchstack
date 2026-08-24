//! Scratchstack implementation of the AWS Security Token Service (STS).

#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

pub(crate) mod authz;
pub(crate) mod constants;
pub(crate) mod operations;
pub(crate) mod service;

use {
    crate::{constants::*, service::serve_request},
    scratchstack_core::axum::Router,
    scratchstack_service_common::{ServiceDescriptor, ServiceState, query_protocol_router},
};

/// The Scratchstack implementation of the AWS Security Token Service (STS).
///
/// This is a unit struct carrying the service's [`ServiceDescriptor`] implementation; the binary
/// uses it to stand the service up without depending on anything else in this crate.
#[derive(Clone, Copy, Debug)]
pub struct StsService;

impl ServiceDescriptor for StsService {
    const DEFAULT_PORT: u16 = 7400;
    const SERVICE: &'static str = SERVICE_STS;
    const XML_NAMESPACE: &'static str = XML_NS_STS;

    fn router() -> Router<ServiceState> {
        query_protocol_router(serve_request)
    }
}
