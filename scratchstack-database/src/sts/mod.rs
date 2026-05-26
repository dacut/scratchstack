//! Database operations for the Scratchstack STS database implementation.
//!
//! All operations take database transactions, allowing these operations to be used in larger
//! transactions as needed. Any returned results are subject to the transaction being committed.
//! Do **not** use results until the commit has been completed.
#![allow(unused)] // TODO: Remove once STS operations are implemented

use {
    crate::constants::sts::*,
    scratchstack_pagination::{
        FixedKeyService, OperationPaginator, ScratchstackOperationMetadata, ScratchstackServiceMetadata,
    },
    scratchstack_shapes_sts::{
        error_meta::Error as StsError,
        types::error::{InternalFailure, ValidationError},
    },
};

/// Ensure that the max_items parameter is valid, converting it to a usize if it is.
pub(crate) fn constrain_max_items(max_items: Option<i32>) -> Result<usize, ValidationError> {
    if let Some(max_items) = max_items {
        if max_items <= 0 {
            let message = "max_items must be a positive integer.".to_string();
            Err(ValidationError::builder().message(message).build())
        } else if max_items > 1000 {
            let message = "max_items must be at most 1000.".to_string();
            Err(ValidationError::builder().message(message).build())
        } else {
            Ok(max_items as usize)
        }
    } else {
        Ok(100)
    }
}

/// Construct an `OperationPaginator` for a policy-related list operation.
pub(crate) fn make_paginator(
    partition: &str,
    operation_name: &'static str,
) -> Result<OperationPaginator<FixedKeyService, FixedKeyService>, StsError> {
    let service_metadata = ScratchstackServiceMetadata::new(partition.to_string(), "", SERVICE_ID_STS);
    let operation_metadata = ScratchstackOperationMetadata::new(STS_API_VERSION, operation_name);
    OperationPaginator::new_fixed_key(&service_metadata, &operation_metadata, PAGINATION_KEY_ID, *PAGINATION_KEY)
        .map_err(|e| {
            log::error!("Failed to create paginator for {operation_name}: {e}");
            StsError::from(InternalFailure::builder().message(MSG_INTERNAL_FAILURE).build())
        })
}
