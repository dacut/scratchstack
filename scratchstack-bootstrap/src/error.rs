use {
    crate::MSG_INTERNAL_FAILURE,
    scratchstack_core::{ErrorType, ProvideErrorMetadata, RequestId, http::StatusCode},
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError, types::error::InternalFailure as CloudInternalFailure,
    },
    scratchstack_shapes_iam::{error_meta::Error as IamError, types::error::InternalFailure as IamInternalFailure},
    scratchstack_shapes_sts::{error_meta::Error as StsError, types::error::InternalFailure as StsInternalFailure},
    std::{
        error::Error as StdError,
        fmt::{Display, Formatter, Result as FmtResult},
    },
};

/// Error wrapper that can hold any of the supported error types (CloudError, IamError, StsError).
#[derive(Debug)]
pub(crate) enum ErrorWrapper {
    Cloud(CloudError),
    Iam(IamError),
    Sts(StsError),
}

impl From<CloudError> for ErrorWrapper {
    fn from(err: CloudError) -> Self {
        ErrorWrapper::Cloud(err)
    }
}

impl From<IamError> for ErrorWrapper {
    fn from(err: IamError) -> Self {
        ErrorWrapper::Iam(err)
    }
}

impl From<StsError> for ErrorWrapper {
    fn from(err: StsError) -> Self {
        ErrorWrapper::Sts(err)
    }
}

impl Display for ErrorWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ErrorWrapper::Cloud(err) => write!(f, "Cloud error: {}", err),
            ErrorWrapper::Iam(err) => write!(f, "IAM error: {}", err),
            ErrorWrapper::Sts(err) => write!(f, "STS error: {}", err),
        }
    }
}

impl ProvideErrorMetadata for ErrorWrapper {
    fn error_type(&self) -> ErrorType {
        match self {
            ErrorWrapper::Cloud(err) => err.error_type(),
            ErrorWrapper::Iam(err) => err.error_type(),
            ErrorWrapper::Sts(err) => err.error_type(),
        }
    }

    fn code(&self) -> &str {
        match self {
            ErrorWrapper::Cloud(err) => err.code(),
            ErrorWrapper::Iam(err) => err.code(),
            ErrorWrapper::Sts(err) => err.code(),
        }
    }

    fn message(&self) -> Option<&str> {
        match self {
            ErrorWrapper::Cloud(err) => err.message(),
            ErrorWrapper::Iam(err) => err.message(),
            ErrorWrapper::Sts(err) => err.message(),
        }
    }

    fn http_status(&self) -> Option<StatusCode> {
        match self {
            ErrorWrapper::Cloud(err) => err.http_status(),
            ErrorWrapper::Iam(err) => err.http_status(),
            ErrorWrapper::Sts(err) => err.http_status(),
        }
    }
}

impl StdError for ErrorWrapper {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ErrorWrapper::Cloud(err) => Some(err),
            ErrorWrapper::Iam(err) => Some(err),
            ErrorWrapper::Sts(err) => Some(err),
        }
    }
}

/// Trait for types that can create an internal failure error.
pub(crate) trait CreateInternalFailure {
    /// Create an internal failure error.
    fn create_internal_failure(request_id: RequestId) -> Self;
}

impl CreateInternalFailure for CloudInternalFailure {
    #[inline(always)]
    fn create_internal_failure(request_id: RequestId) -> Self {
        CloudInternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build()
    }
}

impl CreateInternalFailure for CloudError {
    #[inline(always)]
    fn create_internal_failure(request_id: RequestId) -> Self {
        CloudInternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build().into()
    }
}

impl CreateInternalFailure for IamInternalFailure {
    #[inline(always)]
    fn create_internal_failure(request_id: RequestId) -> Self {
        IamInternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build()
    }
}

impl CreateInternalFailure for IamError {
    #[inline(always)]
    fn create_internal_failure(request_id: RequestId) -> Self {
        IamInternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build().into()
    }
}

impl CreateInternalFailure for StsInternalFailure {
    #[inline(always)]
    fn create_internal_failure(request_id: RequestId) -> Self {
        StsInternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build()
    }
}

impl CreateInternalFailure for StsError {
    fn create_internal_failure(request_id: RequestId) -> Self {
        StsInternalFailure::builder().message(MSG_INTERNAL_FAILURE).request_id(request_id).build().into()
    }
}
