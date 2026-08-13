include!(concat!(env!("OUT_DIR"), "/error_meta.rs"));

// Allow IAM error types to cast to STS error types where appropriate.
impl From<::scratchstack_shapes_iam::error_meta::Error> for Error {
    fn from(e: ::scratchstack_shapes_iam::error_meta::Error) -> Self {
        use ::scratchstack_shapes_iam::error_meta::Error as IamError;
        match e {
            IamError::AccessDeniedException(inner) => Self::AccessDeniedException(inner.into()),
            IamError::ExpiredTokenException(inner) => Self::ExpiredTokenException(inner.into()),
            IamError::IncompleteSignature(inner) => Self::IncompleteSignature(inner.into()),
            IamError::InternalFailure(inner) => Self::InternalFailure(inner.into()),
            IamError::InvalidParameterCombination(inner) => Self::InvalidParameterCombination(inner.into()),
            IamError::InvalidParameterValue(inner) => Self::InvalidParameterValue(inner.into()),
            IamError::MalformedPolicyDocumentException(inner) => Self::MalformedPolicyDocumentException(inner.into()),
            IamError::MalformedQueryString(inner) => Self::MalformedQueryString(inner.into()),
            IamError::MissingAction(inner) => Self::MissingAction(inner.into()),
            IamError::MissingAuthenticationToken(inner) => Self::MissingAuthenticationToken(inner.into()),
            IamError::MissingParameter(inner) => Self::MissingParameter(inner.into()),
            IamError::NotAuthorized(inner) => Self::NotAuthorized(inner.into()),
            IamError::OptInRequired(inner) => Self::OptInRequired(inner.into()),
            IamError::RequestExpired(inner) => Self::RequestExpired(inner.into()),
            IamError::ServiceUnavailable(inner) => Self::ServiceUnavailable(inner.into()),
            IamError::ThrottlingException(inner) => Self::ThrottlingException(inner.into()),
            IamError::UnrecognizedClientException(inner) => Self::UnrecognizedClientException(inner.into()),
            IamError::ValidationError(inner) => Self::ValidationError(inner.into()),
            _ => {
                use ::scratchstack_core::error::ProvideErrorMetadata as _;
                Self::Unhandled(
                    ::scratchstack_core::error::GenericError::builder()
                        .code(e.code())
                        .maybe_message(e.message().map(::std::string::ToString::to_string))
                        .maybe_http_status(e.http_status())
                        .maybe_request_id(
                            ::scratchstack_core::ProvideRequestId::request_id(&e)
                                .map(::std::string::ToString::to_string),
                        )
                        .build(),
                )
            }
        }
    }
}

// Allow STS error meta to be converted to IAM error meta where appropriate.
impl From<Error> for ::scratchstack_shapes_iam::error_meta::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::AccessDeniedException(inner) => Self::AccessDeniedException(inner.into()),
            Error::ExpiredTokenException(inner) => Self::ExpiredTokenException(inner.into()),
            Error::IncompleteSignature(inner) => Self::IncompleteSignature(inner.into()),
            Error::InternalFailure(inner) => Self::InternalFailure(inner.into()),
            Error::InvalidParameterCombination(inner) => Self::InvalidParameterCombination(inner.into()),
            Error::InvalidParameterValue(inner) => Self::InvalidParameterValue(inner.into()),
            Error::MalformedPolicyDocumentException(inner) => Self::MalformedPolicyDocumentException(inner.into()),
            Error::MalformedQueryString(inner) => Self::MalformedQueryString(inner.into()),
            Error::MissingAction(inner) => Self::MissingAction(inner.into()),
            Error::MissingAuthenticationToken(inner) => Self::MissingAuthenticationToken(inner.into()),
            Error::MissingParameter(inner) => Self::MissingParameter(inner.into()),
            Error::NotAuthorized(inner) => Self::NotAuthorized(inner.into()),
            Error::OptInRequired(inner) => Self::OptInRequired(inner.into()),
            Error::RequestExpired(inner) => Self::RequestExpired(inner.into()),
            Error::ServiceUnavailable(inner) => Self::ServiceUnavailable(inner.into()),
            Error::ThrottlingException(inner) => Self::ThrottlingException(inner.into()),
            Error::UnrecognizedClientException(inner) => Self::UnrecognizedClientException(inner.into()),
            Error::ValidationError(inner) => Self::ValidationError(inner.into()),
            _ => {
                ::log::error!("Converting unhandled STS error to IAM error: {:?}", e);
                Self::InternalFailure(Box::new(
                    ::scratchstack_shapes_iam::types::error::InternalFailure::builder()
                        .message("An internal error has occurred")
                        .build(),
                ))
            }
        }
    }
}

macro_rules! from_iam {
    ($ty: ident) => {
        impl From<::scratchstack_shapes_iam::types::error::$ty> for Error {
            fn from(e: ::scratchstack_shapes_iam::types::error::$ty) -> Self {
                Self::$ty(Box::new(crate::types::error::$ty {
                    message: e.message,
                    request_id: e.request_id,
                }))
            }
        }
    };
}

from_iam!(AccessDeniedException);
from_iam!(ExpiredTokenException);
from_iam!(IncompleteSignature);
from_iam!(InternalFailure);
from_iam!(InvalidParameterCombination);
from_iam!(InvalidParameterValue);
from_iam!(MalformedPolicyDocumentException);
from_iam!(MalformedQueryString);
from_iam!(MissingAction);
from_iam!(MissingAuthenticationToken);
from_iam!(MissingParameter);
from_iam!(NotAuthorized);
from_iam!(OptInRequired);
from_iam!(RequestExpired);
from_iam!(ServiceUnavailable);
from_iam!(ThrottlingException);
from_iam!(UnrecognizedClientException);
from_iam!(ValidationError);
