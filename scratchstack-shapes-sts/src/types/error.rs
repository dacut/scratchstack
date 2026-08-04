//! Error types

include!(concat!(env!("OUT_DIR"), "/types_error.rs"));

// Allow IAM error types to cast to STS error types where appropriate.
macro_rules! unified_error {
    ($ty: ident) => {
        impl From<::scratchstack_shapes_iam::types::error::$ty> for $ty {
            fn from(e: ::scratchstack_shapes_iam::types::error::$ty) -> Self {
                Self {
                    message: e.message,
                    request_id: e.request_id,
                }
            }
        }

        impl From<::std::boxed::Box<::scratchstack_shapes_iam::types::error::$ty>> for ::std::boxed::Box<$ty> {
            fn from(e: ::std::boxed::Box<::scratchstack_shapes_iam::types::error::$ty>) -> Self {
                Box::new($ty {
                    message: e.message,
                    request_id: e.request_id,
                })
            }
        }

        impl From<$ty> for ::scratchstack_shapes_iam::types::error::$ty {
            fn from(e: $ty) -> Self {
                Self {
                    message: e.message,
                    request_id: e.request_id,
                }
            }
        }

        impl From<::std::boxed::Box<$ty>> for ::std::boxed::Box<::scratchstack_shapes_iam::types::error::$ty> {
            fn from(e: ::std::boxed::Box<$ty>) -> Self {
                Box::new(::scratchstack_shapes_iam::types::error::$ty {
                    message: e.message,
                    request_id: e.request_id,
                })
            }
        }
    };
}

unified_error!(AccessDeniedException);
unified_error!(ExpiredTokenException);
unified_error!(IncompleteSignature);
unified_error!(InternalFailure);
unified_error!(InvalidParameterCombination);
unified_error!(InvalidParameterValue);
unified_error!(MalformedPolicyDocumentException);
unified_error!(MalformedQueryString);
unified_error!(MissingAction);
unified_error!(MissingAuthenticationToken);
unified_error!(MissingParameter);
unified_error!(NotAuthorized);
unified_error!(OptInRequired);
unified_error!(RequestExpired);
unified_error!(ServiceUnavailable);
unified_error!(ThrottlingException);
unified_error!(UnrecognizedClientException);
unified_error!(ValidationError);
