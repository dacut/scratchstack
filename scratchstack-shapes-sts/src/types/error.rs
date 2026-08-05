//! Error types

pub(crate) mod sealed_unhandled {
    /// This struct is not intended to be used.
    ///
    /// This struct holds information about an unhandled error,
    /// but that information should be obtained by using the
    /// [`ProvideErrorMetadata`](::aws_smithy_types::error::metadata::ProvideErrorMetadata) trait
    /// on the error type.
    ///
    /// This struct intentionally doesn't yield any useful information itself.
    #[deprecated(note = "Matching `Unhandled` directly is not forwards compatible. Instead, match using a \
    variable wildcard pattern and check `.code()`:
    \
    &nbsp;&nbsp;&nbsp;`err if err.code() == Some(\"SpecificExceptionCode\") => { /* handle the error */ }`
    \
    See [`ProvideErrorMetadata`](::aws_smithy_types::error::metadata::ProvideErrorMetadata) for what information is available for the error.")]
    #[derive(Debug)]
    pub struct Unhandled {
        #[allow(dead_code)]
        pub(crate) source: ::aws_smithy_runtime_api::box_error::BoxError,
        #[allow(dead_code)]
        pub(crate) meta: ::aws_smithy_types::error::metadata::ErrorMetadata,
    }
}

include!(concat!(env!("OUT_DIR"), "/types_error.rs"));

// Allow IAM error types to cast to STS error types where appropriate.
macro_rules! unified_error {
    ($ty: ident) => {
        impl From<::scratchstack_shapes_iam::types::error::$ty> for $ty {
            fn from(e: ::scratchstack_shapes_iam::types::error::$ty) -> Self {
                Self {
                    meta: e.meta,
                }
            }
        }

        impl From<::std::boxed::Box<::scratchstack_shapes_iam::types::error::$ty>> for ::std::boxed::Box<$ty> {
            fn from(e: ::std::boxed::Box<::scratchstack_shapes_iam::types::error::$ty>) -> Self {
                Box::new($ty {
                    meta: e.meta,
                })
            }
        }

        impl From<$ty> for ::scratchstack_shapes_iam::types::error::$ty {
            fn from(e: $ty) -> Self {
                Self {
                    meta: e.meta,
                }
            }
        }

        impl From<::std::boxed::Box<$ty>> for ::std::boxed::Box<::scratchstack_shapes_iam::types::error::$ty> {
            fn from(e: ::std::boxed::Box<$ty>) -> Self {
                Box::new(::scratchstack_shapes_iam::types::error::$ty {
                    meta: e.meta,
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
