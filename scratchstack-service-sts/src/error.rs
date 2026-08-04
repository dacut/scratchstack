use {
    crate::constants::*,
    axum::Error as AxumError,
    scratchstack_aws_signature::SignatureError,
    scratchstack_shapes_sts::types::error::InternalFailure as StsInternalFailure,
    sqlx::Error as SqlxError,
    std::{
        error::Error,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        io::Error as IOError,
    },
};

#[derive(Debug)]
pub(crate) enum ServiceError {
    Axum(AxumError),
    IO(IOError),
    SignatureError(SignatureError),
    SqlxError(SqlxError),
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Axum(e) => Some(e),
            Self::IO(e) => Some(e),
            Self::SignatureError(e) => Some(e),
            Self::SqlxError(e) => Some(e),
        }
    }
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Axum(e) => write!(f, "Axum error: {e}"),
            Self::IO(e) => write!(f, "IO error: {e}"),
            Self::SignatureError(e) => write!(f, "Signature error: {e}"),
            Self::SqlxError(e) => write!(f, "Sqlx error: {e}"),
        }
    }
}

impl From<AxumError> for ServiceError {
    fn from(e: AxumError) -> Self {
        Self::Axum(e)
    }
}

impl From<IOError> for ServiceError {
    fn from(e: IOError) -> Self {
        Self::IO(e)
    }
}

impl From<SignatureError> for ServiceError {
    fn from(e: SignatureError) -> Self {
        Self::SignatureError(e)
    }
}

impl From<SqlxError> for ServiceError {
    fn from(e: SqlxError) -> Self {
        Self::SqlxError(e)
    }
}

/// Construct a generic `InternalFailure` with the standard internal-failure message. Use
/// this for every "unexpected database/builder/etc. error" call site — never leak
/// underlying details to the caller (those go to the log).
#[allow(dead_code)]
pub(crate) fn internal_failure() -> StsInternalFailure {
    StsInternalFailure::builder().message(MSG_INTERNAL_FAILURE).build()
}
