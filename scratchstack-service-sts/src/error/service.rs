use {
    hyper::Error as HyperError,
    scratchstack_aws_signature::SignatureError,
    sqlx::Error as SqlxError,
    std::{
        error::Error,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        io::Error as IOError,
    },
};

#[derive(Debug)]
pub(crate) enum ServiceError {
    Hyper(HyperError),
    IO(IOError),
    SignatureError(SignatureError),
    SqlxError(SqlxError),
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hyper(e) => Some(e),
            Self::IO(e) => Some(e),
            Self::SignatureError(e) => Some(e),
            Self::SqlxError(e) => Some(e),
        }
    }
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::Hyper(e) => write!(f, "Hyper error: {e}"),
            Self::IO(e) => write!(f, "IO error: {e}"),
            Self::SignatureError(e) => write!(f, "Signature error: {e}"),
            Self::SqlxError(e) => write!(f, "Sqlx error: {e}"),
        }
    }
}

impl From<HyperError> for ServiceError {
    fn from(e: HyperError) -> Self {
        Self::Hyper(e)
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
