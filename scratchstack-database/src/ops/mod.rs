//! Operations on the Scratchstack database.
use {anyhow::Result as AnyResult, futures::Future, serde::Serialize, sqlx::postgres::PgTransaction};

/// Operations related to Identity and Access Management (IAM).
#[cfg(feature = "iam")]
pub mod iam;

/// Trait that all request types implement to be executed and return a response.
pub trait RequestExecutor {
    /// The type of response returned by this request.
    type Response: Serialize + Send + 'static;

    /// Execute the request and return the response. The transaction is not committed, so any
    /// returned results are subject to the transaction being committed. Do **not** use results
    /// until the commit has been completed.
    fn execute(&self, tx: &mut PgTransaction<'_>) -> impl Future<Output = AnyResult<Self::Response>>;
}
