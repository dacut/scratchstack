//! Scratchstack bootstrap cloud subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    bigdecimal::BigDecimal,
    clap::Parser,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        operation::{CreateQuotaDefinitionRequest, CreateQuotaDefinitionResponse},
        types::QuotaScope,
    },
};

/// Create a new quota definition for a service.
#[derive(Debug, Parser)]
pub(crate) struct CreateQuotaDefinitionCommand {
    /// The service this quota is scoped to.
    #[clap(long)]
    pub service_id: String,

    /// The name of the quota.
    #[clap(long)]
    pub quota_name: String,

    /// The scope of the quota, either Global or Regional.
    #[clap(long)]
    pub scope: QuotaScope,

    /// Description of the quota.
    #[clap(long)]
    pub description: Option<String>,

    /// Default value of the quota.
    #[clap(long)]
    pub default_value: Option<BigDecimal>,

    /// The unit of quota values.
    #[clap(long)]
    pub unit: String,

    /// The maximum value of the quota.
    #[clap(long)]
    pub max_value: Option<BigDecimal>,

    /// The minimum value of the quota.
    #[clap(long)]
    pub min_value: Option<BigDecimal>,
}

impl Runnable for CreateQuotaDefinitionCommand {
    type Result = CreateQuotaDefinitionResponse;
    type Error = CloudError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let request = CreateQuotaDefinitionRequest::builder()
            .service_id(&self.service_id)
            .quota_name(&self.quota_name)
            .scope(self.scope)
            .set_description(self.description.clone())
            .set_default_value(self.default_value.clone())
            .unit(&self.unit)
            .set_max_value(self.max_value.clone())
            .set_min_value(self.min_value.clone())
            .build()?;

        execute_in_transaction(cli, vars, &request).await
    }
}
