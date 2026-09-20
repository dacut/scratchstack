//! Scratchstack bootstrap cloud subcommands
use {
    crate::{Cli, Runnable, execute_in_transaction},
    bigdecimal::BigDecimal,
    clap::Parser,
    scratchstack_shapes_cloud::{
        error_meta::Error as CloudError,
        operation::{
            CreateQuotaDefinitionRequest, CreateQuotaDefinitionResponse, CreateQuotaUnitRequest,
            CreateQuotaUnitResponse, CreateRegionRequest, CreateRegionResponse, CreateServiceRequest,
            CreateServiceResponse,
        },
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

/// Create a new unit for quotas.
#[derive(Debug, Parser)]
pub(crate) struct CreateQuotaUnitCommand {
    /// The name of the unit.
    #[clap(long)]
    pub unit: String,
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

impl Runnable for CreateQuotaUnitCommand {
    type Result = CreateQuotaUnitResponse;
    type Error = CloudError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let request = CreateQuotaUnitRequest::builder().unit(&self.unit).build()?;

        execute_in_transaction(cli, vars, &request).await
    }
}

/// Create a new region.
#[derive(Debug, Parser)]
pub(crate) struct CreateRegionCommand {
    /// The name of the region.
    #[clap(long)]
    pub region_name: String,
}

impl Runnable for CreateRegionCommand {
    type Result = CreateRegionResponse;
    type Error = CloudError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let request = CreateRegionRequest::builder().region_name(&self.region_name).build()?;

        execute_in_transaction(cli, vars, &request).await
    }
}

/// Create a new service.
#[derive(Debug, Parser)]
pub(crate) struct CreateServiceCommand {
    /// The short identifier for the service.
    #[clap(long)]
    pub service_id: String,

    /// The DNS name of the service.
    #[clap(long)]
    pub service_dns_name: String,

    /// The description of the service.
    #[clap(long)]
    pub description: Option<String>,
}

impl Runnable for CreateServiceCommand {
    type Result = CreateServiceResponse;
    type Error = CloudError;

    async fn run<I>(&self, cli: &Cli, vars: I) -> Result<Self::Result, Self::Error>
    where
        I: IntoIterator<Item = (std::ffi::OsString, String)> + Clone + Send,
    {
        let request = CreateServiceRequest::builder()
            .service_id(&self.service_id)
            .service_dns_name(&self.service_dns_name)
            .set_description(self.description.clone())
            .build()?;

        execute_in_transaction(cli, vars, &request).await
    }
}
