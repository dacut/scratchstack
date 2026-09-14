use {
    anyhow::Result as AnyResult,
    scratchstack_shapegen::{CommonErrors, ShapeGenerator},
};

/// The Smithy namespace for the Scratchstack Cloud Service.
const CLOUD_NAMESPACE: &str = "net.scratchstack.cloud";

fn main() -> AnyResult<()> {
    ShapeGenerator::builder()
        .namespace(CLOUD_NAMESPACE)
        .model("cloud-2026-09-03.json")
        .common_errors(CommonErrors::aws_standard())
        .build()
        .run()?;

    Ok(())
}
