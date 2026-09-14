use {
    anyhow::Result as AnyResult,
    scratchstack_shapegen::{CommonErrors, ShapeGenerator},
};

/// The Smithy namespace for the Scratchstack Access Service.
const ACCESS_NAMESPACE: &str = "net.scratchstack.access";

fn main() -> AnyResult<()> {
    ShapeGenerator::builder()
        .namespace(ACCESS_NAMESPACE)
        .model("access-2026-09-03.json")
        .common_errors(CommonErrors::aws_standard())
        .build()
        .run()?;

    Ok(())
}
