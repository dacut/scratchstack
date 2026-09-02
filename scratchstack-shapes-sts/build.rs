use {
    anyhow::Result as AnyResult,
    scratchstack_shapegen::{CommonErrors, ShapeGenerator},
};

/// The Smithy namespace for STS.
const STS_NAMESPACE: &str = "com.amazonaws.sts";

fn main() -> AnyResult<()> {
    ShapeGenerator::builder()
        .namespace(STS_NAMESPACE)
        .model("sts-2011-06-15.json")
        .extensions(vec!["scratchstack-sts-ext.json".into()])
        .common_errors(CommonErrors::aws_query())
        .build()
        .run()?;

    Ok(())
}
