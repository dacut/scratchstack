use {
    anyhow::Result as AnyResult,
    scratchstack_shapegen::{CommonErrors, ShapeGenerator},
};

fn main() -> AnyResult<()> {
    ShapeGenerator::builder()
        .namespace("com.example")
        .model("conformance-model.json")
        .common_errors(CommonErrors::aws_query())
        .build()
        .run()?;

    Ok(())
}
