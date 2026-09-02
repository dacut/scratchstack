use {
    anyhow::Result as AnyResult,
    scratchstack_shapegen::{CommonErrors, DocRewrite, ShapeGenerator},
};

/// The Smithy namespace for STS.
const STS_NAMESPACE: &str = "com.amazonaws.sts";

/// Shapes whose member documentation rustdoc will not accept as written.
const STS_PROBLEMATIC_HTML_SHAPE_IDS: &[&str] = &["com.amazonaws.sts#AssumeRootRequest"];

/// A stray blank line inside a `<p>` element in `AssumeRootRequest`'s `TaskPolicyArn` docs.
///
/// Each line of model documentation becomes its own `///`, so a whitespace-only line becomes an
/// empty one. CommonMark reads that as a paragraph break, which closes the enclosing HTML block
/// early and leaves the `</p>` and the `<ul>` after it dangling -- rustdoc reports an "improperly
/// nested Markdown paragraph". Joining the sentence is what AWS meant in the first place.
const STS_SPLIT_PARAGRAPH: &str = "You must\n         \n         use one of";

/// The replacement for [`STS_SPLIT_PARAGRAPH`].
const STS_SPLIT_PARAGRAPH_REPLACEMENT: &str = "You must use one of";

fn main() -> AnyResult<()> {
    ShapeGenerator::builder()
        .namespace(STS_NAMESPACE)
        .model("sts-2011-06-15.json")
        .extensions(vec!["scratchstack-sts-ext.json".into()])
        .common_errors(CommonErrors::aws_query())
        .doc_rewrites(vec![
            DocRewrite::new(STS_PROBLEMATIC_HTML_SHAPE_IDS)
                .replacing(STS_SPLIT_PARAGRAPH, STS_SPLIT_PARAGRAPH_REPLACEMENT),
        ])
        .build()
        .run()?;

    Ok(())
}
