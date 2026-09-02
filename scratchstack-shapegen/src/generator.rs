//! The build-script entry point.

use {
    crate::{
        CliShorthand, CommonErrors, DerivedStructs, DocRewrite, PatternRewrite, SmithyModel, Writers, merge_extension,
    },
    bon::bon,
    std::{
        env::var_os,
        fs::File,
        io::{BufReader, Error as IoError, Result as IoResult},
        path::{Path, PathBuf},
    },
};

/// Generates Rust shapes for one service, from one Smithy model plus whatever patches it needs.
///
/// A build script declares its inputs and transformations and calls [`run`][Self::run]; the ordering
/// of the pipeline is fixed here rather than restated by each caller:
///
/// 1. parse the base model and add Smithy's built-in shapes,
/// 2. apply pattern rewrites, then documentation rewrites,
/// 3. derive additional structures from operation inputs,
/// 4. merge extension models,
/// 5. synthesize common errors,
/// 6. resolve, and generate.
///
/// Derivation precedes the extension merge, so extension operations do not acquire derived
/// structures; common errors follow it, so extension operations do get them.
///
/// ```no_run
/// # use scratchstack_shapegen::{CommonErrors, ShapeGenerator};
/// # fn main() -> std::io::Result<()> {
/// ShapeGenerator::builder()
///     .namespace("com.amazonaws.sts")
///     .model("sts-2011-06-15.json")
///     .extensions(vec!["scratchstack-sts-ext.json".into()])
///     .common_errors(CommonErrors::aws_query())
///     .build()
///     .run()
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ShapeGenerator {
    cli_shorthand: CliShorthand,
    common_errors: CommonErrors,
    derived_structs: Option<DerivedStructs>,
    doc_rewrites: Vec<DocRewrite>,
    extensions: Vec<PathBuf>,
    model: PathBuf,
    namespace: String,
    out_dir: Option<PathBuf>,
    pattern_rewrites: Vec<PatternRewrite>,
}

#[bon]
impl ShapeGenerator {
    /// Returns a [`ShapeGeneratorBuilder`].
    ///
    /// # Fields
    ///
    /// * `namespace`: the Smithy namespace of the service, such as `com.amazonaws.iam`. Transforms
    ///   that create or scan shapes are scoped to it.
    /// * `model`: path to the base Smithy model, relative to the crate root.
    /// * `extensions`: additional models merged over the base, in order.
    /// * `cli_shorthand`: which shapes get CLI shorthand parsers. Defaults to value types only.
    /// * `common_errors`: errors to attach to every operation. Defaults to none.
    /// * `derived_structs`: a rule for deriving extra structures from operation inputs.
    /// * `doc_rewrites`: repairs to documentation rustdoc will not accept.
    /// * `pattern_rewrites`: replacements for regular expressions `regex` cannot compile.
    /// * `out_dir`: where to write the generated files. Defaults to `$OUT_DIR`.
    #[builder(builder_type = ShapeGeneratorBuilder, finish_fn = build)]
    pub fn builder(
        #[builder(into)] namespace: String,
        #[builder(into)] model: PathBuf,
        #[builder(default)] extensions: Vec<PathBuf>,
        #[builder(default)] cli_shorthand: CliShorthand,
        #[builder(default = CommonErrors::none())] common_errors: CommonErrors,
        derived_structs: Option<DerivedStructs>,
        #[builder(default)] doc_rewrites: Vec<DocRewrite>,
        #[builder(default)] pattern_rewrites: Vec<PatternRewrite>,
        out_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            cli_shorthand,
            common_errors,
            derived_structs,
            doc_rewrites,
            extensions,
            model,
            namespace,
            out_dir,
            pattern_rewrites,
        }
    }

    /// Runs the pipeline, writing the generated modules into the output directory.
    ///
    /// # Errors
    ///
    /// Returns an error if an input cannot be read or parsed, if an extension model is empty, or if
    /// writing the output fails. Inconsistencies within the model itself -- a member targeting a
    /// shape that is not there, an error shape with no status code -- panic instead, naming the
    /// shape at fault: they are not conditions a build script can respond to.
    pub fn run(self) -> IoResult<()> {
        // Emitting any rerun-if-changed narrows cargo's watch set to exactly what is listed, so
        // build.rs has to name itself here too. Emit before doing any work, so a failing run still
        // registers its inputs and a fixed model file triggers a retry.
        println!("cargo::rerun-if-changed=build.rs");
        println!("cargo::rerun-if-changed={}", self.model.display());
        for extension in &self.extensions {
            println!("cargo::rerun-if-changed={}", extension.display());
        }

        let mut model = load_model(&self.model)?;
        model.add_default_shapes();

        for rewrite in &self.pattern_rewrites {
            rewrite.apply(&mut model);
        }

        for rewrite in &self.doc_rewrites {
            rewrite.apply(&mut model);
        }

        if let Some(derived) = &self.derived_structs {
            derived.apply(&mut model, &self.namespace);
        }

        for extension in &self.extensions {
            let parsed = load_model(extension)?;
            merge_extension(&mut model, parsed, &extension.display().to_string())?;
        }

        self.common_errors.apply(&mut model, &self.namespace);

        model.cli_shorthand = self.cli_shorthand;
        model.resolve();

        let out_dir = match self.out_dir {
            Some(dir) => dir,
            None => PathBuf::from(
                var_os("OUT_DIR").ok_or_else(|| IoError::other("OUT_DIR is not set; run this from a build script"))?,
            ),
        };

        let mut writers = Writers::create_in(&out_dir)?;
        model.generate(&mut writers)?;

        // BufWriter flushes on drop but discards the error, which would truncate a generated file
        // and leave the failure to surface as a baffling syntax error in the consuming crate.
        writers.flush()
    }
}

/// Reads and parses a Smithy model, naming the file in any error.
fn load_model(path: &Path) -> IoResult<SmithyModel> {
    let file = File::open(path)
        .map_err(|e| IoError::new(e.kind(), format!("could not open model {}: {e}", path.display())))?;
    serde_json::from_reader(BufReader::new(file))
        .map_err(|e| IoError::other(format!("could not parse model {}: {e}", path.display())))
}
