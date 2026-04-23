use {
    crate::{Shape, ShapeBase, ShapeInfo, ShapeRef, SmithyModel},
    serde::{Deserialize, Serialize},
    std::{
        cell::RefCell,
        io::{Result as IoResult, Write},
        rc::Rc,
    },
};

/// The operation type represents the input, output, and possible errors of an API operation.
/// Operation shapes are bound to resource shapes and service shapes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    /// Basic shape information for this `Operation` type.
    #[serde(flatten)]
    pub base: ShapeBase,

    /// Defines the optional input structure of the operation. The `input` of an operation MUST
    /// resolve to a [`Structure`][crate::Shape::Structure].
    pub input: ShapeRef,

    /// The actual input shape.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip)]
    pub input_shape: Option<Rc<RefCell<Shape>>>,

    /// Defines the optional output structure of the operation. The `output` of an operation MUST
    /// resolve to a [`Structure`][crate::Shape::Structure].
    pub output: ShapeRef,

    /// The actual output shape.
    ///
    /// This is resolved during a call to `SmithyModel::resolve`.
    #[serde(skip)]
    pub output_shape: Option<Rc<RefCell<Shape>>>,

    /// Defines the list of errors that MAY be encountered when invoking the operation. Each
    /// reference MUST resolve to a [`Structure`][crate::Shape::Structure] shape that is marked with the
    /// error trait.
    #[serde(default)]
    pub errors: Vec<ShapeRef>,

    /// The actual error shapes.
    ///
    /// These are resolved during a call to `SmithyModel::resolve`.
    #[serde(skip)]
    pub error_shapes: Vec<Rc<RefCell<Shape>>>,
}

impl ShapeInfo for Operation {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        self.base.rust_typename()
    }

    fn resolve(&mut self, shape_name: &str, model: &SmithyModel) {
        self.base.resolve(shape_name);

        if let Some(input_shape) = model.get_shape(&self.input.target) {
            self.input_shape = Some(input_shape);
        }

        if let Some(output_shape) = model.get_shape(&self.output.target) {
            self.output_shape = Some(output_shape);
        }

        for error_ref in &self.errors {
            if let Some(error_shape) = model.get_shape(&error_ref.target) {
                self.error_shapes.push(error_shape);
            }
        }
    }

    fn clap_parser(&self) -> Option<String> {
        unimplemented!("clap_parser cannot be called on Operation types")
    }

    fn derive_builder_validator(&self, _: &str, _: &str) -> Option<String> {
        unimplemented!("derive_builder_validator cannot be called on Operation types")
    }

    /// Writes Rust code representing this operation's error types.
    fn generate(&self, output: &mut dyn Write) -> IoResult<()> {
        let rust_typename = self.rust_typename();
        let error_typename = format!("{rust_typename}Error");

        // Write the error type declaration for this operation
        writeln!(output, "/// Error type for the `{rust_typename}` operation")?;
        writeln!(output, "#[derive(::std::fmt::Debug)]")?;
        writeln!(output, "#[non_exhaustive]")?;
        writeln!(output, "pub enum {error_typename} {{")?;

        for error_shape in &self.error_shapes {
            let Shape::Structure(error_struct) = &*error_shape.borrow() else {
                panic!("Error shape must be a structure");
            };

            let error_rust_name = error_struct.rust_typename();
            error_struct.base.traits.write_docs(output, "    ")?;
            writeln!(output, "    {error_rust_name}({error_rust_name}),")?;
        }
        writeln!(
            output,
            "    /// An unexpected error occurred (e.g., invalid JSON returned by the service or an unknown error code)."
        )?;
        writeln!(output, "    #[allow(deprecated)]")?;
        writeln!(
            output,
            "    #[deprecated(note = \"Matching `Unhandled` directly is not forwards compatible. Instead, match using a variable wildcard pattern and check `.code()`: `if err.code() == Some(\\\"SpecificiExceptionCode\\\") => {{ /* handle the error */ }}\")]"
        )?;
        writeln!(output, "    Unhandled(crate::error::sealed_unhandled::Unhandled),")?;

        writeln!(output, "}}")?;
        Ok(())
    }
}
