use {
    crate::{Shape, ShapeBase, ShapeInfo, ShapeRef, SmithyModel, Writers},
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

    /// The XML namespace for the service.
    #[serde(skip)]
    pub xmlns: Option<String>,
}

impl ShapeInfo for Operation {
    fn smithy_name(&self) -> String {
        self.base.smithy_name()
    }

    fn rust_typename(&self) -> String {
        format!("crate::operation::{}", self.base.rust_typename())
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

        self.xmlns = model.xmlns.clone();
    }

    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let output_shape = self.output_shape.as_ref().unwrap().borrow();
        let output_typename = output_shape.rust_typename();

        // Envelope struct definition
        writeln!(w.operation, "/// Response wire type for the {rust_typename} operation")?;
        writeln!(w.operation, "#[derive(::bon::Builder, ::std::clone::Clone, ::std::fmt::Debug)]")?;
        writeln!(w.operation, "pub struct {rust_typename}ResponseEnvelope {{")?;
        if !output_shape.is_unit() {
            writeln!(w.operation, "    /// Result from the {rust_typename} operation")?;
            writeln!(w.operation, "    pub result: {output_typename},")?;
            writeln!(w.operation)?;
        }
        writeln!(w.operation, "    /// Associated request id for the operation")?;
        writeln!(w.operation, "    #[builder(into)]")?;
        writeln!(w.operation, "    pub request_id: ::std::option::Option<::std::string::String>,")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // Envelope Serialize impl
        writeln!(w.operation, "impl ::serde::Serialize for {rust_typename}ResponseEnvelope {{")?;
        writeln!(w.operation, "    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>")?;
        writeln!(w.operation, "    where")?;
        writeln!(w.operation, "        S: ::serde::ser::Serializer,")?;
        writeln!(w.operation, "    {{")?;
        writeln!(w.operation, "        use ::serde::ser::SerializeMap as _;")?;
        writeln!(w.operation, "        let mut m = serializer.serialize_map(None)?;")?;
        writeln!(w.operation, "        m.serialize_entry(\"@xmlns\", \"{}\")?;", self.xmlns.as_ref().unwrap())?;
        if !output_shape.is_unit() {
            writeln!(w.operation, "        m.serialize_entry(\"{rust_typename}Result\", &self.result)?;")?;
        } else {
            writeln!(w.operation, "        m.serialize_entry(\"{rust_typename}Result\", &())?;")?;
        }
        writeln!(w.operation, "        if let Some(request_id) = &self.request_id {{")?;
        writeln!(w.operation, "            m.serialize_entry(\"RequestId\", request_id)?;")?;
        writeln!(w.operation, "        }}")?;
        writeln!(w.operation, "        m.end()")?;
        writeln!(w.operation, "    }}")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // Envelope Responder impl
        writeln!(w.operation, "impl ::scratchstack_core::response::Responder for {rust_typename}ResponseEnvelope {{")?;
        writeln!(
            w.operation,
            "    fn respond(&self) -> ::scratchstack_core::http::Response<::scratchstack_core::axum::body::Body> {{"
        )?;
        writeln!(
            w.operation,
            "        ::scratchstack_core::response::xml_response(self, ::scratchstack_core::http::StatusCode::OK)"
        )?;
        writeln!(w.operation, "    }}")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // Envelope ProvideRequestId impl
        writeln!(w.operation, "impl ::scratchstack_core::ProvideRequestId for {rust_typename}ResponseEnvelope {{")?;
        writeln!(w.operation, "    fn request_id(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w.operation, "        self.request_id.as_deref()")?;
        writeln!(w.operation, "    }}")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // Envelope ProvideXmlNamespace impl
        writeln!(w.operation, "impl ::scratchstack_core::ProvideXmlNamespace for {rust_typename}ResponseEnvelope {{")?;
        writeln!(w.operation, "    fn xml_namespace(&self) -> &str {{")?;
        writeln!(w.operation, "        \"{}\"", self.xmlns.as_ref().unwrap())?;
        writeln!(w.operation, "    }}")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        Ok(())
    }

    fn derive_builder_validator(&self, _: &str, _: &str) -> Option<String> {
        unimplemented!("derive_builder_validator cannot be called on Operation types")
    }
}
