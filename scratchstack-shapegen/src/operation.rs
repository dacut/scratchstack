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

    /// The XML namespace of the service this operation belongs to.
    ///
    /// This is copied from the model during a call to `resolve`.
    #[serde(skip, default)]
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

        self.xmlns.clone_from(&model.xmlns);
    }

    /// Generates the response envelope for this operation.
    ///
    /// AWS query-protocol services wrap operation output in an
    /// `<{Operation}Response xmlns="..."><{Operation}Result>...</{Operation}Result><RequestId>...`
    /// envelope. The result shape itself is generated as an ordinary structure; this adds the
    /// wrapper around it.
    fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        let rust_typename = self.base.rust_typename();
        let xmlns = self.xmlns.as_deref().expect("XML namespace must be resolved before generating");
        // An operation with no output shape, or one whose output is the Smithy unit type, has no
        // result element -- the envelope is just the namespace and the request id.
        let output_shape = self.output_shape.as_ref().map(|shape| shape.borrow());
        let output_shape = output_shape.as_deref().filter(|shape| !shape.is_unit());
        let output_typename = output_shape.map(ShapeInfo::rust_typename);

        // Envelope struct
        writeln!(w.operation, "/// Response wire type for the {rust_typename} operation.")?;
        writeln!(w.operation, "#[derive(::bon::Builder, ::std::clone::Clone, ::std::fmt::Debug)]")?;
        writeln!(w.operation, "pub struct {rust_typename}ResponseEnvelope {{")?;
        if let Some(output_typename) = &output_typename {
            writeln!(w.operation, "    /// The result of the {rust_typename} operation.")?;
            writeln!(w.operation, "    pub result: {output_typename},")?;
            writeln!(w.operation)?;
        }
        writeln!(w.operation, "    /// The request id associated with the request, if available.")?;
        writeln!(w.operation, "    #[builder(into)]")?;
        writeln!(w.operation, "    pub request_id: ::std::option::Option<::std::string::String>,")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // Serialize impl.
        //
        // This has to be `serialize_struct`, not `serialize_map`: quick-xml takes the root element
        // name from the struct name, and refuses to serialize a map at the top level ("cannot
        // serialize map without defined root tag"). The name given here is the wire name --
        // `<{Operation}Response>` -- not the Rust type name.
        let field_count = if output_typename.is_some() {
            3
        } else {
            2
        };
        writeln!(w.operation, "impl ::serde::Serialize for {rust_typename}ResponseEnvelope {{")?;
        writeln!(
            w.operation,
            "    fn serialize<S: ::serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {{"
        )?;
        writeln!(w.operation, "        use ::serde::ser::SerializeStruct as _;")?;
        writeln!(
            w.operation,
            "        let mut s = serializer.serialize_struct(\"{rust_typename}Response\", {field_count})?;"
        )?;
        writeln!(w.operation, "        s.serialize_field(\"@xmlns\", \"{xmlns}\")?;")?;
        if output_typename.is_some() {
            writeln!(w.operation, "        s.serialize_field(\"{rust_typename}Result\", &self.result)?;")?;
        }
        // AWS wraps the request id of a *successful* query-protocol response in
        // `<ResponseMetadata>`. Errors are different -- they carry `<RequestId>` directly -- so
        // this deliberately does not match `ErrorResponseEnvelope`.
        writeln!(w.operation, "        match &self.request_id {{")?;
        writeln!(w.operation, "            ::std::option::Option::Some(request_id) => s.serialize_field(")?;
        writeln!(w.operation, "                \"ResponseMetadata\",")?;
        writeln!(w.operation, "                &::scratchstack_core::response::ResponseMetadata::new(request_id),")?;
        writeln!(w.operation, "            )?,")?;
        writeln!(w.operation, "            ::std::option::Option::None => s.skip_field(\"ResponseMetadata\")?,")?;
        writeln!(w.operation, "        }}")?;
        writeln!(w.operation, "        s.end()")?;
        writeln!(w.operation, "    }}")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // ProvideRequestId impl
        writeln!(w.operation, "impl ::scratchstack_core::ProvideRequestId for {rust_typename}ResponseEnvelope {{")?;
        writeln!(w.operation, "    #[inline(always)]")?;
        writeln!(w.operation, "    fn request_id(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w.operation, "        self.request_id.as_deref()")?;
        writeln!(w.operation, "    }}")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // ProvideXmlNamespace impl
        writeln!(w.operation, "impl ::scratchstack_core::ProvideXmlNamespace for {rust_typename}ResponseEnvelope {{")?;
        writeln!(w.operation, "    #[inline(always)]")?;
        writeln!(w.operation, "    fn xml_namespace(&self) -> &str {{")?;
        writeln!(w.operation, "        \"{xmlns}\"")?;
        writeln!(w.operation, "    }}")?;
        writeln!(w.operation, "}}")?;
        writeln!(w.operation)?;

        // Responder impl
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

        Ok(())
    }
}
