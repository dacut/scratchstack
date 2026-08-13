use {
    crate::{Shape, ShapeInfo as _, Writers, primitive::SmithyUnit},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        cell::RefCell,
        collections::{BTreeMap, HashSet},
        io::{Result as IoResult, Write},
        rc::Rc,
    },
};

/// Smithy service model.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmithyModel {
    /// Defines the version of the Smithy specification (e.g., "2.0"). The version can be set to a
    /// single number like "2" or include a point release like "2.0".
    pub smithy: String,

    /// Defines all of the metadata about the model using a JSON object. Each key is the metadata
    /// key to set, and each value is the metadata value to assign to the key.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metadata: BTreeMap<String, Value>,

    /// A map of absolute shape IDs to shape definitions.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub shapes: BTreeMap<String, Rc<RefCell<Shape>>>,

    /// A set of shape IDs that are reachable from the service's input shapes. This is used to
    /// generate try_from implementations from CLI input.
    #[serde(skip, default)]
    pub input_reachable_shapes: HashSet<String>,
}

impl SmithyModel {
    /// Adds default shapes to the model if they do not already exist.
    pub fn add_default_shapes(&mut self) {
        self.shapes.entry("smithy.api#Unit".to_string()).or_insert_with(|| {
            let unit = SmithyUnit::new("smithy.api#Unit");
            Rc::new(RefCell::new(Shape::Unit(unit)))
        });
    }

    /// Resolve all shapes in the model by calling `resolve` on each shape until all shapes are resolved.
    pub fn resolve(&self) {
        for (shape_name, shape) in &self.shapes {
            if shape_name.starts_with("smithy.api#") {
                continue;
            }

            let mut shape = shape.borrow_mut();
            shape.resolve(shape_name, self);
        }
    }

    /// Gets a shape by its shape ID.
    #[must_use]
    pub fn get_shape(&self, shape_id: &str) -> Option<Rc<RefCell<Shape>>> {
        self.shapes.get(shape_id).cloned()
    }

    /// Generates Rust code for the Smithy model.
    ///
    /// This must have been resolved before calling this method.
    pub fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            shape.generate(w)?;
        }

        self.generate_error_meta(w)?;
        Ok(())
    }

    /// Generates code that belongs in `crate::error_meta` for all shapes in the model.
    fn generate_error_meta<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        // Error enum definition.
        writeln!(w.error_meta, "/// All possible error types for this service.")?;
        writeln!(w.error_meta, "#[derive(::std::fmt::Debug)]")?;
        writeln!(w.error_meta, "#[non_exhaustive]")?;
        writeln!(w.error_meta, "pub enum Error {{")?;
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                s.base.traits.write_docs(&mut w.error_meta, "    ")?;
                writeln!(
                    w.error_meta,
                    "    {}(::std::boxed::Box<crate::types::error::{}>),",
                    s.base.rust_typename(),
                    s.base.rust_typename()
                )?;
            }
        }

        writeln!(w.error_meta, "    /// An unexpected error occurred")?;
        writeln!(w.error_meta, "    Unhandled(::scratchstack_core::error::GenericError)")?;
        writeln!(w.error_meta, "}}")?;
        writeln!(w.error_meta)?;

        // Display implementation for Error.
        writeln!(w.error_meta, "impl ::std::fmt::Display for Error {{")?;
        writeln!(w.error_meta, "    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {{")?;
        writeln!(w.error_meta, "        match self {{")?;
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                writeln!(w.error_meta, "            Self::{}(inner) => inner.fmt(f),", s.base.rust_typename())?;
            }
        }
        writeln!(w.error_meta, "            Self::Unhandled(inner) => inner.fmt(f),")?;
        writeln!(w.error_meta, "        }}")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta, "}}")?;
        writeln!(w.error_meta)?;

        // ProvideErrorMetadata and ProvideRequestId implementations, both of which forward to
        // whichever variant is present.
        writeln!(w.error_meta, "impl Error {{")?;
        writeln!(w.error_meta, "    /// Returns this error as a `ProvideErrorMetadata` reference.")?;
        writeln!(
            w.error_meta,
            "    pub fn as_provide_error_metadata(&self) -> &dyn ::scratchstack_core::error::ProvideErrorMetadata {{"
        )?;
        writeln!(w.error_meta, "        match self {{")?;
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                writeln!(w.error_meta, "            Self::{}(inner) => &**inner,", s.base.rust_typename())?;
            }
        }
        writeln!(w.error_meta, "            Self::Unhandled(inner) => inner,")?;
        writeln!(w.error_meta, "        }}")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta, "}}")?;
        writeln!(w.error_meta)?;

        writeln!(w.error_meta, "impl ::scratchstack_core::error::ProvideErrorMetadata for Error {{")?;
        writeln!(w.error_meta, "    #[inline(always)]")?;
        writeln!(w.error_meta, "    fn error_type(&self) -> ::scratchstack_core::error::ErrorType {{")?;
        writeln!(w.error_meta, "        self.as_provide_error_metadata().error_type()")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta)?;
        writeln!(w.error_meta, "    #[inline(always)]")?;
        writeln!(w.error_meta, "    fn code(&self) -> &str {{")?;
        writeln!(w.error_meta, "        self.as_provide_error_metadata().code()")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta)?;
        writeln!(w.error_meta, "    #[inline(always)]")?;
        writeln!(w.error_meta, "    fn message(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w.error_meta, "        self.as_provide_error_metadata().message()")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta)?;
        writeln!(w.error_meta, "    #[inline(always)]")?;
        writeln!(
            w.error_meta,
            "    fn http_status(&self) -> ::std::option::Option<::scratchstack_core::http::StatusCode> {{"
        )?;
        writeln!(w.error_meta, "        self.as_provide_error_metadata().http_status()")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta, "}}")?;
        writeln!(w.error_meta)?;

        writeln!(w.error_meta, "impl ::scratchstack_core::ProvideRequestId for Error {{")?;
        writeln!(w.error_meta, "    fn request_id(&self) -> ::std::option::Option<&str> {{")?;
        writeln!(w.error_meta, "        match self {{")?;
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                writeln!(
                    w.error_meta,
                    "            Self::{}(inner) => ::scratchstack_core::ProvideRequestId::request_id(&**inner),",
                    s.base.rust_typename()
                )?;
            }
        }
        writeln!(
            w.error_meta,
            "            Self::Unhandled(inner) => ::scratchstack_core::ProvideRequestId::request_id(inner),"
        )?;
        writeln!(w.error_meta, "        }}")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta, "}}")?;
        writeln!(w.error_meta)?;

        // std::error::Error implementation for Error.
        writeln!(w.error_meta, "impl ::std::error::Error for Error {{")?;
        writeln!(
            w.error_meta,
            "    fn source(&self) -> ::std::option::Option<&(dyn ::std::error::Error + 'static)> {{"
        )?;
        writeln!(w.error_meta, "        match self {{")?;
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                writeln!(
                    w.error_meta,
                    "            Self::{}(inner) => ::std::option::Option::Some(inner),",
                    s.base.rust_typename()
                )?;
            }
        }
        writeln!(w.error_meta, "            Self::Unhandled(inner) => ::std::option::Option::Some(inner),")?;
        writeln!(w.error_meta, "        }}")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta, "}}")?;
        writeln!(w.error_meta)?;

        // From implementations
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                writeln!(
                    w.error_meta,
                    "impl ::std::convert::From<crate::types::error::{}> for Error {{",
                    s.base.rust_typename()
                )?;
                writeln!(
                    w.error_meta,
                    "    fn from(inner: crate::types::error::{}) -> Self {{",
                    s.base.rust_typename()
                )?;
                writeln!(w.error_meta, "        Self::{}(::std::boxed::Box::new(inner))", s.base.rust_typename())?;
                writeln!(w.error_meta, "    }}")?;
                writeln!(w.error_meta, "}}")?;
                writeln!(w.error_meta)?;

                writeln!(
                    w.error_meta,
                    "impl ::std::convert::From<::std::boxed::Box<crate::types::error::{}>> for Error {{",
                    s.base.rust_typename()
                )?;
                writeln!(
                    w.error_meta,
                    "    fn from(inner: ::std::boxed::Box<crate::types::error::{}>) -> Self {{",
                    s.base.rust_typename()
                )?;
                writeln!(w.error_meta, "        Self::{}(inner)", s.base.rust_typename())?;
                writeln!(w.error_meta, "    }}")?;
                writeln!(w.error_meta, "}}")?;
                writeln!(w.error_meta)?;
            }
        }

        Ok(())
    }
}
