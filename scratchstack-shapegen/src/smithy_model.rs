use {
    crate::{Shape, ShapeInfo as _, Writers, primitive::SmithyUnit},
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        cell::{Ref, RefCell},
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

    /// The XML namespace for this service.
    #[serde(skip)]
    pub xmlns: Option<String>,
}

impl SmithyModel {
    /// Adds default shapes to the model if they do not already exist.
    pub fn add_default_shapes(&mut self) {
        self.shapes.entry("smithy.api#Unit".to_string()).or_insert_with(|| {
            let unit = SmithyUnit::new("smithy.api#Unit");
            Rc::new(RefCell::new(Shape::Unit(unit)))
        });
    }

    /// Resolve the model itself without resolving any subshapes.
    pub fn resolve_self(&mut self) {
        // Find the XML namespace for this service so we can pass it to each shape.
        let service_shape = self.get_service().unwrap();
        let service = service_shape.as_service().unwrap();
        let xmlns = service.base.traits.xml_namespace().unwrap().to_string();
        drop(service_shape);
        self.xmlns = Some(xmlns);
    }

    /// Resolve all shapes in the model by calling `resolve` on each shape until all shapes are
    /// resolved.
    ///
    /// resolve_self must be invoked before this is called.
    pub fn resolve(&self) {
        if self.xmlns.is_none() {
            panic!("resolve_self must be called before resolve");
        }

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

    /// Returns the service shape for this Smithy model.
    #[must_use]
    pub fn get_service(&self) -> Option<Ref<'_, Shape>> {
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Service(_) = &*shape {
                return Some(shape);
            }
        }

        None
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
        writeln!(w.error_meta, "    #[allow(deprecated)]")?;
        writeln!(w.error_meta, "    Unhandled(::std::boxed::Box<crate::types::error::sealed_unhandled::Unhandled>)")?;
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
        writeln!(w.error_meta, "            Self::Unhandled(_) => {{")?;
        writeln!(
            w.error_meta,
            "                if let ::std::option::Option::Some(code) = ::aws_smithy_types::error::metadata::ProvideErrorMetadata::code(self) {{"
        )?;
        writeln!(w.error_meta, "                    write!(f, \"unhandled error ({{code}})\")")?;
        writeln!(w.error_meta, "                }} else {{")?;
        writeln!(w.error_meta, "                    f.write_str(\"unhandled error\")")?;
        writeln!(w.error_meta, "                }}")?;
        writeln!(w.error_meta, "            }}")?;
        writeln!(w.error_meta, "        }}")?;
        writeln!(w.error_meta, "    }}")?;
        writeln!(w.error_meta, "}}")?;
        writeln!(w.error_meta)?;

        // ProvideErrorMetadata implementation
        writeln!(w.error_meta, "impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for Error {{")?;
        writeln!(w.error_meta, "    fn meta(&self) -> &::aws_smithy_types::error::metadata::ErrorMetadata {{")?;
        writeln!(w.error_meta, "        match self {{")?;
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                writeln!(w.error_meta, "            Self::{}(inner) => inner.meta(),", s.base.rust_typename())?;
            }
        }
        writeln!(w.error_meta, "            #[allow(deprecated)]")?;
        writeln!(w.error_meta, "            Self::Unhandled(inner) => &inner.meta,")?;
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
        writeln!(w.error_meta, "            #[allow(deprecated)]")?;
        writeln!(w.error_meta, "            Self::Unhandled(inner) => ::std::option::Option::Some(&*inner.source),")?;
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
