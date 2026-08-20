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

    /// The XML namespace for this service, taken from the service shape's `xmlNamespace` trait.
    ///
    /// This is resolved during a call to [`resolve`][Self::resolve] and handed down to every shape
    /// that needs to render itself into an XML envelope.
    #[serde(skip, default)]
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

    /// Resolve all shapes in the model by calling `resolve` on each shape until all shapes are resolved.
    ///
    /// The service's XML namespace is resolved first, since individual shapes copy it out of the
    /// model as they resolve.
    pub fn resolve(&mut self) {
        let xmlns = {
            let service_shape = self.get_service().expect("Model has no service shape");
            let service = service_shape.as_service().expect("Service shape is not a service");
            service.base.traits.xml_namespace().expect("Service shape has no xmlNamespace trait").to_string()
        };
        self.xmlns = Some(xmlns);

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

    /// Returns the service shape for this Smithy model, if it has one.
    #[must_use]
    pub fn get_service(&self) -> Option<Ref<'_, Shape>> {
        self.shapes.values().map(|shape| shape.borrow()).find(|shape| matches!(**shape, Shape::Service(_)))
    }

    /// Generates Rust code for the Smithy model.
    ///
    /// This must have been resolved before calling this method.
    pub fn generate<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            shape.generate(w)?;
        }

        self.generate_action(w)?;
        self.generate_error_meta(w)?;
        Ok(())
    }

    /// Generates code that belongs in `crate::action` for this model's service.
    ///
    /// The wire actions are the operations bound to the service shape, not every operation shape
    /// in the model: `build.rs` synthesizes `*InternalRequest` structures that are not callable
    /// actions.
    fn generate_action<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        let service_shape = self.get_service().expect("Model has no service shape");
        let service = service_shape.as_service().expect("Service shape is not a service");

        let mut actions: Vec<&str> = service
            .operations
            .iter()
            .map(|op| op.target.rsplit_once('#').map_or(op.target.as_str(), |(_, name)| name))
            .collect();
        actions.sort_unstable();

        // The API version, as sent in the Version request parameter.
        writeln!(w.action, "/// The version of this API, as sent in the `Version` request parameter.")?;
        writeln!(w.action, "pub const VERSION: &str = \"{}\";", service.version)?;
        writeln!(w.action)?;

        // Action enum definition. The operation's own documentation is not reused here: it is a
        // block of HTML prose describing the operation, not the action name.
        writeln!(w.action, "/// An action that can be invoked on this service.")?;
        writeln!(w.action, "///")?;
        writeln!(w.action, "/// This is the value of the `Action` request parameter in the AWS query protocol.")?;
        writeln!(w.action, "#[derive(::std::clone::Clone, ::std::marker::Copy, ::std::fmt::Debug)]")?;
        writeln!(
            w.action,
            "#[derive(::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd)]"
        )?;
        writeln!(w.action, "#[derive(::std::hash::Hash)]")?;
        // Operation names such as AddClientIDToOpenIDConnectProvider are wire names; they cannot be
        // renamed to satisfy the acronym lint.
        writeln!(w.action, "#[allow(clippy::upper_case_acronyms)]")?;
        writeln!(w.action, "#[non_exhaustive]")?;
        writeln!(w.action, "pub enum Action {{")?;
        for action in &actions {
            writeln!(w.action, "    /// The `{action}` action.")?;
            writeln!(w.action, "    {action},")?;
        }
        writeln!(w.action, "}}")?;
        writeln!(w.action)?;

        // Action::as_str.
        writeln!(w.action, "impl Action {{")?;
        writeln!(w.action, "    /// Returns the wire name of this action.")?;
        writeln!(w.action, "    #[must_use]")?;
        writeln!(w.action, "    pub const fn as_str(self) -> &'static str {{")?;
        writeln!(w.action, "        match self {{")?;
        for action in &actions {
            writeln!(w.action, "            Self::{action} => \"{action}\",")?;
        }
        writeln!(w.action, "        }}")?;
        writeln!(w.action, "    }}")?;
        writeln!(w.action, "}}")?;
        writeln!(w.action)?;

        // Display implementation for Action.
        writeln!(w.action, "impl ::std::fmt::Display for Action {{")?;
        writeln!(w.action, "    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {{")?;
        writeln!(w.action, "        f.write_str(self.as_str())")?;
        writeln!(w.action, "    }}")?;
        writeln!(w.action, "}}")?;
        writeln!(w.action)?;

        // FromStr implementation for Action.
        writeln!(w.action, "impl ::std::str::FromStr for Action {{")?;
        writeln!(w.action, "    type Err = UnknownAction;")?;
        writeln!(w.action)?;
        writeln!(w.action, "    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {{")?;
        writeln!(w.action, "        match s {{")?;
        for action in &actions {
            writeln!(w.action, "            \"{action}\" => ::std::result::Result::Ok(Self::{action}),")?;
        }
        writeln!(w.action, "            _ => ::std::result::Result::Err(UnknownAction),")?;
        writeln!(w.action, "        }}")?;
        writeln!(w.action, "    }}")?;
        writeln!(w.action, "}}")?;
        writeln!(w.action)?;

        // UnknownAction error type.
        writeln!(w.action, "/// Error returned when a string does not name an action of this service.")?;
        writeln!(w.action, "#[derive(::std::clone::Clone, ::std::marker::Copy, ::std::fmt::Debug)]")?;
        writeln!(w.action, "#[derive(::std::cmp::Eq, ::std::cmp::PartialEq)]")?;
        writeln!(w.action, "pub struct UnknownAction;")?;
        writeln!(w.action)?;
        writeln!(w.action, "impl ::std::fmt::Display for UnknownAction {{")?;
        writeln!(w.action, "    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {{")?;
        writeln!(w.action, "        f.write_str(\"Unknown action\")")?;
        writeln!(w.action, "    }}")?;
        writeln!(w.action, "}}")?;
        writeln!(w.action)?;
        writeln!(w.action, "impl ::std::error::Error for UnknownAction {{}}")?;

        Ok(())
    }

    /// Generates code that belongs in `crate::error_meta` for all shapes in the model.
    fn generate_error_meta<W: Write>(&self, w: &mut Writers<W>) -> IoResult<()> {
        let xmlns = self.xmlns.as_deref().expect("Model has not been resolved; no xmlns available");

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

        // ProvideErrorMetadata just forwards to the variant implementation.
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

        // ProvideRequestId just forwards to the variant implementation.
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

        // Responder just forwards to the variant implementation.
        writeln!(w.error_meta, "impl ::scratchstack_core::response::Responder for Error {{")?;
        writeln!(
            w.error_meta,
            "    fn respond(&self) -> ::scratchstack_core::http::Response<::scratchstack_core::axum::body::Body> {{"
        )?;
        writeln!(w.error_meta, "        match self {{")?;
        for shape in self.shapes.values() {
            let shape = shape.borrow();
            if let Shape::Structure(s) = &*shape
                && s.base.traits.is_error()
            {
                writeln!(
                    w.error_meta,
                    "            Self::{}(inner) => ::scratchstack_core::response::Responder::respond(&**inner),",
                    s.base.rust_typename()
                )?;
            }
        }
        writeln!(w.error_meta, "            Self::Unhandled(inner) => {{")?;
        writeln!(
            w.error_meta,
            r#"                ::scratchstack_core::response::ErrorResponseEnvelope::new_with_xmlns(inner, "{xmlns}").respond()"#
        )?;
        writeln!(w.error_meta, "            }}")?;
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
