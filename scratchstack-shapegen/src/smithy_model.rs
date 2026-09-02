use {
    crate::{CliShorthand, Modules, Shape, ShapeInfo as _, doc_tokens, ident, primitive::SmithyUnit},
    proc_macro2::TokenStream,
    quote::quote,
    serde::{Deserialize, Serialize},
    serde_json::Value,
    std::{
        cell::{Ref, RefCell},
        collections::{BTreeMap, HashSet},
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

    /// Which shapes get CLI shorthand parsers.
    ///
    /// Set before [`resolve`][Self::resolve], which hands it down to every shape that can emit one.
    #[serde(skip, default)]
    pub cli_shorthand: CliShorthand,

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
            let service_shape = self.service();
            let service = service_shape.as_service().expect("service lookup returned a non-service shape");
            service
                .base
                .traits
                .xml_namespace()
                .expect("the service shape has no smithy.api#xmlNamespace trait; the AWS query protocol needs one")
                .to_string()
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

    /// Returns the service shape.
    ///
    /// # Panics
    ///
    /// Panics if the model has no service shape. Everything generated hangs off it -- the action
    /// enum, the API version, the XML namespace -- so a model without one has nothing to generate.
    #[must_use]
    fn service(&self) -> Ref<'_, Shape> {
        self.get_service().expect("model has no service shape")
    }

    /// Generates Rust code for the Smithy model.
    ///
    /// This must have been resolved before calling this method.
    pub fn generate(&self, m: &mut Modules) {
        self.generate_validators(m);

        for shape in self.shapes.values() {
            shape.borrow().generate(m);
        }

        self.generate_action(m);
        self.generate_error_meta(m);
    }

    /// Writes one validator function per constrained shape into `crate::types`.
    ///
    /// Constraints are a property of the shape, so the check is emitted once here and every builder
    /// field targeting that shape calls it. Inlining them instead cost IAM 694 `LazyLock<Regex>`
    /// statics for 80 distinct constrained shapes.
    fn generate_validators(&self, m: &mut Modules) {
        let reachable = self.builder_reachable_shape_ids();

        for (shape_id, shape) in &self.shapes {
            if shape_id.starts_with("smithy.api#") || !reachable.contains(shape_id) {
                continue;
            }

            if let Some(validator) = shape.borrow().validator_fn() {
                m.types.extend(validator);
            }
        }
    }

    /// Returns the ids of shapes a generated builder can validate.
    ///
    /// That is the shapes targeted by the members of structures that get a hand-written builder --
    /// everything but error structures, which use `bon` -- plus, transitively, the element shapes of
    /// any lists among them. Emitting a validator for anything else would be dead code.
    fn builder_reachable_shape_ids(&self) -> HashSet<String> {
        let mut pending: Vec<String> = Vec::new();

        for shape in self.shapes.values() {
            if let Shape::Structure(structure) = &*shape.borrow()
                && !structure.base.traits.is_error()
            {
                pending.extend(structure.members.values().map(|member| member.target.clone()));
            }
        }

        let mut reachable = HashSet::new();
        while let Some(shape_id) = pending.pop() {
            if !reachable.insert(shape_id.clone()) {
                continue;
            }

            if let Some(shape) = self.shapes.get(&shape_id)
                && let Shape::List(list) = &*shape.borrow()
            {
                pending.push(list.member.target.clone());
            }
        }

        reachable
    }

    /// Returns the Rust type names of every error structure in the model, in model order.
    ///
    /// `generate_error_meta` needs this list six times over; collecting it once keeps those passes
    /// from each re-scanning every shape in the model.
    fn error_typenames(&self) -> Vec<String> {
        self.shapes
            .values()
            .filter_map(|shape| match &*shape.borrow() {
                Shape::Structure(structure) if structure.base.traits.is_error() => Some(structure.base.rust_typename()),
                _ => None,
            })
            .collect()
    }

    /// Generates code that belongs in `crate::action` for this model's service.
    ///
    /// The wire actions are the operations bound to the service shape, not every operation shape
    /// in the model. A model transform may add structures or operations that are not callable
    /// actions, and those must not appear here.
    fn generate_action(&self, m: &mut Modules) {
        let service_shape = self.service();
        let service = service_shape.as_service().expect("service lookup returned a non-service shape");

        let mut action_names: Vec<&str> = service
            .operations
            .iter()
            .map(|op| op.target.rsplit_once('#').map_or(op.target.as_str(), |(_, name)| name))
            .collect();
        action_names.sort_unstable();

        let version = &service.version;
        let actions = action_names.iter().map(|name| {
            let variant = ident(name);
            let doc = format!(" The `{name}` action.");
            quote! {
                #[doc = #doc]
                #variant,
            }
        });
        let as_str_arms = action_names.iter().map(|name| {
            let variant = ident(name);
            quote!(Self::#variant => #name,)
        });
        let from_str_arms = action_names.iter().map(|name| {
            let variant = ident(name);
            quote!(#name => ::std::result::Result::Ok(Self::#variant),)
        });

        m.action.extend(quote! {
            #[doc = " The version of this API, as sent in the `Version` request parameter."]
            pub const VERSION: &str = #version;

            #[doc = " An action that can be invoked on this service."]
            #[doc = ""]
            #[doc = " This is the value of the `Action` request parameter in the AWS query protocol."]
            #[derive(::std::clone::Clone, ::std::marker::Copy, ::std::fmt::Debug)]
            #[derive(::std::cmp::Eq, ::std::cmp::Ord, ::std::cmp::PartialEq, ::std::cmp::PartialOrd)]
            #[derive(::std::hash::Hash)]
            // Operation names such as AddClientIDToOpenIDConnectProvider are wire names; they
            // cannot be renamed to satisfy the acronym lint.
            #[allow(clippy::upper_case_acronyms)]
            #[non_exhaustive]
            pub enum Action {
                #(#actions)*
            }

            impl Action {
                #[doc = " Returns the wire name of this action."]
                #[must_use]
                pub const fn as_str(self) -> &'static str {
                    match self {
                        #(#as_str_arms)*
                    }
                }
            }

            impl ::std::fmt::Display for Action {
                fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    f.write_str(self.as_str())
                }
            }

            impl ::std::str::FromStr for Action {
                type Err = UnknownAction;

                fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                    match s {
                        #(#from_str_arms)*
                        _ => ::std::result::Result::Err(UnknownAction),
                    }
                }
            }

            #[doc = " Error returned when a string does not name an action of this service."]
            #[derive(::std::clone::Clone, ::std::marker::Copy, ::std::fmt::Debug)]
            #[derive(::std::cmp::Eq, ::std::cmp::PartialEq)]
            pub struct UnknownAction;

            impl ::std::fmt::Display for UnknownAction {
                fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    f.write_str("Unknown action")
                }
            }

            impl ::std::error::Error for UnknownAction {}
        });
    }

    /// Generates code that belongs in `crate::error_meta` for all shapes in the model.
    fn generate_error_meta(&self, m: &mut Modules) {
        let xmlns = self.xmlns.as_deref().expect("model has no XML namespace; call resolve() before generate()");
        let errors = self.error_typenames();

        let variants = self.shapes.values().filter_map(|shape| match &*shape.borrow() {
            Shape::Structure(structure) if structure.base.traits.is_error() => {
                let name = ident(&structure.base.rust_typename());
                let docs = doc_tokens(structure.base.traits.documentation());
                Some(quote! {
                    #docs
                    #name(::std::boxed::Box<crate::types::error::#name>),
                })
            }
            _ => None,
        });

        // One arm per error for each of the forwarding impls below.
        let arms = |body: fn(&proc_macro2::Ident) -> TokenStream| {
            let arms = errors.iter().map(|name| {
                let name = ident(name);
                let arm = body(&name);
                quote!(Self::#name(inner) => #arm,)
            });
            quote!(#(#arms)*)
        };

        let display_arms = arms(|_| quote!(inner.fmt(f)));
        let metadata_arms = arms(|_| quote!(&**inner));
        let request_id_arms = arms(|_| quote!(::scratchstack_core::ProvideRequestId::request_id(&**inner)));
        let respond_arms = arms(|_| quote!(::scratchstack_core::response::Responder::respond(&**inner)));
        let source_arms = arms(|_| quote!(::std::option::Option::Some(inner)));

        let from_impls = errors.iter().map(|name| {
            let name = ident(name);
            quote! {
                impl ::std::convert::From<crate::types::error::#name> for Error {
                    fn from(inner: crate::types::error::#name) -> Self {
                        Self::#name(::std::boxed::Box::new(inner))
                    }
                }

                impl ::std::convert::From<::std::boxed::Box<crate::types::error::#name>> for Error {
                    fn from(inner: ::std::boxed::Box<crate::types::error::#name>) -> Self {
                        Self::#name(inner)
                    }
                }
            }
        });

        m.error_meta.extend(quote! {
            #[doc = " All possible error types for this service."]
            #[derive(::std::fmt::Debug)]
            #[non_exhaustive]
            pub enum Error {
                #(#variants)*

                #[doc = " An unexpected error occurred"]
                Unhandled(::scratchstack_core::error::GenericError),
            }

            impl ::std::fmt::Display for Error {
                fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                    match self {
                        #display_arms
                        Self::Unhandled(inner) => inner.fmt(f),
                    }
                }
            }

            impl Error {
                #[doc = " Returns this error as a `ProvideErrorMetadata` reference."]
                pub fn as_provide_error_metadata(&self) -> &dyn ::scratchstack_core::error::ProvideErrorMetadata {
                    match self {
                        #metadata_arms
                        Self::Unhandled(inner) => inner,
                    }
                }
            }

            impl ::scratchstack_core::error::ProvideErrorMetadata for Error {
                fn error_type(&self) -> ::scratchstack_core::error::ErrorType {
                    self.as_provide_error_metadata().error_type()
                }

                fn code(&self) -> &str {
                    self.as_provide_error_metadata().code()
                }

                fn message(&self) -> ::std::option::Option<&str> {
                    self.as_provide_error_metadata().message()
                }

                fn http_status(&self) -> ::std::option::Option<::scratchstack_core::http::StatusCode> {
                    self.as_provide_error_metadata().http_status()
                }
            }

            impl ::scratchstack_core::ProvideRequestId for Error {
                fn request_id(&self) -> ::std::option::Option<&str> {
                    match self {
                        #request_id_arms
                        Self::Unhandled(inner) => ::scratchstack_core::ProvideRequestId::request_id(inner),
                    }
                }
            }

            impl ::scratchstack_core::response::Responder for Error {
                fn respond(&self) -> ::scratchstack_core::http::Response<::scratchstack_core::axum::body::Body> {
                    match self {
                        #respond_arms
                        Self::Unhandled(inner) => {
                            ::scratchstack_core::response::ErrorResponseEnvelope::new_with_xmlns(inner, #xmlns)
                                .respond()
                        }
                    }
                }
            }

            impl ::std::error::Error for Error {
                fn source(&self) -> ::std::option::Option<&(dyn ::std::error::Error + 'static)> {
                    match self {
                        #source_arms
                        Self::Unhandled(inner) => ::std::option::Option::Some(inner),
                    }
                }
            }

            #(#from_impls)*
        });
    }
}
