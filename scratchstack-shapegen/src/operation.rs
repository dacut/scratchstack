use {
    crate::{Modules, Protocol, Shape, ShapeBase, ShapeInfo, ShapeRef, SmithyModel, ident, type_tokens, usize_literal},
    proc_macro2::TokenStream,
    quote::quote,
    serde::{Deserialize, Serialize},
    std::{cell::RefCell, rc::Rc},
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
    /// `<{Operation}Response xmlns="..."><{Operation}Result>...</{Operation}Result><ResponseMetadata>...`
    /// envelope. The result shape itself is generated as an ordinary structure; this adds the
    /// wrapper around it.
    ///
    /// The JSON protocols have no wrapper at all: the body is the result shape itself and the
    /// request id goes out as a header. The envelope is still generated for them, so that service
    /// code builds and returns a response the same way whatever the protocol, but it serializes as
    /// the result it carries.
    fn generate(&self, model: &SmithyModel, m: &mut Modules) {
        let base_name = self.base.rust_typename();
        let envelope = ident(&format!("{base_name}ResponseEnvelope"));
        let protocol = model.protocol.expect("the model has no protocol; resolve() before generate()");

        // An operation with no output shape, or one whose output is the Smithy unit type, has no
        // result to carry -- the envelope is just the request id, and whatever the protocol wraps
        // it in.
        let output_shape = self.output_shape.as_ref().map(|shape| shape.borrow());
        let output_shape = output_shape.as_deref().filter(|shape| !shape.is_unit());
        let output_typename = output_shape.map(ShapeInfo::rust_typename);

        let envelope_doc = format!(" Response wire type for the {base_name} operation.");
        let result_doc = format!(" The result of the {base_name} operation.");
        let result_field = match &output_typename {
            Some(typename) => {
                let result_type = type_tokens(typename);
                quote! {
                    #[doc = #result_doc]
                    pub result: #result_type,
                }
            }
            None => quote!(),
        };

        // `serialize_struct`, not `serialize_map`: quick-xml takes the root element name from the
        // struct name and refuses to serialize a map at the top level ("cannot serialize map
        // without defined root tag"). The name given is the wire name, not the Rust type name.
        let response_wire_name = format!("{base_name}Response");

        let (serialize_impl, xml_namespace_impl, responder_impl) = match protocol {
            Protocol::AwsQuery => {
                let xmlns = self.xmlns.as_deref().unwrap_or_else(|| {
                    panic!(
                        "operation {} has no XML namespace; call resolve() before generate()",
                        self.base.smithy_name()
                    )
                });

                let field_count = usize_literal(if output_typename.is_some() {
                    3
                } else {
                    2
                });
                let serialize_result = match &output_typename {
                    Some(_) => {
                        let result_wire_name = format!("{base_name}Result");
                        quote!(s.serialize_field(#result_wire_name, &self.result)?;)
                    }
                    None => quote!(),
                };

                let serialize_impl = quote! {
                    impl ::serde::Serialize for #envelope {
                        fn serialize<S: ::serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                            use ::serde::ser::SerializeStruct as _;
                            let mut s = serializer.serialize_struct(#response_wire_name, #field_count)?;
                            s.serialize_field("@xmlns", #xmlns)?;
                            #serialize_result
                            // AWS wraps the request id of a *successful* query-protocol response in
                            // `<ResponseMetadata>`. Errors carry `<RequestId>` directly, so this
                            // deliberately does not match `ErrorResponseEnvelope`.
                            match &self.request_id {
                                ::std::option::Option::Some(request_id) => s.serialize_field(
                                    "ResponseMetadata",
                                    &::scratchstack_core::response::ResponseMetadata::new(request_id),
                                )?,
                                ::std::option::Option::None => s.skip_field("ResponseMetadata")?,
                            }
                            s.end()
                        }
                    }
                };

                let xml_namespace_impl = quote! {
                    impl ::scratchstack_core::ProvideXmlNamespace for #envelope {
                        fn xml_namespace(&self) -> &str {
                            #xmlns
                        }
                    }
                };

                let responder_impl = quote! {
                    impl ::scratchstack_core::response::Responder for #envelope {
                        fn respond(&self)
                            -> ::scratchstack_core::http::Response<::scratchstack_core::axum::body::Body>
                        {
                            ::scratchstack_core::response::xml_response(
                                self,
                                ::scratchstack_core::http::StatusCode::OK,
                            )
                        }
                    }
                };

                (serialize_impl, xml_namespace_impl, responder_impl)
            }

            Protocol::AwsJson1_0 | Protocol::AwsJson1_1 | Protocol::RestJson1 => {
                // The content type names the protocol, so the responder has to carry it.
                let content_type = protocol.content_type();

                let serialize_body = match &output_typename {
                    // The envelope adds a request id and nothing else, and that goes out as a
                    // header, so what is left to write is the result itself.
                    Some(_) => quote!(::serde::Serialize::serialize(&self.result, serializer)),

                    // An operation with no output still answers with an object, empty rather than
                    // absent: `{}` is what the AWS services return and what their clients parse.
                    None => quote! {
                        use ::serde::ser::SerializeStruct as _;
                        let s = serializer.serialize_struct(#response_wire_name, 0)?;
                        s.end()
                    },
                };

                let serialize_impl = quote! {
                    impl ::serde::Serialize for #envelope {
                        fn serialize<S: ::serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                            #serialize_body
                        }
                    }
                };

                let responder_impl = quote! {
                    impl ::scratchstack_core::response::Responder for #envelope {
                        fn respond(&self)
                            -> ::scratchstack_core::http::Response<::scratchstack_core::axum::body::Body>
                        {
                            ::scratchstack_core::response::json_response(
                                self,
                                ::scratchstack_core::http::StatusCode::OK,
                                ::scratchstack_core::http::HeaderValue::from_static(#content_type),
                            )
                        }
                    }
                };

                (serialize_impl, TokenStream::new(), responder_impl)
            }

            Protocol::Ec2Query | Protocol::RestXml => {
                panic!("operation {} uses the {protocol} protocol, which is not supported", self.base.smithy_name())
            }
        };

        m.operation.extend(quote! {
            #[doc = #envelope_doc]
            #[derive(::bon::Builder, ::std::clone::Clone, ::std::fmt::Debug)]
            pub struct #envelope {
                #result_field

                #[doc = " The request id associated with the request, if available."]
                #[builder(into)]
                pub request_id: ::std::option::Option<::std::string::String>,
            }

            #serialize_impl

            impl ::scratchstack_core::ProvideRequestId for #envelope {
                fn request_id(&self) -> ::std::option::Option<&str> {
                    self.request_id.as_deref()
                }
            }

            #xml_namespace_impl

            #responder_impl
        });
    }
}
