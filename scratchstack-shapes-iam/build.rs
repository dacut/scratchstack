use {
    anyhow::{Result as AnyResult, bail},
    scratchstack_shapegen::{
        LengthConstraint, Member, Shape, ShapeBase, ShapeRef, SmithyModel, Structure, TraitMap, Writers,
        primitive::SmithyString,
    },
    serde_json::{Map as JsonMap, Value as JsonValue, json},
    std::{cell::RefCell, collections::BTreeMap, env::var, fs::File, io::BufReader, path::Path, rc::Rc},
};

/// The IAM APIs to exclude from internal request generation.
///
/// Some of these do not have request bodies (so we can't annotate with an account id); others are
/// organization APIs that do not need an account id.
const IAM_NO_INTERNAL_REQUEST_API: &[&str] = &[
    // These use an ARN parameter that already includes the account id, so we don't need to add an
    // internal request with an account id field.
    "CreatePolicyVersion",
    "DeletePolicy",
    "DeletePolicyVersion",
    "GetPolicy",
    "GetPolicyVersion",
    "ListEntitiesForPolicy",
    "ListPolicyTags",
    "ListPolicyVersions",
    "SetDefaultPolicyVersion",
    "TagPolicy",
    "UntagPolicy",
    // These do not have request bodies, so we can't add an account id field to the object.
    // These are (or will be) implemented in scratchstack-iam-ext.json.
    "GenerateCredentialReport",
    "GetAccountPasswordPolicy",
    "GetAccountSummary",
    "GetCredentialReport",
    "GetOutboundWebIdentityFederationInfo",
    // Organization APIs that don't need an account id.
    "DeleteAccountPasswordPolicy",
    "DisableOrganizationsRootCredentialsManagement",
    "DisableOrganizationsRootSessions",
    "DisableOutboundWebIdentityFederation",
    "EnableOrganizationsRootCredentialsManagement",
    "EnableOrganizationsRootSessions",
    "EnableOutboundWebIdentityFederation",
    "GenerateOrganizationsAccessReport",
    "GetOrganizationsAccessReport",
    "ListOrganizationsFeatures",
];

/// Documentation to use for the account id field in internal request types.
const ACCOUNT_ID_DOCUMENTATION: &str = "The Amazon Web Services account ID this delegation request is targeted to.";

/// The field name to use for the account id in internal request types.
const ACCOUNT_ID_FIELD_NAME: &str = "account_id";

/// The Smithy shape id for the account id type.
const ACCOUNT_ID_SHAPE_ID: &str = "com.amazonaws.iam#accountIdType";

/// Shapes with problematic HTML tags in IAM.
const IAM_PROBLEMATIC_HTML_SHAPE_IDS: &[&str] = &[
    "com.amazonaws.iam#DeleteServiceLinkedRoleResponse",
    "com.amazonaws.iam#GetServiceLinkedRoleDeletionStatusRequest",
];

/// The problematic regex pattern on various string shapes in the IAM mode.
const IAM_PROBLEMATIC_REGEX_1: &str = r"^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$";

/// The replacement regex pattern to use for the problematic regex pattern in the IAM model.
const IAM_PROBLEMATIC_REGEX_1_REPLACEMENT: &str = r"^[a-z0-9]([-a-z0-9]){1,61}[a-z0-9]$";

/// The Smithy namespace for IAM.
const IAM_NAMESPACE: &str = "com.amazonaws.iam";

fn main() {
    generate_iam_shapes().expect("Failed to generate IAM shapes");
}

/// Generate the IAM shapes to include from `iam/mod.rs`.
fn generate_iam_shapes() -> AnyResult<()> {
    println!("cargo:rerun-if-changed=iam-2010-05-08.json");
    println!("cargo:rerun-if-changed=scratchstack-iam-ext.json");
    println!("cargo:rerun-if-changed=build.rs");

    // Load the AWS IAM model.
    let file = File::open("iam-2010-05-08.json")?;
    let reader = BufReader::new(file);
    let mut model: SmithyModel = serde_json::from_reader(reader)?;

    // Perform a few fixups on the model to fix unsupported regular expressions and broken HTML in
    // the documentation.
    model.add_default_shapes();
    fix_unsupported_regexes(&mut model);
    fix_html_doc_tags(&mut model);

    // Add internal operations to the model.
    let new_requests = get_internal_request_shapes(&model)?;
    for (new_request_name, new_request) in new_requests {
        let new_request_shape = Shape::Structure(new_request);
        model
            .shapes
            .insert(format!("com.amazonaws.iam#{}", new_request_name), Rc::new(RefCell::new(new_request_shape)));
    }

    // Load the extensions to the model that we maintain in this repo.
    let file = File::open("scratchstack-iam-ext.json")?;
    let reader = BufReader::new(file);
    let model_ext: SmithyModel = serde_json::from_reader(reader)?;

    // Merge the extensions into the model.
    for (shape_id, shape) in model_ext.shapes {
        model.shapes.insert(shape_id, shape);
    }

    // Add common exception types that are missing from the model.
    // These are applied to every operation since the AWS docs are inaccurate here; service
    // operations happily return exceptions they don't claim to return.
    let common_exceptions = get_common_exception_shapes();
    for (exc_name, exc_def) in common_exceptions.as_object().unwrap() {
        create_exception_shape(&mut model, exc_name, exc_def);
    }
    add_common_exception_types_to_operations(
        &mut model,
        &common_exceptions.as_object().unwrap().keys().collect::<Vec<_>>(),
    );

    model.resolve();

    let out_dir = var("OUT_DIR").expect("OUT_DIR environment variable not set");
    let mut writers = Writers::builder()
        .action(File::create(Path::new(&out_dir).join("action.rs"))?)
        .error_meta(File::create(Path::new(&out_dir).join("error_meta.rs"))?)
        .operation(File::create(Path::new(&out_dir).join("operation.rs"))?)
        .types(File::create(Path::new(&out_dir).join("types.rs"))?)
        .types_error(File::create(Path::new(&out_dir).join("types_error.rs"))?)
        .build();

    model.generate(&mut writers)?;

    Ok(())
}

/// Fix unsupported regular expressions on various types.
fn fix_unsupported_regexes(model: &mut SmithyModel) {
    for shape in model.shapes.values_mut() {
        let mut shape = shape.borrow_mut();
        let traits = shape.traits_mut();

        let Some(pattern) = traits.pattern() else {
            continue;
        };

        if pattern == IAM_PROBLEMATIC_REGEX_1 {
            traits.set_pattern(IAM_PROBLEMATIC_REGEX_1_REPLACEMENT);
            traits.set_length_constraint(LengthConstraint::new(Some(3), Some(63)));
        }
    }
}

/// Fix HTML tags on documentation for a few types.
fn fix_html_doc_tags(model: &mut SmithyModel) {
    for shape_id in IAM_PROBLEMATIC_HTML_SHAPE_IDS {
        let shape = model.shapes.get_mut(*shape_id).unwrap();
        let mut shape = shape.borrow_mut();
        for member in shape.members_mut().unwrap().values_mut() {
            let Some(doc) = member.traits.documentation() else {
                continue;
            };
            let replacement = doc
                .replace("<service-principal-name>", "<i>service-principal-name</i>")
                .replace("<role-name>", "<i>role-name</i>")
                .replace("<task-uuid>", "<i>task-uuid</i>");
            member.traits.set_documentation(replacement);
        }
    }
}

/// Return a map of new shape names to their definitions to add to the model for internal request
/// generation.
fn get_internal_request_shapes(model: &SmithyModel) -> AnyResult<BTreeMap<String, Structure>> {
    let mut result = BTreeMap::new();
    for (api_name, shape) in &model.shapes {
        let Shape::Operation(op) = &*shape.borrow() else {
            continue;
        };

        let Some(base_api_name) = api_name.strip_prefix("com.amazonaws.iam#") else {
            continue;
        };

        if IAM_NO_INTERNAL_REQUEST_API.contains(&base_api_name) {
            continue;
        }

        let request_name = op.input.target.as_str();
        let Some(request_shape) = model.get_shape(request_name) else {
            bail!("Operation {base_api_name} has input shape {request_name} that does not exist in the model");
        };
        let Shape::Structure(request_struct) = &*request_shape.borrow() else {
            bail!("Operation {base_api_name} has input shape {request_name} that is not a structure");
        };

        // Create a new structure that represents the internal request.
        let mut internal_request = request_struct.clone();
        let internal_request_shape_name = format!("{}InternalRequest", base_api_name);

        // Add the account_id field to the internal request.
        let mut traits = TraitMap::new();
        traits.set_required(true);
        traits.set_documentation(ACCOUNT_ID_DOCUMENTATION);
        let account_id_member = Member {
            shape: None,
            target: ACCOUNT_ID_SHAPE_ID.to_string(),
            traits,
        };
        internal_request.members.insert(ACCOUNT_ID_FIELD_NAME.to_string(), account_id_member);
        result.insert(internal_request_shape_name, internal_request);
    }

    Ok(result)
}

/// Returns a name-to-definition map of the common exception types listed in the
/// [AWS IAM API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/CommonErrors.html)
/// but are not included in the model for some reason.
fn get_common_exception_shapes() -> JsonValue {
    json!({
        // Common errors that aren't in the published IAM error list but are returned by the service.
        "com.amazonaws.iam#InvalidAction": {
            "documentation": "The action or version specified in the request is not valid for this service.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#InvalidClientTokenId": {
            "documentation": "The security token included in the request is invalid.",
            "httpResponseCode": 403
        },
        "com.amazonaws.iam#MalformedInput": {
            "documentation": "The request was rejected because it was malformed or otherwise incorrect.",
            "httpResponseCode": 400
        },

        // Published errors
        "com.amazonaws.iam#AccessDeniedException": {
            "documentation": "You don't have permission to perform this action. Verify that your IAM policy includes the required permissions.",
            "httpResponseCode": 403
        },
        "com.amazonaws.iam#ExpiredTokenException": {
            "documentation": "The security token included in the request has expired. Request a new security token and try again.",
            "httpResponseCode": 403
        },
        "com.amazonaws.iam#IncompleteSignature": {
            "documentation": "The request signature doesn't conform to AWS standards. Verify that you're using valid AWS credentials and that your request is properly formatted. If you're using an SDK, ensure it's up to date.",
            "httpResponseCode": 403
        },
        "com.amazonaws.iam#InternalFailure": {
            "documentation": "The request can't be processed right now because of an internal server issue. Try again later. If the problem persists, contact AWS Support.",
            "httpResponseCode": 500
        },
        "com.amazonaws.iam#InvalidParameterCombination": {
            "documentation": "Parameters that must not be used together were used together. Remove one of the conflicting parameters and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#InvalidParameterValue": {
            "documentation": "A value that you provided for a parameter isn't valid. Check the parameter constraints and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#InvalidQueryParameter": {
            "documentation": "The AWS query string is malformed or doesn't adhere to AWS standards. Verify the query string format and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#MalformedQueryString": {
            "documentation": "The query string contains a syntax error. Verify the query string and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#MissingAction": {
            "documentation": "The request is missing the Action parameter. Add the Action parameter and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#MissingAuthenticationToken": {
            "documentation": "The request must contain a valid AWS access key ID or X.509 certificate. Verify that your credentials are included in the request.",
            "httpResponseCode": 403
        },
        "com.amazonaws.iam#MissingParameter": {
            "documentation": "A required parameter for the specified action isn't included in the request. Add the missing parameter and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#NotAuthorized": {
            "documentation": "You don't have permissions to perform this action. Verify that your IAM policy includes the required permissions.",
            "httpResponseCode": 401
        },
        "com.amazonaws.iam#OptInRequired": {
            "documentation": "Your AWS account needs a subscription for this service. Verify that you've enabled the service in your account.",
            "httpResponseCode": 403
        },
        "com.amazonaws.iam#RequestExpired": {
            "documentation": "The request has expired. This can happen if the request took more than 15 minutes to reach the service, the date stamp is more than 15 minutes in the future, or a pre-signed URL has expired. Generate a new request with a current timestamp and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#ServiceUnavailable": {
            "documentation": "The service is temporarily unavailable. Try again later.",
            "httpResponseCode": 503
        },
        "com.amazonaws.iam#ThrottlingException": {
            "documentation": "Your request rate is too high. The AWS SDKs automatically retry requests that receive this exception. Reduce the frequency of requests.",
            "httpResponseCode": 400
        },
        "com.amazonaws.iam#UnrecognizedClientException": {
            "documentation": "The X.509 certificate or AWS access key ID you provided doesn't exist in our records. Verify that you're using valid credentials and that they haven't expired.",
            "httpResponseCode": 403
        },
        "com.amazonaws.iam#ValidationError": {
            "documentation": "The input doesn't meet the required format or constraints. Check that all required parameters are included and that values are valid.",
            "httpResponseCode": 400
        }
    })
}

/// Converts an error code to the corresponding message type name.
fn error_code_to_message_type(error_code: &str) -> String {
    let mut result = String::with_capacity(IAM_NAMESPACE.len() + 1 + error_code.len() + "Message".len());
    result.push_str(IAM_NAMESPACE);
    result.push('#');

    for (i, c) in error_code.chars().enumerate() {
        if i == 0 {
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }

    result.push_str("Message");

    result
}

/// Creates a new exception shape (and message type) in the model for the given
/// exception name and JSON shape definition
fn create_exception_shape(model: &mut SmithyModel, exc_name: &str, exc_def: &JsonValue) {
    let hash_pos = exc_name.find('#').unwrap();
    let simple_name = &exc_name[hash_pos + 1..];
    let error_code = simple_name.strip_suffix("Exception").unwrap_or(simple_name);
    let http_response_code = exc_def.get("httpResponseCode").unwrap().as_u64().unwrap() as u16;
    let message_type = error_code_to_message_type(error_code);

    let mut traits = TraitMap::new();
    let mut aws_query_error = JsonMap::new();
    aws_query_error.insert("code".to_string(), JsonValue::String(error_code.to_string()));
    aws_query_error.insert("httpResponseCode".to_string(), JsonValue::Number(http_response_code.into()));
    traits.set_aws_query_error(JsonValue::Object(aws_query_error));
    traits.set_documentation(exc_def.get("documentation").unwrap().as_str().unwrap().to_string());
    if http_response_code >= 500 {
        traits.set_error("server");
    } else {
        traits.set_error("client");
    }
    traits.set_http_error(http_response_code);

    let mut members = BTreeMap::new();
    let member = Member {
        shape: None,
        target: message_type.clone(),
        traits: TraitMap::default(),
    };
    members.insert("message".to_string(), member);

    let error_struct = Structure {
        base: ShapeBase {
            smithy_name: None,
            rust_typename: None,
            traits,
        },
        members,
        // Filled in when the model resolves.
        xmlns: None,
    };

    model.shapes.insert(exc_name.to_string(), Rc::new(RefCell::new(Shape::Structure(error_struct))));

    let message_shape = SmithyString {
        base: ShapeBase {
            smithy_name: None,
            rust_typename: None,
            traits: TraitMap::default(),
        },
    };
    model.shapes.insert(message_type, Rc::new(RefCell::new(Shape::String(message_shape))));
}

/// Add common exception types to each operation in the model definition.
fn add_common_exception_types_to_operations(model: &mut SmithyModel, exc_names: &[impl AsRef<str>]) {
    for shape in model.shapes.values_mut() {
        let mut shape = shape.borrow_mut();
        let Some(o) = shape.as_mut_operation() else {
            continue;
        };

        for exc_name in exc_names {
            let exc_name = exc_name.as_ref();
            let shape_ref = ShapeRef {
                target: exc_name.to_string(),
            };
            o.errors.push(shape_ref);
        }
    }
}
