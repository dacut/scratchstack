use {
    scratchstack_shapegen::{
        Member, Shape, ShapeBase, ShapeRef, SmithyModel, Structure, TraitMap, Writers, primitive::SmithyString,
    },
    serde_json::{Map as JsonMap, Value as JsonValue, json},
    std::{cell::RefCell, collections::BTreeMap, env::var, fs::File, io::BufReader, path::Path, rc::Rc},
};

/// The Smithy namespace for STS.
const STS_NAMESPACE: &str = "com.amazonaws.sts";

fn main() {
    env_logger::init();
    generate_sts_shapes();
}

/// Generate the STS shapes to include from `sts/mod.rs`.
fn generate_sts_shapes() {
    println!("cargo:rerun-if-changed=sts-2011-06-15.json");
    println!("cargo:rerun-if-changed=scratchstack-sts-ext.json");
    println!("cargo:rerun-if-changed=build.rs");

    // Load the AWS STS model.
    let file = File::open("sts-2011-06-15.json").expect("Failed to open STS model file");
    let reader = BufReader::new(file);
    let mut model: SmithyModel = serde_json::from_reader(reader).expect("Failed to parse STS model JSON");

    // Perform a few fixups on the model to fix unsupported regular expressions and broken HTML in
    // the documentation.
    model.add_default_shapes();

    // Load the extensions to the model that we maintain in this repo.
    let file = File::open("scratchstack-sts-ext.json").expect("Failed to open STS extensions file");
    let reader = BufReader::new(file);
    let model_ext: SmithyModel = serde_json::from_reader(reader).expect("Failed to parse STS extensions JSON");

    // Merge the extensions into the model.
    let mut n_inserted = 0;
    for (shape_id, shape) in model_ext.shapes {
        eprintln!("Adding shape {shape_id} from extensions");
        model.shapes.insert(shape_id, shape);
        n_inserted += 1;
    }

    assert!(n_inserted > 0, "No shapes were inserted from the extensions file; something is wrong");

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
        .error_meta(File::create(Path::new(&out_dir).join("error_meta.rs")).expect("Failed to create error_meta.rs"))
        .operation(File::create(Path::new(&out_dir).join("operation.rs")).expect("Failed to create operation.rs"))
        .types(File::create(Path::new(&out_dir).join("types.rs")).expect("Failed to create types.rs"))
        .types_error(File::create(Path::new(&out_dir).join("types_error.rs")).expect("Failed to create types_error.rs"))
        .build()
        .expect("Failed to create writers");

    model.generate(&mut writers).expect("Failed to generate shapes");
}

/// Returns a name-to-definition map of common AWSQuery exception types that are missing from the model.
fn get_common_exception_shapes() -> JsonValue {
    json!({
        "com.amazonaws.sts#AccessDeniedException": {
            "documentation": "You don't have permission to perform this action. Verify that your IAM policy includes the required permissions.",
            "httpResponseCode": 403
        },
        "com.amazonaws.sts#ExpiredTokenException": {
            "documentation": "The security token included in the request has expired. Request a new security token and try again.",
            "httpResponseCode": 403
        },
        "com.amazonaws.sts#IncompleteSignature": {
            "documentation": "The request signature doesn't conform to AWS standards. Verify that you're using valid AWS credentials and that your request is properly formatted. If you're using an SDK, ensure it's up to date.",
            "httpResponseCode": 403
        },
        "com.amazonaws.sts#InternalFailure": {
            "documentation": "The request can't be processed right now because of an internal server issue. Try again later. If the problem persists, contact AWS Support.",
            "httpResponseCode": 500
        },
        "com.amazonaws.sts#InvalidParameterCombination": {
            "documentation": "Parameters that must not be used together were used together. Remove one of the conflicting parameters and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#InvalidParameterValue": {
            "documentation": "A value that you provided for a parameter isn't valid. Check the parameter constraints and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#InvalidQueryParameter": {
            "documentation": "The AWS query string is malformed or doesn't adhere to AWS standards. Verify the query string format and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#MalformedQueryString": {
            "documentation": "The query string contains a syntax error. Verify the query string and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#MissingAction": {
            "documentation": "The request is missing the Action parameter. Add the Action parameter and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#MissingAuthenticationToken": {
            "documentation": "The request must contain a valid AWS access key ID or X.509 certificate. Verify that your credentials are included in the request.",
            "httpResponseCode": 403
        },
        "com.amazonaws.sts#MissingParameter": {
            "documentation": "A required parameter for the specified action isn't included in the request. Add the missing parameter and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#NotAuthorized": {
            "documentation": "You don't have permissions to perform this action. Verify that your IAM policy includes the required permissions.",
            "httpResponseCode": 401
        },
        "com.amazonaws.sts#OptInRequired": {
            "documentation": "Your AWS account needs a subscription for this service. Verify that you've enabled the service in your account.",
            "httpResponseCode": 403
        },
        "com.amazonaws.sts#RequestExpired": {
            "documentation": "The request has expired. This can happen if the request took more than 15 minutes to reach the service, the date stamp is more than 15 minutes in the future, or a pre-signed URL has expired. Generate a new request with a current timestamp and try again.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#ServiceUnavailable": {
            "documentation": "The service is temporarily unavailable. Try again later.",
            "httpResponseCode": 503
        },
        "com.amazonaws.sts#ThrottlingException": {
            "documentation": "Your request rate is too high. The AWS SDKs automatically retry requests that receive this exception. Reduce the frequency of requests.",
            "httpResponseCode": 400
        },
        "com.amazonaws.sts#UnrecognizedClientException": {
            "documentation": "The X.509 certificate or AWS access key ID you provided doesn't exist in our records. Verify that you're using valid credentials and that they haven't expired.",
            "httpResponseCode": 403
        },
        "com.amazonaws.sts#ValidationError": {
            "documentation": "The input doesn't meet the required format or constraints. Check that all required parameters are included and that values are valid.",
            "httpResponseCode": 400
        }
    })
}

/// Converts an error code to the corresponding message type name.
fn error_code_to_message_type(error_code: &str) -> String {
    let mut result = String::with_capacity(STS_NAMESPACE.len() + 1 + error_code.len() + "Message".len());
    result.push_str(STS_NAMESPACE);
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
