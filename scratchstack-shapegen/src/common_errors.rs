//! Common service errors that published Smithy models omit.
//!
//! AWS query-protocol services return a set of errors that every operation can produce -- bad
//! signatures, throttling, expired tokens -- but the published models do not declare them, and the
//! per-operation error lists in the AWS documentation are not accurate either: operations happily
//! return errors they do not claim to. Rather than patch each operation by hand, a service declares
//! the common set once and it is attached to every operation in the model.

use {
    crate::{Member, Shape, ShapeBase, ShapeRef, SmithyModel, Structure, TraitMap, primitive::SmithyString},
    serde_json::{Map as JsonMap, Value as JsonValue},
    std::{cell::RefCell, collections::BTreeMap, rc::Rc},
};

/// One error shape to synthesize into a model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonError {
    /// Prose describing the error, used as the doc comment on the generated type.
    pub documentation: String,

    /// The HTTP status code the error is returned with. Codes at 500 and above are marked as server
    /// errors; everything else is a client error.
    pub http_status: u16,

    /// The simple shape name, without a namespace -- for example `AccessDeniedException`. A
    /// trailing `Exception` is stripped to form the wire error code.
    pub name: String,
}

/// The set of common errors to attach to every operation in a model.
///
/// [`CommonErrors::aws_query`] supplies the standard AWS query-protocol set. The list is open, so a
/// service can add entries or drop ones that do not apply:
///
/// ```
/// # use scratchstack_shapegen::{CommonError, CommonErrors};
/// let mut errors = CommonErrors::aws_query();
/// errors.retain(|e| e.name != "OptInRequired");
/// errors.push(CommonError::new("PolicyEvaluationException", "Evaluation failed.", 500));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommonErrors(Vec<CommonError>);

impl CommonError {
    /// Creates a common error definition.
    #[must_use]
    pub fn new(name: impl Into<String>, documentation: impl Into<String>, http_status: u16) -> Self {
        Self {
            documentation: documentation.into(),
            http_status,
            name: name.into(),
        }
    }

    /// Returns the wire error code: the shape name with any trailing `Exception` removed.
    #[must_use]
    pub fn error_code(&self) -> &str {
        self.name.strip_suffix("Exception").unwrap_or(&self.name)
    }
}

impl CommonErrors {
    /// The errors common to every AWS query-protocol service.
    ///
    /// The first three are absent from the published common-error lists but are returned by the
    /// services regardless; the remainder are the documented set.
    #[must_use]
    pub fn aws_query() -> Self {
        Self(vec![
            CommonError::new(
                "InvalidAction",
                "The action or version specified in the request is not valid for this service.",
                400,
            ),
            CommonError::new("InvalidClientTokenId", "The security token included in the request is invalid.", 403),
            CommonError::new(
                "MalformedInput",
                "The request was rejected because it was malformed or otherwise incorrect.",
                400,
            ),
            CommonError::new(
                "AccessDeniedException",
                "You don't have permission to perform this action. Verify that your IAM policy includes the required permissions.",
                403,
            ),
            CommonError::new(
                "ExpiredTokenException",
                "The security token included in the request has expired. Request a new security token and try again.",
                403,
            ),
            CommonError::new(
                "IncompleteSignature",
                "The request signature doesn't conform to AWS standards. Verify that you're using valid AWS credentials and that your request is properly formatted. If you're using an SDK, ensure it's up to date.",
                403,
            ),
            CommonError::new(
                "InternalFailure",
                "The request can't be processed right now because of an internal server issue. Try again later. If the problem persists, contact AWS Support.",
                500,
            ),
            CommonError::new(
                "InvalidParameterCombination",
                "Parameters that must not be used together were used together. Remove one of the conflicting parameters and try again.",
                400,
            ),
            CommonError::new(
                "InvalidParameterValue",
                "A value that you provided for a parameter isn't valid. Check the parameter constraints and try again.",
                400,
            ),
            CommonError::new(
                "InvalidQueryParameter",
                "The AWS query string is malformed or doesn't adhere to AWS standards. Verify the query string format and try again.",
                400,
            ),
            CommonError::new(
                "MalformedQueryString",
                "The query string contains a syntax error. Verify the query string and try again.",
                400,
            ),
            CommonError::new(
                "MissingAction",
                "The request is missing the Action parameter. Add the Action parameter and try again.",
                400,
            ),
            CommonError::new(
                "MissingAuthenticationToken",
                "The request must contain a valid AWS access key ID or X.509 certificate. Verify that your credentials are included in the request.",
                403,
            ),
            CommonError::new(
                "MissingParameter",
                "A required parameter for the specified action isn't included in the request. Add the missing parameter and try again.",
                400,
            ),
            CommonError::new(
                "NotAuthorized",
                "You don't have permissions to perform this action. Verify that your IAM policy includes the required permissions.",
                401,
            ),
            CommonError::new(
                "OptInRequired",
                "Your AWS account needs a subscription for this service. Verify that you've enabled the service in your account.",
                403,
            ),
            CommonError::new(
                "RequestExpired",
                "The request has expired. This can happen if the request took more than 15 minutes to reach the service, the date stamp is more than 15 minutes in the future, or a pre-signed URL has expired. Generate a new request with a current timestamp and try again.",
                400,
            ),
            CommonError::new("ServiceUnavailable", "The service is temporarily unavailable. Try again later.", 503),
            CommonError::new(
                "ThrottlingException",
                "Your request rate is too high. The AWS SDKs automatically retry requests that receive this exception. Reduce the frequency of requests.",
                400,
            ),
            CommonError::new(
                "UnrecognizedClientException",
                "The X.509 certificate or AWS access key ID you provided doesn't exist in our records. Verify that you're using valid credentials and that they haven't expired.",
                403,
            ),
            CommonError::new(
                "ValidationError",
                "The input doesn't meet the required format or constraints. Check that all required parameters are included and that values are valid.",
                400,
            ),
        ])
    }

    /// Creates an empty set.
    #[must_use]
    pub fn none() -> Self {
        Self(Vec::new())
    }

    /// Returns true if there are no errors in this set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterates over the errors in this set.
    pub fn iter(&self) -> impl Iterator<Item = &CommonError> {
        self.0.iter()
    }

    /// Adds an error to this set.
    pub fn push(&mut self, error: CommonError) {
        self.0.push(error);
    }

    /// Keeps only the errors matching `predicate`.
    pub fn retain(&mut self, predicate: impl FnMut(&CommonError) -> bool) {
        self.0.retain(predicate);
    }

    /// Synthesizes each error into `model` under `namespace` and lists it on every operation.
    ///
    /// Each error contributes two shapes: the error structure itself, and the string shape holding
    /// its `message` member. Both are inserted unresolved, so this must run before
    /// [`SmithyModel::resolve`].
    pub fn apply(&self, model: &mut SmithyModel, namespace: &str) {
        for error in &self.0 {
            self.insert_error_shape(model, namespace, error);
        }

        // Every operation can return every common error. `Operation::errors` feeds
        // `Operation::error_shapes` during resolution; the union `Error` enum in `error_meta` is
        // built by scanning the model for error structures, not from these lists.
        for shape in model.shapes.values_mut() {
            let mut shape = shape.borrow_mut();
            let Some(operation) = shape.as_mut_operation() else {
                continue;
            };

            for error in &self.0 {
                operation.errors.push(ShapeRef {
                    target: format!("{namespace}#{}", error.name),
                });
            }
        }
    }

    /// Inserts the error structure and its message string shape into the model.
    fn insert_error_shape(&self, model: &mut SmithyModel, namespace: &str, error: &CommonError) {
        let error_code = error.error_code();
        let shape_id = format!("{namespace}#{}", error.name);
        let message_shape_id = message_shape_id(namespace, error_code);

        let mut aws_query_error = JsonMap::new();
        aws_query_error.insert("code".to_string(), JsonValue::String(error_code.to_string()));
        aws_query_error.insert("httpResponseCode".to_string(), JsonValue::Number(error.http_status.into()));

        let mut traits = TraitMap::new();
        traits.set_aws_query_error(JsonValue::Object(aws_query_error));
        traits.set_documentation(error.documentation.clone());
        traits.set_error(if error.http_status >= 500 {
            "server"
        } else {
            "client"
        });
        traits.set_http_error(error.http_status);

        let mut members = BTreeMap::new();
        members.insert(
            "message".to_string(),
            Member {
                shape: None,
                target: message_shape_id.clone(),
                traits: TraitMap::default(),
            },
        );

        let error_structure = Structure {
            base: ShapeBase {
                smithy_name: None,
                rust_typename: None,
                traits,
            },
            members,
            // Filled in when the model resolves.
            xmlns: None,
        };
        model.shapes.insert(shape_id, Rc::new(RefCell::new(Shape::Structure(error_structure))));

        let message_shape = SmithyString {
            base: ShapeBase {
                smithy_name: None,
                rust_typename: None,
                traits: TraitMap::default(),
            },
        };
        model.shapes.insert(message_shape_id, Rc::new(RefCell::new(Shape::String(message_shape))));
    }
}

/// Returns the shape id of the string shape holding an error's `message` member.
///
/// AWS models name these after the error code with a lowercased first character and a `Message`
/// suffix, so `AccessDenied` becomes `accessDeniedMessage`.
fn message_shape_id(namespace: &str, error_code: &str) -> String {
    let mut result = String::with_capacity(namespace.len() + 1 + error_code.len() + "Message".len());
    result.push_str(namespace);
    result.push('#');

    let mut chars = error_code.chars();
    if let Some(first) = chars.next() {
        result.extend(first.to_lowercase());
        result.push_str(chars.as_str());
    }

    result.push_str("Message");
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_shape_id_lowercases_only_the_first_character() {
        assert_eq!(message_shape_id("com.amazonaws.iam", "AccessDenied"), "com.amazonaws.iam#accessDeniedMessage");
        assert_eq!(message_shape_id("com.amazonaws.sts", "InvalidAction"), "com.amazonaws.sts#invalidActionMessage");
        assert_eq!(message_shape_id("com.example", ""), "com.example#Message");
    }

    #[test]
    fn error_code_strips_the_exception_suffix() {
        assert_eq!(CommonError::new("AccessDeniedException", "", 403).error_code(), "AccessDenied");
        assert_eq!(CommonError::new("InvalidAction", "", 400).error_code(), "InvalidAction");
    }

    #[test]
    fn aws_query_set_is_the_documented_size() {
        let errors = CommonErrors::aws_query();
        assert_eq!(errors.iter().count(), 21);
        assert!(errors.iter().any(|e| e.name == "ThrottlingException"));
    }
}
