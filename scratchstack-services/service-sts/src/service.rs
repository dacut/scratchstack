use {
    crate::{model, operations},
    http::{header::HeaderValue, StatusCode},
    hyper::{service::Service, Body, Request, Response},
    log::warn,
    scratchstack_aws_signature::{canonical::get_content_type_and_charset, signature::IntoRequestBytes},
    scratchstack_http_framework::RequestId,
    std::{
        collections::HashMap,
        fmt::Debug,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::BoxError,
};

/// Content-Type string for HTML forms
const APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

pub const STS_XML_NS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

pub const STS_VERSION_20110615: &str = "2011-06-15";

#[derive(Clone, Debug)]
pub struct StsService {}

impl Service<Request<Body>> for StsService {
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        Box::pin(async {
            let (mut parts, body) = req.into_parts();
            let request_id = match parts.extensions.get::<RequestId>() {
                Some(request_id) => *request_id,
                None => {
                    let new_request_id = RequestId::new();
                    parts.extensions.insert(new_request_id);
                    new_request_id
                }
            };

            let query = parts.uri.query().unwrap_or("").to_string();
            let mut parameters: HashMap<String, String> = HashMap::new();
            for pair in form_urlencoded::parse(query.as_bytes()) {
                let key = pair.0.to_string();
                let value = pair.1.to_string();

                // Only use the first value found. If an entry already exists, do not update it.
                parameters.entry(key).or_insert(value);
            }

            if let Some(ctc) = get_content_type_and_charset(&parts.headers) {
                // This should not happen.
                if ctc.content_type != APPLICATION_X_WWW_FORM_URLENCODED {
                    // FIXME: Format result.
                    return Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .header("Content-Type", HeaderValue::from_static("text/plain"))
                        .header("X-Amzn-RequestId", request_id.to_string())
                        .body(Body::from("Bad request"))
                        .map_err(Into::into);
                }

                let body = match body.into_request_bytes().await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!("{} Error reading request body: {}", request_id, e);
                        return Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .header("Content-Type", HeaderValue::from_static("text/plain"))
                            .header("X-Amzn-RequestId", request_id.to_string())
                            .body(Body::from("Internal server error"))
                            .map_err(Into::into);
                    }
                };

                for pair in form_urlencoded::parse(&body) {
                    let key = pair.0.to_string();
                    let value = pair.1.to_string();

                    // Again, only use the first value found. If an entry already exists, do not update it.
                    parameters.entry(key).or_insert(value);
                }
            }

            // Action is required.
            let action = match parameters.get("Action") {
                Some(action) => action,
                None => {
                    // AWS returns HTML here; we always return an XML body instead.
                    let error = model::Error::builder()
                        .code("InvalidRequest")
                        .message("Missing required parameter: Action")
                        .r#type("Sender")
                        .build()?;

                    let error_response = model::response::ErrorResponse::builder()
                        .xmlns(model::AWSFAULT_XML_NS)
                        .request_id(request_id)
                        .error(error)
                        .build()?;

                    return error_response.respond(&parts, StatusCode::BAD_REQUEST);
                }
            };

            let version =
                parameters.get("Version").map(Clone::clone).unwrap_or_else(|| "NO_VERSION_SPECIFIED".to_string());

            match (action.as_str(), version.as_str()) {
                ("GetCallerIdentity", STS_VERSION_20110615) => operations::get_caller_identity(parts, parameters).await,
                _ => {
                    let error = model::Error::builder()
                        .code("InvalidAction")
                        .message(format!("Could not find operation {action} for version {version}"))
                        .r#type("Sender")
                        .build()?;

                    let error_response = model::response::ErrorResponse::builder()
                        .xmlns(model::AWSFAULT_XML_NS)
                        .request_id(request_id)
                        .error(error)
                        .build()?;

                    error_response.respond(&parts, StatusCode::BAD_REQUEST)
                }
            }
        })
    }
}
