use {
    http::{header::HeaderValue, StatusCode},
    hyper::{service::Service, Body, Request, Response},
    std::{
        fmt::Debug,
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::BoxError,
};

pub const IAM_XML_NS: &str = "https://iam.amazonaws.com/doc/2010-05-08/";

#[derive(Clone, Debug)]
pub struct IamService {}

impl Service<Request<Body>> for IamService {
    type Response = Response<Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<Body>) -> Self::Future {
        Box::pin(async {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", HeaderValue::from_static("text/plain"))
                .body(Body::from("Hello IAM"))
                .unwrap())
        })
    }
}
