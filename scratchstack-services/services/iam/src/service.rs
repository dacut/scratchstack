use {
    http::{header::HeaderValue, StatusCode},
    hyper::{
        service::Service,
        Body, Request, Response,
    },
    std::{
        fmt::{Debug},
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::BoxError,
};

#[derive(Clone, Debug)]
pub struct IAMService {}

impl Service<Request<Body>> for IAMService {
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
