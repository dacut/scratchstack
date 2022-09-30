use http::status::StatusCode;

pub trait ServiceError {
    fn error_code(&self) -> &'static str;
    fn http_status(&self) -> StatusCode;
}
