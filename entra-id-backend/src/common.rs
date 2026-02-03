use axum::{http::StatusCode, response::IntoResponse};
use serde::Serialize;

pub type AppResult<T> = Result<T, RequestError>;

#[derive(thiserror::Error, Debug)]
#[error("{message}")]
pub struct RequestError {
    pub code: StatusCode,
    pub message: String,
}

impl IntoResponse for RequestError {
    fn into_response(self) -> axum::response::Response {
        (self.code, axum::Json::<RequestErrorRaw>(self.into())).into_response()
    }
}

#[derive(Serialize)]
pub struct RequestErrorRaw {
    pub code: u16,
    pub message: String,
}

impl From<RequestError> for RequestErrorRaw {
    fn from(err: RequestError) -> Self {
        Self {
            code: err.code.as_u16(),
            message: err.message,
        }
    }
}
