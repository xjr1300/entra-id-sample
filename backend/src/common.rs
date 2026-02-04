use axum::{
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
};
use serde::Serialize;

pub type AppResult<T> = Result<T, RequestError>;

#[derive(Debug)]
pub struct RequestError {
    pub code: StatusCode,
    pub message: String,
}

impl IntoResponse for RequestError {
    fn into_response(self) -> axum::response::Response {
        let status_code = self.code;
        let mut response = (self.code, axum::Json::<RequestErrorRaw>(self.into())).into_response();
        if status_code == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer"),
            );
        }
        response
    }
}

#[derive(Serialize)]
struct RequestErrorRaw {
    code: u16,
    error: String,
    message: String,
}

impl From<RequestError> for RequestErrorRaw {
    fn from(err: RequestError) -> Self {
        Self {
            code: err.code.as_u16(),
            error: err
                .code
                .canonical_reason()
                .unwrap_or("Unknown Error")
                .into(),
            message: err.message,
        }
    }
}
