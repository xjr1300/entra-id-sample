use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::config::ConfigError;
use crate::entra_id::EntraIdError;

pub type AppResult<T> = Result<T, AppError>;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("{0}")]
    Config(ConfigError),
    #[error("{0}")]
    EntraId(EntraIdError),
    #[error("{0}")]
    Handler(ErrorBody),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::Config(e) => e.into_response(),
            AppError::EntraId(e) => e.into_response(),
            AppError::Handler(e) => e.into_response(),
        }
    }
}
#[derive(Debug, thiserror::Error)]
#[error("{{ code: {code}, message: {message} }}")]
pub struct ErrorBody {
    pub code: StatusCode,
    pub message: String,
}

#[derive(Serialize)]
pub struct ErrorBodyRaw {
    pub code: u16,
    pub message: String,
}

impl From<ErrorBody> for ErrorBodyRaw {
    fn from(err: ErrorBody) -> Self {
        ErrorBodyRaw {
            code: err.code.as_u16(),
            message: err.message,
        }
    }
}

impl IntoResponse for ErrorBody {
    fn into_response(self) -> Response {
        (self.code, axum::Json::<ErrorBodyRaw>(self.into())).into_response()
    }
}

impl IntoResponse for ConfigError {
    fn into_response(self) -> Response {
        let status_code = StatusCode::INTERNAL_SERVER_ERROR;
        (
            status_code,
            axum::Json(ErrorBodyRaw {
                code: status_code.as_u16(),
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

macro_rules! entra_id_error_response {
    ($error:expr, $status_code:expr) => {
        (
            $status_code,
            axum::Json(ErrorBodyRaw {
                code: $status_code.as_u16(),
                message: $error.to_string(),
            }),
        )
    };
}

impl IntoResponse for EntraIdError {
    fn into_response(self) -> Response {
        let response = match self {
            EntraIdError::JwksFetchError(_) | EntraIdError::JwksResponseParseError(_, _) => {
                entra_id_error_response!(self, StatusCode::BAD_GATEWAY)
            }
            EntraIdError::DecodingKeyNotFound(_)
            | EntraIdError::TokenHeaderDecodeError(_)
            | EntraIdError::TenantNotFound(_) => {
                entra_id_error_response!(self, StatusCode::UNAUTHORIZED)
            }
            EntraIdError::TokenHeaderMissingKid(_)
            | EntraIdError::DisallowedIssuerTenant(_)
            | EntraIdError::UnsupportedTokenAlgorithm(_)
            | EntraIdError::VerifyTokenError
            | EntraIdError::CreateDecodingKeyError(_, _)
            | EntraIdError::InvalidTokenFormat(_)
            | EntraIdError::TokenPayloadDecodeError(_)
            | EntraIdError::TokenPayloadParseError(_)
            | EntraIdError::TokenMissingIssuer(_)
            | EntraIdError::InvalidIssuerFormat(_) => {
                entra_id_error_response!(self, StatusCode::BAD_REQUEST)
            }
        };
        response.into_response()
    }
}
