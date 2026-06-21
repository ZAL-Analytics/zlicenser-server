use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Request, rejection::JsonRejection},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::json;

pub struct JsonBody<T>(pub T);

impl<T, S> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                let (status, code) = match rejection {
                    JsonRejection::MissingJsonContentType(_) => {
                        (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
                    }
                    JsonRejection::JsonDataError(_) => {
                        (StatusCode::UNPROCESSABLE_ENTITY, "unprocessable_entity")
                    }
                    JsonRejection::JsonSyntaxError(_) => (StatusCode::BAD_REQUEST, "invalid_json"),
                    _ => (StatusCode::BAD_REQUEST, "bad_request"),
                };
                Err((status, Json(json!({"error": code}))).into_response())
            }
        }
    }
}

pub struct PathParam<T>(pub T);

impl<T, S> FromRequestParts<S> for PathParam<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Path::<T>::from_request_parts(parts, state).await {
            Ok(axum::extract::Path(value)) => Ok(Self(value)),
            Err(_rejection) => Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_path_parameter"})),
            )
                .into_response()),
        }
    }
}

#[allow(clippy::unused_async)]
pub async fn not_found_handler() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response()
}
