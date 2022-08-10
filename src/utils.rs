use std::collections::HashMap;

use axum::extract::Multipart;
use http::Response;
use http_body::Empty;

use crate::{
    authentication::SessionToken, errors::MultipartError, COOKIE_MAX_AGE, USER_COOKIE_NAME,
};

pub(crate) fn login_response(session_token: SessionToken) -> impl axum::response::IntoResponse {
    http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header("Location", "/")
        .header(
            "Set-Cookie",
            format!(
                "{}={}; Max-Age={}",
                USER_COOKIE_NAME,
                session_token.into_cookie_value(),
                COOKIE_MAX_AGE
            ),
        )
        .body(http_body::Empty::new())
        .unwrap()
}

// TODO database and change session...?
pub(crate) async fn logout_response() -> impl axum::response::IntoResponse {
    Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header("Location", "/")
        .header("Set-Cookie", format!("{}=_; Max-Age=0", USER_COOKIE_NAME,))
        .body(Empty::new())
        .unwrap()
}

pub(crate) fn error_page(err: &dyn std::error::Error) -> impl axum::response::IntoResponse {
    Response::builder()
        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
        .body(format!("Err: {}", err))
        .unwrap()
}

pub(crate) async fn parse_multipart(
    mut multipart: Multipart,
) -> Result<HashMap<String, String>, MultipartError> {
    let mut map = HashMap::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_err| MultipartError::ReadError)?
    {
        let name = field.name().ok_or(MultipartError::NoName)?.to_string();

        let data = field
            .text()
            .await
            .map_err(|_| MultipartError::InvalidValue)?;

        map.insert(name, data);
    }
    Ok(map)
}
