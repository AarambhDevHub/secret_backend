use std::sync::Arc;

use axum::{response::IntoResponse, routing::{put, get}, Extension, Json, Router};
use validator::Validate;

use crate::{db::UserExt, dtos::{FilterUserDto, NameUpdateDto, Response, UserData, UserPasswordUpdateDto, UserResponseDto}, error::HttpError, middleware::JWTAuthMiddleware, utils::password, AppState};

pub fn users_handler() -> Router {
    Router::new()
    .route("/me", get(get_me))
    .route("/name", put(update_user_name))
    .route("/password", put(update_user_password))
}

pub async fn get_me(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>
) -> Result<impl IntoResponse, HttpError> {

    let filtered_user = FilterUserDto::filter_user(&user.user);

    let response_data = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(Json(response_data))
}

pub async fn update_user_name(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<NameUpdateDto>
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user_id = uuid::Uuid::parse_str(&user.user.id.to_string()).unwrap();

    let result = app_state.db_client
        .update_user_name(user_id.clone(), body.name)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let filtered_user = FilterUserDto::filter_user(&result);

    let response_data = UserResponseDto {
        status: "success".to_string(),
        data: UserData {
            user: filtered_user,
        },
    };

    Ok(Json(response_data))
}

pub async fn update_user_password(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<UserPasswordUpdateDto>
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
       .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let password_match = password::compare(&body.old_password, &user.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    if !password_match {
        return Err(HttpError::bad_request("Old password is incorrect".to_string()))?;
    }

    let hash_password = password::hash(&body.new_password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user_id = uuid::Uuid::parse_str(&user.id.to_string()).unwrap();

    app_state.db_client
        .update_user_password(user_id.clone(), hash_password)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        status: "success",
        message: "Password updated successfully".to_string(),
    };

    Ok(Json(response))
}