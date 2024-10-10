use std::sync::Arc;

use axum::{http::{header, HeaderMap, StatusCode}, response::IntoResponse, routing::post, Extension, Json, Router};
use axum_extra::extract::cookie::Cookie;
use validator::Validate;

use crate::{db::UserExt, dtos::{FilterUserDto, LoginUserDto, RegisterUserDto, Response, UserLoginResponseDto}, error::{ErrorMessage, HttpError}, utils::{generate_key::generate_api_key, password, token}, AppState};

pub fn auth_handler() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
}

pub async fn register(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<RegisterUserDto>
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let hash_password = password::hash(&body.password)
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let api_key = &generate_api_key();

    let result = app_state.db_client
            .save_user(&body.name, &body.email, &hash_password, api_key)
            .await;

    match result {
        Ok(_user) => {
            Ok((StatusCode::CREATED, Json(Response {
                status: "success",
                message: "Registration successful! You can now log in your account.".to_string()
            })))
        },
        Err(sqlx::Error::Database(db_err)) => {
            if db_err.is_unique_violation() {
                Err(HttpError::unique_constraint_violation(
                    ErrorMessage::EmailExist.to_string(),
                ))
            } else {
                Err(HttpError::server_error(db_err.to_string()))
            }
        }
        Err(e) => Err(HttpError::server_error(e.to_string()))
    }
}


pub async fn login(
    Extension(app_state): Extension<Arc<AppState>>,
    Json(body): Json<LoginUserDto>
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let result = app_state.db_client
        .get_user(None, None, Some(&body.email), None)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result.ok_or(HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))?;

    let password_matchs = password::compare(&body.password, &user.password)
        .map_err(|_| HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))?;

    if password_matchs {
        let token = token::create_token(
            &user.id.to_string(), 
            &app_state.env.jwt_secret.as_bytes(), 
            app_state.env.jwt_maxage
        ).
        map_err(|e| HttpError::server_error(e.to_string()))?;

        let cookie_duration = time::Duration::minutes(app_state.env.jwt_maxage * 60);
        let cookie = Cookie::build(("token", token.clone()))
            .path("/")
            .max_age(cookie_duration)
            .http_only(true)
            .build();

        let filter_user = FilterUserDto::filter_user(&user);

        let response = Json(UserLoginResponseDto {
            status: "success".to_string(),
            user: filter_user,
            token,
        });

        let mut headers = HeaderMap::new();
        headers.append(
            header::SET_COOKIE,
            cookie.to_string().parse().unwrap(), 
        );

        let mut response = response.into_response();
        response.headers_mut().extend(headers);

        Ok(response)
    } else {
        Err(HttpError::bad_request(ErrorMessage::WrongCredentials.to_string()))
    }
}