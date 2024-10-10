use std::sync::Arc;

use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use validator::Validate;

use crate::{db::UserExt, dtos::{DatabaseDto, EncryptionMethodDto, Response}, error::HttpError, middleware::JWTAuthMiddleware, models::DbConnection, utils::{connect_user_database::connect_to_user_database, create_table::create_user_specific_table, generate_key::generate_key}, AppState};

pub fn setting_handler() -> Router {
    Router::new()
        .route("/database", post(database))
        .route("/encryption_method", post(encryption_method))
}


pub async fn database(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<DatabaseDto>
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let db_connection = DbConnection {
        host: body.host.clone(),
        port: body.port.clone(),
        username: body.username.clone(),
        password: body.password.clone(),
        database: body.database.clone(),
    };

    let user_db_pool = connect_to_user_database(&db_connection).await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    create_user_specific_table(&user_db_pool).await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user_id = uuid::Uuid::parse_str(&user.user.id.to_string()).unwrap();

    app_state.db_client
        .save_database_details(user_id.clone(), db_connection)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        status: "success",
        message: "Database created successfully".to_string(),
    };

    Ok(Json(response))
}

pub async fn encryption_method(
    Extension(app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<EncryptionMethodDto>
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
       .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let key = generate_key(&body.encryption_method);
    let user_id = uuid::Uuid::parse_str(&user.user.id.to_string()).unwrap();

    app_state.db_client
       .save_user_key(user_id.clone(), key, body.encryption_method)
       .await
       .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = Response {
        message: "Encryption method saved successfully".to_string(),
        status: "success",
    };

    Ok(Json(response))
}