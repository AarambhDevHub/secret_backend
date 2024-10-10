use std::sync::Arc;

use axum::{extract::Query, response::IntoResponse, routing::{get, post, put}, Extension, Json, Router};
use validator::Validate;

use crate::{dtos::{EditSecretDto, FilterSecretDto, RequestQueryDto, Response, SaveSecretDto, SecretResponse, SecretResponseDto}, error::HttpError, middleware::JWTAuthMiddleware, secret::{PostgresSecretRespository, SecretRepository}, utils::{connect_user_database::connect_to_user_database, decrypt::decrypt, encrypt::encrypt}, AppState};

#[derive(Debug)]
pub struct SavedSecret {
    pub secret_name: String,
    pub encrypted_secret_value: Vec<u8>,
    pub version: i32,
}

pub fn secrets_handler() -> Router {
    Router::new()
        .route("/get", get(get_secrets))
        .route("/save", post(save_secrets))
        .route("/update", put(edit_secrets))
}


pub async fn get_secrets(
    Query(query_params): Query<RequestQueryDto>,
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>
) -> Result<impl IntoResponse, HttpError> {
    query_params.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let db_connection = &user.db_connection.as_ref()
        .ok_or_else(|| HttpError::server_error("No Database connection found"))?;

    let user_db_pool = connect_to_user_database(db_connection).await?;

    let repo = PostgresSecretRespository::new(&user_db_pool);

    let (total_count, secrets) = repo.get_secrets(page as u32, limit as u32).await?;

    let encryption_method = &user.encryption_method.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Method Not Found"))?;

    let encryption_key = &user.keys.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Key Not Found"))?;

    let mut send_secrets: Vec<SecretResponse> = Vec::new();

    for secret in secrets {
        let decrypted_value_bytes = decrypt(&encryption_method, &encryption_key, &secret.encrypted_secret_value);

        let decrypted_value = String::from_utf8(decrypted_value_bytes)
        .map_err(|e| HttpError::server_error(format!("Decryption failed: {}", e)))?;

        send_secrets.push(
            SecretResponse {
                id: secret.id,
                secret_name: secret.secret_name.clone(),
                secret_value: decrypted_value,
                version: secret.version.clone(),
                created_at: secret.created_at.clone(),
                updated_at: secret.updated_at.clone(),
            }
        );
    }

    let filter_secrets = FilterSecretDto::filter_secrets(&send_secrets);

    let response = SecretResponseDto {
        secret: filter_secrets,
        total_count,
    };

    Ok(Json(response))
}

pub async fn save_secrets(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<Vec<SaveSecretDto>>,
) -> Result<impl IntoResponse, HttpError> {
    for dto in  &body {
        dto.validate()
            .map_err(|e| HttpError::bad_request(e.to_string()))?;
    }

    let user = &user.user;

    let encryption_method = &user.encryption_method.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Method Not Found"))?;

    let encryption_key = &user.keys.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Key Not Found"))?;

    let mut saved_secrets: Vec<SavedSecret> = Vec::new();

    for dto in body {
        let encrypted_secret_value = encrypt(&encryption_method, &encryption_key, &dto.secret_value.as_bytes());

        saved_secrets.push(SavedSecret {
            secret_name: dto.secret_name.clone(),
            encrypted_secret_value,
            version: 1,
        });
    }

    let user_db_connection = &user.db_connection.as_ref()
        .ok_or_else(|| HttpError::server_error("No Database connection found"))?;

    let user_db_pool = connect_to_user_database(user_db_connection).await?;

    let repo = PostgresSecretRespository::new(&user_db_pool);

    repo.save_secrets(saved_secrets).await?;

    let response = Response {
        status: "success",
        message: "Secrets saved successfully".to_string(),
    };

    Ok(Json(response))

}

pub async fn edit_secrets(
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
    Json(body): Json<EditSecretDto>
) -> Result<impl IntoResponse, HttpError> {
    body.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let encryption_method = &user.encryption_method.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Method Not Found"))?;

    let encryption_key = &user.keys.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Key Not Found"))?;

    let encrypted_secret_value = encrypt(&encryption_method, &encryption_key, &body.secret_value.as_bytes());

    let user_db_connection = &user.db_connection.as_ref()
        .ok_or_else(|| HttpError::server_error("No Database connection found"))?;

    let user_db_pool = connect_to_user_database(user_db_connection).await?;

    let repo = PostgresSecretRespository::new(&user_db_pool);

    repo.edit_secrets(body.id, body.secret_name, encrypted_secret_value).await?;

    let response = Response {
        status: "success",
        message: "Secret updated successfully".to_string(),
    };

    Ok(Json(response))
}