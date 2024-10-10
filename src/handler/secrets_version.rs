use std::sync::Arc;

use axum::{extract::Query, response::IntoResponse, routing::get, Extension, Json, Router};
use validator::Validate;

use crate::{dtos::{FilterSecretDto, RequestQuerySecretVersionDto, SecretResponse, SecretResponseDto}, error::HttpError, middleware::JWTAuthMiddleware, secret::{PostgresSecretRespository, SecretRepository}, utils::{connect_user_database::connect_to_user_database, decrypt::decrypt}, AppState};

pub fn secrets_version_handler() -> Router {
    Router::new()
        .route("/get", get(get_secret_version))
}

pub async fn get_secret_version(
    Query(query_params): Query<RequestQuerySecretVersionDto>,
    Extension(_app_state): Extension<Arc<AppState>>,
    Extension(user): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, HttpError> {
    query_params.validate()
        .map_err(|e| HttpError::bad_request(e.to_string()))?;

    let user = &user.user;

    let secret_id = query_params.id;
    let page = query_params.page.unwrap_or(1);
    let limit = query_params.limit.unwrap_or(10);

    let db_connection = &user.db_connection.as_ref()
        .ok_or_else(|| HttpError::server_error("No Database connection found"))?;

    let user_db_pool = connect_to_user_database(db_connection).await?;

    let repo = PostgresSecretRespository::new(&user_db_pool);

    let (total_count, secrets_version) = repo.get_secrets_version(secret_id, page as u32, limit as u32).await?;

    let encryption_method = &user.encryption_method.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Method Not Found"))?;

    let encryption_key = &user.keys.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Key Not Found"))?;

    let mut send_secrets: Vec<SecretResponse> = Vec::new();

    for secret_version in secrets_version {
        let decrypted_value_bytes = decrypt(&encryption_method, &encryption_key, &secret_version.encrypted_secret_value);

        let decrypted_value = String::from_utf8(decrypted_value_bytes)
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        send_secrets.push(
            SecretResponse {
                id: secret_version.id,
                secret_name: secret_version.secret_name.clone(),
                secret_value: decrypted_value,
                version: secret_version.version.clone(),
                created_at: secret_version.created_at.clone(),
                updated_at: secret_version.updated_at.clone(),
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