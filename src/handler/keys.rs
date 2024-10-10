use std::sync::Arc;

use axum::{extract::Query, response::IntoResponse, routing::get, Extension, Json, Router};

use crate::{db::UserExt, dtos::{RequestQuerySecretByKeyDto, RequestQuerySecretByKeyResponseDto}, error::{ErrorMessage, HttpError}, secret::{PostgresSecretRespository, SecretRepository}, utils::{connect_user_database::connect_to_user_database, decrypt::decrypt}, AppState};

pub fn get_secret_key() -> Router {
    Router::new()
        .route("/secert", get(get_secret_by_key))
}

pub async fn get_secret_by_key(
    Query(query_params): Query<RequestQuerySecretByKeyDto>,
    Extension(app_state): Extension<Arc<AppState>>
) -> Result<impl IntoResponse, HttpError> {
    let user_api_key = query_params.key;
    let secret_id = query_params.secret;

    let result = app_state.db_client
        .get_user(None, None, None, Some(&user_api_key))
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let user = result
        .ok_or_else(|| HttpError::unauthorized(ErrorMessage::UserNoLongerExist.to_string()))?;

    let user_db_connection = &user.db_connection.as_ref()
        .ok_or_else(|| HttpError::server_error("No Database connection found"))?;

    let user_db_pool = connect_to_user_database(user_db_connection).await?;

    let repo = PostgresSecretRespository::new(&user_db_pool);

    let secret = repo.get_secrets_by_id(secret_id).await?;

    let encryption_method = &user.encryption_method.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Method Not Found"))?;

    let encryption_key = &user.keys.as_ref()
        .ok_or_else(|| HttpError::server_error("Encryption Key Not Found"))?;

    let decrypted_value_bytes = decrypt(&encryption_method, &encryption_key, &secret.encrypted_secret_value);

    let decrypted_value = String::from_utf8(decrypted_value_bytes)
            .map_err(|e| HttpError::server_error(e.to_string()))?;

    let response = RequestQuerySecretByKeyResponseDto {
        value: decrypted_value,
    };

    Ok(Json(response))

}