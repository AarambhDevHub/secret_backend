use sqlx::{Executor, Pool, Postgres};

use crate::error::HttpError;


pub async fn create_user_specific_table(
    db_pool: &Pool<Postgres>,
) -> Result<(), HttpError> {

    let mut transaction = db_pool
        .begin()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    let extension_if_not_exists = r#"
        CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
    "#;

    let create_secrets_table = r#"
        CREATE TABLE IF NOT EXISTS secrets (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            secret_name VARCHAR(100) NOT NULL,
            encrypted_secret_value BYTEA NOT NULL,
            version INTEGER DEFAULT 1 NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
    "#;

    let create_secret_versions_table = r#"
        CREATE TABLE IF NOT EXISTS secret_versions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            secret_id UUID REFERENCES secrets(id) ON DELETE CASCADE,
            secret_name VARCHAR(100) NOT NULL,
            encrypted_secret_value BYTEA NOT NULL,
            version INTEGER NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
    "#;

    transaction
        .execute(extension_if_not_exists)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    transaction
        .execute(create_secrets_table)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;
    
    transaction
        .execute(create_secret_versions_table)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    transaction
        .commit()
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

    Ok(())

}