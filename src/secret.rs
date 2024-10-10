use async_trait::async_trait;
use sqlx::{Pool, Postgres};

use crate::{error::HttpError, handler::secrets::SavedSecret, models::{Secret, SecretVersion}};

#[async_trait]
pub trait SecretRepository {
    async fn get_secrets(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<(i64, Vec<Secret>), HttpError>;

    async fn get_secrets_by_id(
        &self,
        secret_id: uuid::Uuid
    ) -> Result<Secret, HttpError>;

    async fn get_secrets_version(
        &self,
        secret_id: uuid::Uuid,
        page: u32,
        limit: u32,
    ) -> Result<(i64, Vec<SecretVersion>), HttpError>;

    async fn save_secrets(
        &self,
        saved_secrets: Vec<SavedSecret>
    ) -> Result<(), HttpError>;

    async fn edit_secrets(
        &self,
        secret_id: uuid::Uuid,
        secret_name: String,
        encrypted_secret_value: Vec<u8>,
    ) -> Result<(), HttpError>;
}

#[derive(Debug)]
pub struct PostgresSecretRespository<'a> {
    pool: &'a Pool<Postgres>,
}

impl<'a> PostgresSecretRespository<'a> {
    pub fn new(pool: &'a Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl<'a> SecretRepository for PostgresSecretRespository<'a> {
    async fn get_secrets(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<(i64, Vec<Secret>), HttpError> {
        let offset = (page - 1) * limit;

        let query_count = "SELECT COUNT(*) as count FROM secrets";
        let total_count = sqlx::query_scalar(query_count)
            .fetch_one(self.pool) // Ensure self.pool is of type Pool<Postgres>
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let query_secrets = r#"
            SELECT id, secret_name, encrypted_secret_value, version, created_at, updated_at
            FROM secrets
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        "#;

        let secrets = sqlx::query_as::<_, Secret>(query_secrets)
            .bind(limit as i32)
            .bind(offset as i32)
            .fetch_all(self.pool)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        Ok((total_count, secrets))
    }

    async fn get_secrets_by_id(
        &self,
        secret_id: uuid::Uuid,
    ) -> Result<Secret, HttpError> {
        let query_secret = r#"
            SELECT id, secret_name, encrypted_secret_value, version, created_at, updated_at
            FROM secrets
            WHERE id = $1
        "#;

        let secret_versions = sqlx::query_as::<_, Secret>(query_secret)
        .bind(secret_id)
        .fetch_one(self.pool)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

        Ok(secret_versions)

    }

    async fn get_secrets_version(
        &self,
        secret_id: uuid::Uuid,
        page: u32,
        limit: u32,
    ) -> Result<(i64, Vec<SecretVersion>), HttpError> {
        let offset = (page - 1) * limit;

        let query_count = r#"
            SELECT COUNT(*) as count
            FROM secret_versions
            WHERE secret_id = $1
        "#;

        let total_count = sqlx::query_scalar(query_count)
            .bind(secret_id)
            .fetch_one(self.pool)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;

        let query_secret_versions = r#"
            SELECT id, secret_id, secret_name, encrypted_secret_value, version, created_at, updated_at
            FROM secret_versions
            WHERE secret_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let secret_versions = sqlx::query_as::<_, SecretVersion>(query_secret_versions)
        .bind(secret_id)   // Bind the secret_id for filtering
        .bind(limit as i32) // Bind limit for pagination
        .bind(offset as i32) // Bind offset for pagination
        .fetch_all(self.pool)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

        Ok((total_count, secret_versions))

    }

    async fn save_secrets(
        &self,
        saved_secrets: Vec<SavedSecret>
    ) -> Result<(), HttpError> {
        let mut query = String::from("INSERT INTO secrets (secret_name, encrypted_secret_value, version) VALUES ");
        
        for (i, _secret) in saved_secrets.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push_str(&format!("(${}, ${}, ${})", (i * 3 + 1), (i * 3 + 2), (i * 3 + 3)));
        }
    
        // Prepare the query using a query builder
        let mut query_builder = sqlx::query(&query);
    
        // Bind each parameter directly in the loop
        for secret in saved_secrets.iter() {
            query_builder = query_builder
                .bind(secret.secret_name.clone()) // Bind secret_name
                .bind(secret.encrypted_secret_value.clone()) // Bind encrypted_secret_value
                .bind(secret.version.clone()); // Bind version
        }
    
        // Execute the query
        let _result = query_builder
            .execute(self.pool)
            .await
            .map_err(|e| HttpError::server_error(e.to_string()))?;
    
        Ok(())
    }

    async fn edit_secrets(
        &self,
        secret_id: uuid::Uuid,
        secret_name: String,
        encrypted_secret_value: Vec<u8>,
    ) -> Result<(), HttpError> {

        let query = r#"
        SELECT id, secret_name, encrypted_secret_value, version, created_at, updated_at 
        FROM secrets 
        WHERE id = $1
        "#;

        let current_secret = sqlx::query_as::<_, Secret>(query)
        .bind(&secret_id)
        .fetch_one(self.pool)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

        sqlx::query(
            r"
            INSERT INTO secret_versions (secret_id, secret_name, encrypted_secret_value, version) 
            VALUES ($1, $2, $3, $4)
            "
        )
        .bind(current_secret.id)
        .bind(current_secret.secret_name)
        .bind(current_secret.encrypted_secret_value)
        .bind(current_secret.version)
        .execute(self.pool)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;

        sqlx::query(
            r#"
            UPDATE secrets 
            SET secret_name = $1, encrypted_secret_value = $2, version = version + 1, updated_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(secret_name)
        .bind(encrypted_secret_value)
        .bind(secret_id)
        .execute(self.pool)
        .await
        .map_err(|e| HttpError::server_error(e.to_string()))?;


        Ok(())
    }
}