use sqlx::{Postgres, Pool, types::Json};
use async_trait::async_trait;
use uuid::Uuid;

use crate::models::{DbConnection, EncryptionMethod, User};

#[derive(Debug, Clone)]
pub struct DBClient {
    pool: Pool<Postgres>
}

impl DBClient {
    pub fn new(pool: Pool<Postgres>) -> Self {
        DBClient { pool }
    }
}

#[async_trait]
pub trait UserExt {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        api_key: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error>;

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        api_key: T,
    ) -> Result<User, sqlx::Error>;

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        new_name: T,
    ) -> Result<User, sqlx::Error>;

    async fn update_user_password(
        &self,
        user_id: Uuid,
        new_password: String,
    ) -> Result<User, sqlx::Error>;

    async fn save_database_details(
        &self,
        user_id: Uuid,
        db_connection: DbConnection,
    ) -> Result<(), sqlx::Error>;

    async fn save_user_key(
        &self,
        user_id: Uuid,
        keys: Vec<u8>,
        encryption_method: EncryptionMethod,
    ) -> Result<(), sqlx::Error>;
}

#[async_trait]
impl UserExt for DBClient {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        name: Option<&str>,
        email: Option<&str>,
        api_key: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
   
        let query = r#"
            SELECT 
                id, 
                name, 
                email, 
                password, 
                encryption_method, 
                keys, 
                api_keys, 
                db_connection,  
                created_at, 
                updated_at 
            FROM users 
            WHERE 
                ($1::uuid IS NULL OR id = $1) AND
                ($2::text IS NULL OR name = $2) AND
                ($3::text IS NULL OR email = $3) AND
                ($4::text IS NULL OR api_keys = $4)
        "#;

    
        let user = sqlx::query_as::<_, User>(query)
            .bind(user_id)
            .bind(name)
            .bind(email)
            .bind(api_key)
            .fetch_optional(&self.pool)
            .await?;
    
        Ok(user)
    }
    

    async fn save_user<T: Into<String> + Send>(
        &self,
        name: T,
        email: T,
        password: T,
        api_key: T
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (name, email, password, api_keys) 
            VALUES ($1, $2, $3, $4) 
            RETURNING id, name, email, password, encryption_method as "encryption_method: EncryptionMethod", keys, api_keys, db_connection as "db_connection: Json<DbConnection>", created_at, updated_at
            "#,
            name.into(),
            email.into(),
            password.into(),
            api_key.into(),
        ).fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user_name<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        new_name: T
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET name = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password,encryption_method as "encryption_method: EncryptionMethod", keys, api_keys, db_connection as "db_connection: Json<DbConnection>", created_at, updated_at
            "#,
            new_name.into(),
            user_id
        ).fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user_password(
        &self,
        user_id: Uuid,
        new_password: String
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET password = $1, updated_at = Now()
            WHERE id = $2
            RETURNING id, name, email, password, encryption_method as "encryption_method: EncryptionMethod", keys, api_keys, db_connection as "db_connection: Json<DbConnection>", created_at, updated_at
            "#,
            new_password,
            user_id
        ).fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn save_database_details(
        &self,
        user_id: Uuid,
        db_connection: DbConnection,
    ) -> Result<(), sqlx::Error> {
        let json_db_connection = serde_json::to_value(&db_connection)
            .map_err(|_| sqlx::Error::from(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Failed to serialize database connection details")))?;

        sqlx::query!(
            r#"
            UPDATE users
            SET db_connection = $1
            WHERE id = $2
            "#,
            json_db_connection,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn save_user_key(
        &self,
        user_id: Uuid,
        keys: Vec<u8>,
        encryption_method: EncryptionMethod
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE users
            SET keys = $1, encryption_method = $2, updated_at = NOW()
            WHERE id = $3
            "#,
            &keys,
            encryption_method as EncryptionMethod,
            user_id
        )
        .execute(&self.pool) // Use execute to run the update statement
        .await?;

        Ok(())
    }
}