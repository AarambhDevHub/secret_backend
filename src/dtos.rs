use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::models::{EncryptionMethod, User};



#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct RegisterUserDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(
        length(min = 1, message = "Email is required"),
        email(message = "Email is invalid")
    )]
    pub email: String,
    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub password: String,

    #[
        validate(
            length(min = 1, message = "Confirm Password is required"),
            must_match(other = "password", message="passwords do not match")
        )
    ]
    #[serde(rename = "passwordConfirm")]
    pub password_confirm: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginUserDto {
    #[validate(length(min = 1, message = "Email is required"), email(message = "Email is invalid"))]
    pub email: String,
    #[validate(
        length(min = 1, message = "Password is required"),
        length(min = 6, message = "Password must be at least 6 characters")
    )]
    pub password: String,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQueryDto {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUserDto {
    pub id: String,
    pub name: String,
    pub email: String,
    pub encryption_method: Option<EncryptionMethod>,
    pub api_keys: Option<String>,    
    #[serde(rename = "dbConnectionExists")]               
    pub db_connection_exists: bool,  
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl FilterUserDto {
    pub fn filter_user(user: &User) -> Self {
        FilterUserDto {
            id: user.id.to_string(),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            encryption_method: user.encryption_method, // Include this if you want it in the DTO
            api_keys: user.api_keys.clone(), // Include this if you want it in the DTO
            db_connection_exists: user.db_connection.is_some(), // Check if db_connection exists
            created_at: user.created_at.unwrap(),
            updated_at: user.updated_at.unwrap(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUserDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginResponseDto {
    pub status: String,
    pub user: FilterUserDto,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct NameUpdateDto {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
}

#[derive(Debug, Validate, Default, Clone, Serialize, Deserialize)]
pub struct UserPasswordUpdateDto {
    #[validate(
        length(min = 1, message = "New password is required."),
        length(min = 6, message = "new password must be at least 6 characters")
    )]
    pub new_password: String,

    #[validate(
        length(min = 1, message = "New password confirm is required."),
        length(min = 6, message = "new password confirm must be at least 6 characters"),
        must_match(other = "new_password", message="new passwords do not match")
    )]
    pub new_password_confirm: String,

    #[validate(
        length(min = 1, message = "Old password is required."),
        length(min = 6, message = "Old password must be at least 6 characters")
    )]
    pub old_password: String,
}

#[derive(Debug, Validate, Clone, Serialize, Deserialize)]
pub struct DatabaseDto {
    #[validate(length(min = 1, message = "Host is required."))]
    pub host: String,
    #[validate(length(min = 1, message = "Username is required."))]
    pub username: String,
    #[validate(length(min = 1, message = "Password is required."))]
    pub password: String,
    #[validate(length(min = 1, message = "Database is required."))]
    pub database: String,
    #[validate(range(min = 1, max = 65535, message = "Port must be between 1 and 65535"))]
    pub port: i32,
}

#[derive(Debug, Validate, Clone, Serialize, Deserialize)]
pub struct EncryptionMethodDto {
    #[validate(custom = "validate_encryption_method")]
    pub encryption_method: EncryptionMethod,
}

fn validate_encryption_method(encryption_method: &EncryptionMethod) -> Result<(), ValidationError> {
    match encryption_method {
        EncryptionMethod::AES256
        | EncryptionMethod::Chacha20
        | EncryptionMethod::Blowfish
        | EncryptionMethod::DESTriphleDES => Ok(()),
        _ => Err(ValidationError::new("encryption_method must be either AES256, Chacha20, Blowfish, or DESTriphleDES")),
    }
}

#[derive(Debug, Validate, Clone, Serialize, Deserialize)]
pub struct SaveSecretDto {
    #[validate(length(min = 1, message = "Secret name is required."))]
    pub secret_name: String,
    #[validate(length(min = 1, message = "Secret value is required."))]
    pub secret_value: String,
}

#[derive(Debug, Validate, Clone, Serialize, Deserialize)]
pub struct EditSecretDto {
    #[validate(length(min = 1, message = "Secret name is required."))]
    pub secret_name: String,
    #[validate(length(min = 1, message = "Secret value is required."))]
    pub secret_value: String,
    pub id: uuid::Uuid,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQuerySecretVersionDto {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
    pub id: uuid::Uuid,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretResponse {
    pub id: uuid::Uuid,
    pub secret_name: String,
    pub secret_value: String,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterSecretDto {
    pub id: String,
    pub secret_name: String,
    pub secret_value: String,
    pub version: i32,
}

impl FilterSecretDto {
    pub fn filter_secret(secret: &SecretResponse) -> Self {
        FilterSecretDto {
            id: secret.id.to_string(),
            secret_name: secret.secret_name.to_string(),
            secret_value: secret.secret_value.to_string(),
            version: secret.version, 
        }
    }

    pub fn filter_secrets(secret: &[SecretResponse]) -> Vec<FilterSecretDto> {
        secret.iter().map(FilterSecretDto::filter_secret).collect()
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct SecretResponseDto {
    pub secret: Vec<FilterSecretDto>,
    pub total_count: i64,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RequestQuerySecretByKeyDto {
    pub key: String,
    pub secret: uuid::Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestQuerySecretByKeyResponseDto {
  pub value: String,
}