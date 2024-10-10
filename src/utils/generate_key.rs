use std::time::{SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, Rng};

use crate::models::EncryptionMethod;


pub fn generate_key(method: &EncryptionMethod) -> Vec<u8> {
    let mut rng = OsRng;

    match method {
        EncryptionMethod::AES256 => {
            let mut key = vec![0u8; 32];
            rng.fill(&mut key[..]);
            key
        }
        EncryptionMethod::Chacha20 => {
            let mut key = vec![0u8; 32];
            rng.fill(&mut key[..]);
            key
        }
        EncryptionMethod::Blowfish => {
            let mut key = vec![0u8; 32];
            rng.fill(&mut key[..]);
            key
        }
        EncryptionMethod::DESTriphleDES => {
            let mut key = vec![0u8; 21];
            rng.fill(&mut key[..]);
            key
        }
    }
}

pub fn generate_api_key() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();

    let random_string: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    format!("{}{}", timestamp, random_string)
}