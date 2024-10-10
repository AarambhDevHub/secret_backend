use aes::Aes256;
use block_modes::{BlockMode, Ecb};
use block_padding::Pkcs7;
use blowfish::Blowfish;
use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};
use des::TdesEde3;

use crate::models::EncryptionMethod;

const NONCE: [u8; 12] = [0; 12];

pub fn decrypt(method: &EncryptionMethod, key: &[u8], data: &[u8]) -> Vec<u8> {
    match method {
        EncryptionMethod::AES256 => {
            let key: [u8; 32] = key.try_into().expect("Key length must be 32 bytes");
            let cipher = Ecb::<Aes256, Pkcs7>::new_from_slices(&key, &[]).unwrap();
            cipher.decrypt_vec(data).expect("Decryption failed.")
        }
        EncryptionMethod::Chacha20 => {
            let key: [u8; 32] = key.try_into().expect("Key length must be 32 bytes");
            let mut cipher = ChaCha20::new(&key.into(), &NONCE.into());
            let mut decrypted_data = data.to_vec();
            cipher.apply_keystream(&mut decrypted_data);
            decrypted_data
        }
        EncryptionMethod::Blowfish => {
            let mut blowfish_key =[0u8; 32];
            let key_len = key.len().min(32);
            blowfish_key[..key_len].copy_from_slice(&key[..key_len]);

            let cipher = Ecb::<Blowfish, Pkcs7>::new_from_slices(&blowfish_key, &[]).unwrap();
            cipher.decrypt_vec(data).expect("Decryption failed.")
        }
        EncryptionMethod::DESTriphleDES => {
            let mut des_key = [0u8; 24];
            let key_len = key.len().min(24);
            des_key[..key_len].copy_from_slice(&key[..key_len]);

            let cipher = Ecb::<TdesEde3, Pkcs7>::new_from_slices(&des_key, &[]).unwrap();
            cipher.decrypt_vec(data).expect("Decryption failed.")
        }
    }
} 