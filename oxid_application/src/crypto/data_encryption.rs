use aes_gcm::{
    AeadCore, Aes128Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, Payload},
};
use derive_debug::Dbg;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::database::DataAccessError;

#[derive(Dbg, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
/// KeyEncryptionKey : A key used to encrypt other DataEncryptionKey
pub struct KeyEncryptionKey {
    /// KeyEncryptionKey's hash used to identify it
    #[zeroize(skip)]
    pub key_hash: [u8; 32],
    /// The key itself
    #[dbg(placeholder = "****")]
    pub key: Vec<u8>,
}

impl KeyEncryptionKey {
    pub fn new(key: Vec<u8>) -> KeyEncryptionKey {
        KeyEncryptionKey {
            key_hash: *blake3::hash(&key).as_bytes(),
            key,
        }
    }
}

#[derive(Dbg, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
/// DataEncryptionKey : A key used to encrypt other data
pub struct DataEncryptionKey {
    /// DataEncryptionKey's id
    #[zeroize(skip)]
    pub kid: uuid::Uuid,
    /// The key itself
    #[dbg(placeholder = "****")]
    pub key: Vec<u8>,
    /// If the key is currently active and meant to be used
    #[zeroize(skip)]
    pub is_active: bool,
}

impl DataEncryptionKey {
    pub(crate) fn new() -> Result<DataEncryptionKey, DataAccessError> {
        let key = Aes128Gcm::generate_key(OsRng);
        Ok(DataEncryptionKey {
            kid: uuid::Uuid::now_v7(),
            key: key.to_vec(),
            is_active: false,
        })
    }

    pub(crate) fn decrypt_data_encryption_key(
        kid: &uuid::Uuid,
        encrypted_data_encryption_key: &Vec<u8>,
        encryption_nonce: &Vec<u8>,
        is_active: bool,
        key_encryption_key: &KeyEncryptionKey,
    ) -> Result<DataEncryptionKey, DataAccessError> {
        #[allow(deprecated)]
        let key = Key::<Aes128Gcm>::from_slice(&key_encryption_key.key);
        let cipher = Aes128Gcm::new(&key);
        let decrypted_key = cipher
            .decrypt(
                #[allow(deprecated)]
                Nonce::from_slice(encryption_nonce),
                Payload {
                    msg: encrypted_data_encryption_key,
                    aad: &key_encryption_key.key_hash,
                },
            )
            .map_err(|e| {
                tracing::error!(
                    "Failed to decrypt DataEncryptionKey {} due to error: {}",
                    kid,
                    e
                );
                DataAccessError::CryptoError
            })?;

        Ok(DataEncryptionKey {
            kid: kid.clone(),
            key: decrypted_key,
            is_active,
        })
    }

    pub(crate) fn encrypt_data_encryption_key(
        &self,
        key_encryption_key: &KeyEncryptionKey,
    ) -> Result<(Vec<u8>, [u8; 12]), DataAccessError> {
        #[allow(deprecated)]
        let key = Key::<Aes128Gcm>::from_slice(&key_encryption_key.key);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
        let encrypted_key = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &self.key,
                    aad: &key_encryption_key.key_hash,
                },
            )
            .map_err(|_| DataAccessError::CryptoError)?;

        Ok((encrypted_key, nonce.into()))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn create_test_key_encryption_key() -> KeyEncryptionKey {
        let key = Aes128Gcm::generate_key(OsRng);
        KeyEncryptionKey::new(key.to_vec())
    }

    #[test]
    fn test_round_trip() {
        let kek = create_test_key_encryption_key();

        let dek = DataEncryptionKey::new().unwrap();

        let (encrypted_key, nonce) = dek.encrypt_data_encryption_key(&kek).unwrap();
        assert_ne!(encrypted_key, dek.key);

        let decrypt_data_encryption_key = DataEncryptionKey::decrypt_data_encryption_key(
            &dek.kid,
            &encrypted_key,
            &nonce.to_vec(),
            dek.is_active,
            &kek,
        )
        .unwrap();

        assert_eq!(decrypt_data_encryption_key, dek);
    }
}
