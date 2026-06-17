use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, OsRng, Payload},
};
use arc_swap::ArcSwap;
use derive_debug::Dbg;
use diesel_async::{AsyncPgConnection, pooled_connection::deadpool::Pool};
use tokio::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::database::{DataAccessError, model::data_encryption_key::DataEncryptionKeys};

#[derive(Dbg)]
pub struct KeyManager {
    key_encryption_key: ArcSwap<KeyEncryptionKey>,
    data_encryption_keys: ArcSwap<DataEncryptionKeys>,
    last_fetch_time: ArcSwap<Instant>,
    refresh_duration: Duration,
    #[dbg(skip)]
    connection_pool: Pool<AsyncPgConnection>,
    #[dbg(skip)]
    refresh_lock: tokio::sync::Mutex<()>,
}

impl KeyManager {
    pub async fn initialize(
        key_encryption_key_bytes: Vec<u8>,
        refresh_duration: Duration,
        connection_pool: Pool<AsyncPgConnection>,
    ) -> Result<KeyManager, DataAccessError> {
        let mut connection = connection_pool.clone().get().await.unwrap();

        let key_encryption_key = KeyEncryptionKey::new(key_encryption_key_bytes);
        tracing::info!("Loading KeyManager with: {:?}", key_encryption_key);
        let data_encryption_keys =
            DataEncryptionKeys::fetch_data_encryption_keys(&mut connection, &key_encryption_key)
                .await?;

        let key_manager = KeyManager {
            key_encryption_key: ArcSwap::from(Arc::new(key_encryption_key)),
            data_encryption_keys: ArcSwap::from(Arc::new(data_encryption_keys)),
            last_fetch_time: ArcSwap::from(Arc::new(Instant::now())),
            refresh_duration,
            connection_pool,
            refresh_lock: Mutex::new(()),
        };
        if key_manager.data_encryption_keys.load().len() == 0 {
            tracing::info!(
                "Initialized KeyManager but no DataEncryptionKeys found. Generating new DataEncryptionKey..."
            );
            key_manager.create_new_data_encryption_key().await?;
        }

        tracing::info!("Initialized KeyManager: {:?}", key_manager);

        Ok(key_manager)
    }

    pub async fn update_data_encryption_keys(&self) -> Result<(), DataAccessError> {
        let data_encryption_keys = DataEncryptionKeys::fetch_data_encryption_keys(
            &mut self.connection_pool.get().await.unwrap(),
            &**self.key_encryption_key.load(),
        )
        .await?;
        if **self.data_encryption_keys.load() != data_encryption_keys {
            tracing::info!("Updated DataEncryptionKeys: {:?}", data_encryption_keys);
            self.data_encryption_keys
                .store(Arc::new(data_encryption_keys));
        }

        self.last_fetch_time.store(Arc::new(Instant::now()));

        Ok(())
    }

    pub async fn create_new_data_encryption_key(&self) -> Result<(), DataAccessError> {
        tracing::info!("Creating new DataEncryptionKey...");
        DataEncryptionKeys::create_new_encryption_key(
            &mut self.connection_pool.get().await.unwrap(),
            &self.key_encryption_key.load(),
        )
        .await?;

        self.update_data_encryption_keys().await
    }

    async fn refresh_on_stale_data(&self) -> Result<(), DataAccessError> {
        if self
            .last_fetch_time
            .load()
            .elapsed()
            .gt(&self.refresh_duration)
        {
            // Lock so we dont have multiple instances attempt to refresh
            let _mutex_guard = self.refresh_lock.lock().await;
            // Recheck now that we have the lock
            if self
                .last_fetch_time
                .load()
                .elapsed()
                .gt(&self.refresh_duration)
            {
                tracing::debug!("Updating KeyManagers cache...");
                return self.update_data_encryption_keys().await;
            }
        }

        Ok(())
    }

    pub async fn encrypt_data(
        &self,
        data_to_encrypt: &[u8],
    ) -> Result<(uuid::Uuid, Vec<u8>, Vec<u8>), DataAccessError> {
        self.refresh_on_stale_data().await?;

        let data_encryption_keys = self.data_encryption_keys.load_full();
        let dek = data_encryption_keys
            .get_active_key()
            .ok_or(DataAccessError::CryptoError)?;
        #[allow(deprecated)]
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek.key));

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let encrypted_text = cipher
            .encrypt(
                #[allow(deprecated)]
                Nonce::from_slice(&nonce),
                data_to_encrypt,
            )
            .map_err(|_| DataAccessError::CryptoError)?;

        Ok((dek.kid, encrypted_text, nonce.to_vec()))
    }

    pub async fn decrypt_data(
        &self,
        kid: &uuid::Uuid,
        data_to_decrypt: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, DataAccessError> {
        self.refresh_on_stale_data().await?;

        let data_encryption_keys = self.data_encryption_keys.load_full();
        let dek_key = data_encryption_keys
            .get_decryption_key(kid)
            .ok_or(DataAccessError::CryptoError)?;
        #[allow(deprecated)]
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek_key));

        cipher
            .decrypt(
                #[allow(deprecated)]
                Nonce::from_slice(nonce),
                data_to_decrypt,
            )
            .map_err(|_| DataAccessError::CryptoError)
    }
}

#[derive(Dbg, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
/// KeyEncryptionKey : A key used to encrypt other DataEncryptionKey
pub struct KeyEncryptionKey {
    /// KeyEncryptionKey's hash used to identify it
    #[zeroize(skip)]
    #[dbg(formatter = "hex::encode")]
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
        let key = Aes256Gcm::generate_key(OsRng);
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
        let key = Key::<Aes256Gcm>::from_slice(&key_encryption_key.key);
        let cipher = Aes256Gcm::new(&key);
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
        let key = Key::<Aes256Gcm>::from_slice(&key_encryption_key.key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
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
    use tokio::time::sleep;

    use super::*;

    pub fn create_test_key_encryption_key() -> KeyEncryptionKey {
        let key = Aes256Gcm::generate_key(OsRng);
        KeyEncryptionKey::new(key.to_vec())
    }

    pub async fn create_test_key_manager(connection_pool: Pool<AsyncPgConnection>) -> KeyManager {
        let key = Aes256Gcm::generate_key(OsRng);
        KeyManager::initialize(key.to_vec(), Duration::from_secs(60), connection_pool)
            .await
            .unwrap()
    }

    #[test]
    fn test_data_encryption_keys_round_trip() {
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

    #[tokio::test]
    async fn test_key_manager() {
        let pool = crate::database::tests::get_test_db_connection_pool("test_key_manager");

        let key = Aes256Gcm::generate_key(OsRng);
        let key_manager_1 =
            KeyManager::initialize(key.to_vec(), Duration::from_millis(500), pool.clone())
                .await
                .unwrap();

        assert_eq!(key_manager_1.key_encryption_key.load().key, key.to_vec());
        assert_eq!(key_manager_1.data_encryption_keys.load().len(), 1);

        let active_key_1 = key_manager_1
            .data_encryption_keys
            .load()
            .get_active_key()
            .unwrap()
            .clone();
        // Uses the active key to encrypt the data
        let (kid, encrypted_data, nonce) = key_manager_1.encrypt_data(b"dummy data").await.unwrap();
        assert_eq!(kid, active_key_1.kid);
        assert_eq!(
            b"dummy data",
            key_manager_1
                .decrypt_data(&kid, &encrypted_data, nonce.as_array().unwrap())
                .await
                .unwrap()
                .as_array()
                .unwrap()
        );

        // Create a new key
        key_manager_1
            .create_new_data_encryption_key()
            .await
            .unwrap();
        // Now contains 2 keys
        assert_eq!(key_manager_1.data_encryption_keys.load().len(), 2);
        // Old keys still in KeyManager
        assert!(
            key_manager_1
                .data_encryption_keys
                .load()
                .get_decryption_key(&active_key_1.kid)
                .is_some()
        );
        // Now the active key is a new key
        let active_key_2 = key_manager_1
            .data_encryption_keys
            .load()
            .get_active_key()
            .unwrap()
            .clone();
        assert_ne!(active_key_1.kid, active_key_2.kid);

        // Reloads from the database
        let key_manager_2 =
            KeyManager::initialize(key.to_vec(), Duration::from_secs(60), pool.clone())
                .await
                .unwrap();

        assert_eq!(key_manager_2.key_encryption_key.load().key, key.to_vec());
        assert_eq!(key_manager_2.data_encryption_keys.load().len(), 2);
        assert_eq!(
            key_manager_2
                .data_encryption_keys
                .load()
                .get_active_key()
                .unwrap(),
            &active_key_2
        );

        // Uses the new active key to encrypt the data
        let (kid, encrypted_data, nonce) = key_manager_2.encrypt_data(b"dummy data").await.unwrap();
        assert_eq!(kid, active_key_2.kid);
        assert_eq!(
            b"dummy data",
            key_manager_2
                .decrypt_data(&kid, &encrypted_data, nonce.as_array().unwrap())
                .await
                .unwrap()
                .as_array()
                .unwrap()
        );

        // After a duration the old KeyManager will refresh
        sleep(Duration::from_millis(500)).await;
        let (kid, _, _) = key_manager_1.encrypt_data(b"dummy data").await.unwrap();
        assert_eq!(kid, active_key_2.kid);
    }
}
