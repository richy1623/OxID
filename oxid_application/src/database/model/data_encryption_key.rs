use std::collections::HashMap;

use derive_debug::Dbg;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{
    AsyncConnection, AsyncPgConnection, RunQueryDsl, scoped_futures::ScopedFutureExt,
};
use zeroize::Zeroize;

use crate::{
    crypto::data_encryption::{DataEncryptionKey, KeyEncryptionKey},
    database::{DataAccessError, schema::data_encryption_keys},
};

#[derive(Dbg, PartialEq, Eq, Clone)]
pub struct DataEncryptionKeys {
    keys: HashMap<uuid::Uuid, DataEncryptionKey>,
}
impl Zeroize for DataEncryptionKeys {
    fn zeroize(&mut self) {
        for value in self.keys.values_mut() {
            value.zeroize();
        }
        self.keys.clear();
    }
}
impl Drop for DataEncryptionKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl DataEncryptionKeys {
    pub async fn fetch_data_encryption_keys(
        connection: &mut AsyncPgConnection,
        key_encryption_key: &KeyEncryptionKey,
    ) -> Result<DataEncryptionKeys, DataAccessError> {
        let data_encryption_key_db_models: Vec<(uuid::Uuid, Vec<u8>, Vec<u8>, bool)> =
            data_encryption_keys::table
                .select((
                    data_encryption_keys::kid,
                    data_encryption_keys::encrypted_data_encryption_key,
                    data_encryption_keys::encryption_nonce,
                    data_encryption_keys::is_active,
                ))
                .get_results(connection)
                .await
                .map_err(DataAccessError::from)?;

        let data_encryption_keys = data_encryption_key_db_models
            .into_iter()
            .map(
                |(kid, encrypted_data_encryption_key, encryption_nonce, is_active)| {
                    DataEncryptionKey::decrypt_data_encryption_key(
                        &kid,
                        &encrypted_data_encryption_key,
                        &encryption_nonce,
                        is_active,
                        key_encryption_key,
                    )
                    .map(|data_encryption_key| (data_encryption_key.kid, data_encryption_key))
                },
            )
            .collect::<Result<HashMap<uuid::Uuid, DataEncryptionKey>, DataAccessError>>()?;

        Ok(DataEncryptionKeys {
            keys: data_encryption_keys,
        })
    }

    pub async fn create_new_encryption_key(
        connection: &mut AsyncPgConnection,
        key_encryption_key: &KeyEncryptionKey,
    ) -> Result<DataEncryptionKey, DataAccessError> {
        let data_encryption_key = DataEncryptionKey::new()?;
        let (encrypted_key, nonce) =
            data_encryption_key.encrypt_data_encryption_key(&key_encryption_key)?;
        connection
            .transaction(|connection| {
                async move {
                    // Update all other keys to inactive
                    diesel::update(
                        data_encryption_keys::table
                            .filter(data_encryption_keys::is_active.eq(true)),
                    )
                    .set(data_encryption_keys::is_active.eq(false))
                    .execute(connection)
                    .await
                    .map_err(DataAccessError::from)?;

                    // Add the new key as active
                    diesel::insert_into(data_encryption_keys::table)
                        .values((
                            data_encryption_keys::kid.eq(&data_encryption_key.kid),
                            data_encryption_keys::encrypted_data_encryption_key.eq(encrypted_key),
                            data_encryption_keys::encryption_nonce.eq(nonce),
                            data_encryption_keys::is_active.eq(true),
                        ))
                        .execute(connection)
                        .await
                        .map_err(DataAccessError::from)?;

                    // Return Ok
                    Ok::<(), DataAccessError>(())
                }
                .scope_boxed()
            })
            .await?;

        Ok(DataEncryptionKey {
            is_active: true,
            kid: data_encryption_key.kid,
            key: data_encryption_key.key.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use diesel_async::pooled_connection::deadpool::Pool;
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    #[once]
    pub fn pool() -> Pool<AsyncPgConnection> {
        crate::database::tests::get_test_db_connection_pool("test_data_encryption_keys")
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_new_encryption_key(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let kek = crate::crypto::data_encryption::tests::create_test_key_encryption_key();

        let dek_1 = DataEncryptionKeys::create_new_encryption_key(&mut connection, &kek)
            .await
            .unwrap();
        assert_eq!(dek_1.is_active, true);

        let data_encryption_keys =
            DataEncryptionKeys::fetch_data_encryption_keys(&mut connection, &kek)
                .await
                .unwrap();
        assert_eq!(
            data_encryption_keys.keys.get(&dek_1.kid).unwrap().key,
            dek_1.key
        );
        assert_eq!(
            data_encryption_keys.keys.get(&dek_1.kid).unwrap().is_active,
            true
        );

        // Create a second DEK
        let dek_2 = DataEncryptionKeys::create_new_encryption_key(&mut connection, &kek)
            .await
            .unwrap();
        assert_eq!(dek_2.is_active, true);

        let data_encryption_keys =
            DataEncryptionKeys::fetch_data_encryption_keys(&mut connection, &kek)
                .await
                .unwrap();
        assert_eq!(
            data_encryption_keys.keys.get(&dek_1.kid).unwrap().key,
            dek_1.key
        );
        assert_eq!(
            data_encryption_keys.keys.get(&dek_2.kid).unwrap().key,
            dek_2.key
        );
        // Now only the new DEK is active
        assert_eq!(
            data_encryption_keys.keys.get(&dek_1.kid).unwrap().is_active,
            false
        );
        assert_eq!(
            data_encryption_keys.keys.get(&dek_2.kid).unwrap().is_active,
            true
        );
    }
}
