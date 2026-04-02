use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{
    AsyncConnection, AsyncPgConnection, RunQueryDsl, scoped_futures::ScopedFutureExt,
};
use serde::{Deserialize, Serialize};

use crate::database::{DataAccessError, schema::user_permissions};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
/// User Permissions : Assigned permissions for a given user
pub struct UserPermissions {
    /// User's id
    pub user_id: uuid::Uuid,
    /// User's permissions
    pub permissions: Vec<String>,
}

impl UserPermissions {
    /// Fetch all permissions associated with a given user.
    ///
    /// # Arguments
    ///
    /// * `connection` - A mutable reference to an active PostgreSQL database connection.
    /// * `user_id` - The user id to fetch permissions for.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let permissions = UserPermissions::get_permissions(&mut connection, &user_id).await?;
    /// println!("User permissions: {:?}", permissions.permissions);
    /// ```
    pub async fn get_permissions(
        connection: &mut AsyncPgConnection,
        user_id: &uuid::Uuid,
    ) -> Result<UserPermissions, DataAccessError> {
        Ok(UserPermissions {
            user_id: user_id.clone(),
            permissions: user_permissions::table
                .filter(user_permissions::user_id.eq(user_id))
                .select(user_permissions::permission)
                .get_results(connection)
                .await
                .map_err(DataAccessError::from)?,
        })
    }

    /// Add one or more permissions for a given user.
    ///
    /// # Arguments
    ///
    /// * `connection` - A mutable reference to an active PostgreSQL database connection.
    /// * `user_id` - The user id to add permissions for.
    /// * `permissions` - A list of permission identifiers to assign to the user.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let count = UserPermissions::add_permission(
    ///     &mut connection,
    ///     &user_id,
    ///     &vec!["READ".into(), "WRITE".into()],
    /// ).await?;
    ///
    /// println!("Permissions added: {}", count);
    /// ```
    pub async fn add_permission(
        connection: &mut AsyncPgConnection,
        user_id: &uuid::Uuid,
        permissions: &Vec<&str>,
    ) -> Result<usize, DataAccessError> {
        diesel::insert_into(user_permissions::table)
            .values(
                permissions
                    .iter()
                    .map(|permission| {
                        (
                            user_permissions::user_id.eq(user_id),
                            user_permissions::permission.eq(permission),
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .execute(connection)
            .await
            .map_err(DataAccessError::from)
    }

    /// Remove all permissions associated with a given user.
    ///
    /// # Arguments
    ///
    /// * `connection` - A mutable reference to an active PostgreSQL database connection.
    /// * `user_id` - The user id to remove permissions for.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let removed = UserPermissions::remove_all_permissions(&mut connection, &user_id).await?;
    /// println!("Permissions removed: {}", removed);
    /// ```
    pub async fn remove_all_permissions(
        connection: &mut AsyncPgConnection,
        user_id: &uuid::Uuid,
    ) -> Result<usize, DataAccessError> {
        diesel::delete(user_permissions::table)
            .filter(user_permissions::user_id.eq(user_id))
            .execute(connection)
            .await
            .map_err(DataAccessError::from)
    }

    /// Remove specific permissions from a given user.
    ///
    /// # Arguments
    ///
    /// * `connection` - A mutable reference to an active PostgreSQL database connection.
    /// * `user_id` - The user id to remove permissions for.
    /// * `permissions` - A list of permission identifiers to remove.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let removed = UserPermissions::remove_permissions(
    ///     &mut connection,
    ///     &user_id,
    ///     &vec!["READ".into()],
    /// ).await?;
    ///
    /// println!("Permissions removed: {}", removed);
    /// ```
    pub async fn remove_permissions(
        connection: &mut AsyncPgConnection,
        user_id: &uuid::Uuid,
        permissions: &Vec<&str>,
    ) -> Result<usize, DataAccessError> {
        diesel::delete(user_permissions::table)
            .filter(user_permissions::user_id.eq(user_id))
            .filter(user_permissions::permission.eq_any(permissions))
            .execute(connection)
            .await
            .map_err(DataAccessError::from)
    }

    /// Replace all permissions for a given user with the provided set.
    ///
    /// This operation is performed atomically within a database transaction.
    /// All existing permissions are removed before the new permissions are added.
    ///
    /// # Arguments
    ///
    /// * `connection` - A mutable reference to an active PostgreSQL database connection.
    /// * `user_id` - The user id to set permissions for.
    /// * `permissions` - A list of permission identifiers to assign to the user.
    ///
    /// # Example
    ///
    /// ```ignore
    /// UserPermissions::set_permissions(
    ///     &mut connection,
    ///     &user_id,
    ///     &vec!["READ".into(), "WRITE".into()],
    /// ).await?;
    /// ```
    pub async fn set_permissions(
        connection: &mut AsyncPgConnection,
        user_id: &uuid::Uuid,
        permissions: &Vec<&str>,
    ) -> Result<(), DataAccessError> {
        connection
            .transaction(|connection| {
                async move {
                    UserPermissions::remove_all_permissions(connection, user_id).await?;
                    UserPermissions::add_permission(connection, user_id, permissions).await?;
                    Ok(())
                }
                .scope_boxed()
            })
            .await
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
        crate::database::tests::get_test_db_connection_pool("test_user_permissions")
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_user_permissions(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user_1 = crate::database::model::tests::create_test_user(&mut connection).await;
        let user_2 = crate::database::model::tests::create_test_user(&mut connection).await;

        crate::database::model::tests::assign_test_permissions(&mut connection, &user_1).await;

        let user_1_permissions = UserPermissions::get_permissions(&mut connection, &user_1.id)
            .await
            .unwrap();

        assert_eq!(user_1_permissions.user_id, user_1.id);
        assert_eq!(
            user_1_permissions.permissions,
            vec![
                "test:read".to_string(),
                "test:write".to_string(),
                "test2:read".to_string()
            ]
        );

        let user_2_permissions = UserPermissions::get_permissions(&mut connection, &user_2.id)
            .await
            .unwrap();
        assert_eq!(user_2_permissions.permissions, Vec::<String>::new());
    }

    #[rstest]
    #[tokio::test]
    async fn test_add_user_permissions(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        UserPermissions::add_permission(&mut connection, &user.id, &vec!["test1", "test2"])
            .await
            .unwrap();
        assert_eq!(
            UserPermissions::get_permissions(&mut connection, &user.id)
                .await
                .unwrap()
                .permissions,
            vec!["test1".to_string(), "test2".to_string()]
        );

        UserPermissions::add_permission(&mut connection, &user.id, &vec!["test3", "test4"])
            .await
            .unwrap();
        assert_eq!(
            UserPermissions::get_permissions(&mut connection, &user.id)
                .await
                .unwrap()
                .permissions,
            vec![
                "test1".to_string(),
                "test2".to_string(),
                "test3".to_string(),
                "test4".to_string()
            ]
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_remove_user_permissions(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        crate::database::model::tests::assign_test_permissions(&mut connection, &user).await;

        // Remove one permission
        let remove_permissions =
            UserPermissions::remove_permissions(&mut connection, &user.id, &vec!["test2:read"])
                .await;
        assert!(remove_permissions.is_ok());
        assert_eq!(
            UserPermissions::get_permissions(&mut connection, &user.id)
                .await
                .unwrap()
                .permissions,
            vec!["test:read".to_string(), "test:write".to_string()]
        );

        // Remove non-existing permission
        let remove_permissions = UserPermissions::remove_permissions(
            &mut connection,
            &user.id,
            &vec!["no_such_permission"],
        )
        .await;
        assert!(remove_permissions.is_ok());
        assert_eq!(
            UserPermissions::get_permissions(&mut connection, &user.id)
                .await
                .unwrap()
                .permissions,
            vec!["test:read".to_string(), "test:write".to_string()]
        );

        // Remove all remaining
        let remove_permissions = UserPermissions::remove_permissions(
            &mut connection,
            &user.id,
            &vec!["test:read", "test:write"],
        )
        .await;
        assert!(remove_permissions.is_ok());
        assert_eq!(
            UserPermissions::get_permissions(&mut connection, &user.id)
                .await
                .unwrap()
                .permissions,
            Vec::<String>::new()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_remove_all_user_permissions(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        crate::database::model::tests::assign_test_permissions(&mut connection, &user).await;

        // Remove all permissions
        let remove_permissions =
            UserPermissions::remove_all_permissions(&mut connection, &user.id).await;
        assert!(remove_permissions.is_ok());
        assert_eq!(
            UserPermissions::get_permissions(&mut connection, &user.id)
                .await
                .unwrap()
                .permissions,
            Vec::<String>::new()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_set_user_permissions(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        crate::database::model::tests::assign_test_permissions(&mut connection, &user).await;

        // Set Permissions
        let remove_permissions =
            UserPermissions::set_permissions(&mut connection, &user.id, &vec!["test1", "test2"])
                .await;
        assert!(remove_permissions.is_ok());
        assert_eq!(
            UserPermissions::get_permissions(&mut connection, &user.id)
                .await
                .unwrap()
                .permissions,
            vec!["test1".to_string(), "test2".to_string()]
        );
    }
}
