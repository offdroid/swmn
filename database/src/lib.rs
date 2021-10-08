#[cfg(test)]
#[macro_use]
pub extern crate diesel_migrations;
#[cfg(not(test))]
pub extern crate diesel_migrations;

#[macro_use]
pub extern crate diesel;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate rocket;

pub mod models;
mod schema;

use crate::models::{Client, ClientDelta, ClientNew, ClientPartial, User, UserPasswordless};

use anyhow::{anyhow, Context};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use models::ClientRank;
use rand_core::OsRng;

use diesel::{
    prelude::*, query_builder::QueryFragment, sql_query, sql_types::Text, sqlite::Sqlite,
};

use rocket::FromFormField;
use serde::Deserialize;

type Result<T, E = diesel::result::Error> = std::result::Result<T, E>;

fn hash(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    argon2
        .hash_password_simple(password.as_bytes(), salt.as_ref())
        .map(|h| h.to_string())
}

const DUMMY_PW_1: &str = "0";
const DUMMY_PW_2: &str = "1";
lazy_static! {
    static ref DUMMY_HASH: String = hash(DUMMY_PW_2).unwrap();
}

pub fn add_user(
    conn: &SqliteConnection,
    username: String,
    password: String,
) -> Result<(), anyhow::Error> {
    use crate::schema::users;

    let user = User {
        name: username,
        password: hash(&password).map_err(|err| anyhow!("{:?}", err))?,
        disabled: Some(false),
    };
    diesel::replace_into(users::table)
        .values(user)
        .execute(conn)?;

    Ok(())
}

pub fn get_users(conn: &SqliteConnection) -> Result<Vec<UserPasswordless>, anyhow::Error> {
    use crate::schema::users::dsl as users;

    users::users
        .select((users::name, users::disabled))
        .load::<(String, Option<bool>)>(conn)
        .map(|v| {
            v.iter()
                .map(|(name, disabled)| UserPasswordless {
                    name: name.to_string(),
                    disabled: disabled.unwrap_or(false),
                })
                .collect()
        })
        .map_err(anyhow::Error::from)
}

/// Enable or disable an existing user. Note that this might not immediatly stop access to restricted APIs when using session cookies.
///
/// # Arguments
/// * `conn` - Database connection
/// * `username` - Username/id to delete
/// * `enabled` - New status of the user
///
/// # Return value
/// Assuming no database errors an `Ok(x)` value is returned, where `x` is a bool indicating whether the status changed.
pub fn set_user_status(
    conn: &SqliteConnection,
    username: String,
    enabled: bool,
) -> Result<bool, anyhow::Error> {
    use crate::schema::users::dsl as users;

    diesel::update(users::users.find(username))
        .set(users::disabled.eq(enabled))
        .execute(conn)
        .map(|n| n == 1)
        .map_err(anyhow::Error::from)
}

/// Remove an existing user. Note that this might not immediatly stop access to restricted APIs when using session cookies.
///
/// # Arguments
/// * `conn` - Database connection
/// * `username` - Username/id to delete
///
/// # Return value
/// Assuming no database errors an `Ok(x)` value is returned, where `x` is a bool indicating whether an user was deleted.
pub fn remove_user(conn: &SqliteConnection, username: String) -> Result<bool, anyhow::Error> {
    use crate::schema::users::dsl as users;
    diesel::delete(users::users.find(username))
        .execute(conn)
        .map(|n| n == 1)
        .map_err(anyhow::Error::from)
}

/// Outcome of a password verification
#[derive(Debug, PartialEq)]
pub enum PasswordVerification {
    Success,
    FailureNotFound,
    FailureNoMatch,
    FailureDisabled,
}

/// Verify a username password combination against the respective password hash from the
/// database. Performs a dummy verification if the user does not exist.
pub fn verify_user(
    conn: &SqliteConnection,
    username: &str,
    password: &str,
) -> Result<PasswordVerification, anyhow::Error> {
    use crate::schema::users::dsl as users;

    return match users::users.find(username).first::<User>(conn) {
        Err(diesel::result::Error::NotFound) => {
            trace!(
                "Password verification (id = `{}`) failed: user not found",
                username
            );
            // Dummy verification to hide the fact that the user does not exist
            let hash = PasswordHash::new(&DUMMY_HASH).map_err(|err| anyhow!("{:?}", err))?;
            assert_eq!(
                Argon2::default()
                    .verify_password(DUMMY_PW_1.as_bytes(), &hash)
                    .expect_err("dummy password verification (should have failed but didn't)"),
                argon2::password_hash::Error::Password,
                "Dummy password verification failed"
            );
            Ok(PasswordVerification::FailureNotFound)
        }
        Err(e) => {
            trace!(
                "Password verification (id = `{}`) failed: database error: {}",
                username,
                e
            );
            Err(e.into())
        }
        Ok(reference) => {
            let hash = PasswordHash::new(reference.password.as_str())
                .map_err(|err| anyhow!("{:?}", err))?;
            let verification = Argon2::default().verify_password(password.as_bytes(), &hash);
            match (verification, reference.disabled) {
                (Ok(()), Some(true)) => {
                    trace!(
                        "Password verification (id = `{}`) failed: user disabled",
                        username
                    );
                    Ok(PasswordVerification::FailureDisabled)
                }
                (Ok(()), _) => {
                    trace!("Password verification (id = `{}`) succeded", username);
                    Ok(PasswordVerification::Success)
                }
                (Err(argon2::password_hash::Error::Password), _) => {
                    trace!(
                        "Password verification (id = `{}`) failed: wrong credentials",
                        username
                    );
                    Ok(PasswordVerification::FailureNoMatch)
                }
                (Err(e), _) => {
                    trace!("Password verification (id = `{}`) failed: {}", username, e);
                    Err(anyhow!("{:?}", e))
                }
            }
        }
    };
}

pub fn user_is_enabled(conn: &SqliteConnection, username: &str) -> Result<bool, anyhow::Error> {
    use crate::schema::users::dsl as users;

    let reference: User = users::users
        .find(username)
        .first(conn)
        .map_err(anyhow::Error::from)?;

    match reference.disabled {
        Some(v) => Ok(!v),
        None => Ok(true),
    }
}

/// Create client with a custom database object
pub fn create_client_custom(
    conn: &SqliteConnection,
    client: &ClientPartial,
) -> Result<(), anyhow::Error> {
    use crate::schema::clients;
    diesel::insert_into(clients::table)
        .values(client)
        .execute(conn)
        .context("Failed to insert client")?;
    Ok(())
}

/// Create a new client with additional default values
pub fn create_client(
    conn: &SqliteConnection,
    client: ClientNew,
    creator: &str,
) -> Result<(), anyhow::Error> {
    use crate::schema::clients;
    diesel::insert_into(clients::table)
        .values(client.into_client(creator))
        .execute(conn)?;
    Ok(())
}

/// Update specfied values of an existing client in the database.
///
/// # Arguments
/// * `conn` - Database to perform the operation on
/// * `id` - Identifier of the client to change
/// * `changes` - Changes to apply to the client, only fields not-None are taking into account
pub fn update_client(
    conn: &SqliteConnection,
    client_id: String,
    changes: &ClientDelta,
) -> Result<(), anyhow::Error> {
    use crate::schema::clients::dsl::*;
    diesel::update(clients.filter(id.eq(client_id)))
        .set(changes)
        .execute(conn)
        .context("Update client")?;
    Ok(())
}

/// Delete a client by its id.
pub fn delete_client(conn: &SqliteConnection, id: &str) -> Result<usize, anyhow::Error> {
    use crate::schema::clients::dsl as clients;
    diesel::delete(clients::clients.find(id))
        .execute(conn)
        .map_err(|err| err.into())
}

/// Change the disabled status of an existing client in the database.
/// Returns a boolean whether the disabled status changed (false if it already had the requested value)
///
/// # Arguments
/// * `conn` - Database to perform the operation on
/// * `id` - Identifier of the client to change
/// * `changes` - Changes to apply to the client, only fields not-None are taking into account
pub fn set_disabled_client(
    conn: &SqliteConnection,
    client_id: &str,
    status: bool,
) -> Result<bool, anyhow::Error> {
    use crate::schema::clients::dsl::*;
    diesel::update(clients.filter(id.eq(client_id).and(disabled.eq(!status))))
        .set(disabled.eq(status))
        .execute(conn)
        .context("Failed to update the client status")
        .map(|n| n == 1)
}

/// Get a client by its id.
pub fn get_client(conn: &SqliteConnection, id: &str) -> Result<Client, anyhow::Error> {
    use crate::schema::clients::dsl as clients;
    clients::clients
        .find(id)
        .first::<Client>(conn)
        .map_err(|err| err.into())
}

/// Get all clients.
/// For filtered lists see [`get_clients_filtered`].
pub fn get_clients(conn: &SqliteConnection) -> Result<Vec<Client>, anyhow::Error> {
    get_clients_filtered(conn, None, None, None, None, None, None)
}

#[derive(Debug, Deserialize, FromFormField, PartialEq, Clone)]
pub enum ClientOrderCategories {
    Id,
    DateCreated,
    Creator,
    Description,
    Associated,
}

fn query_clients_filtered(
    order_by_category: Option<ClientOrderCategories>,
    asc: Option<bool>,
    disabled: Option<bool>,
    from_creator: Option<String>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> crate::schema::clients::BoxedQuery<'static, Sqlite> {
    use crate::schema::clients::dsl as clients;
    use crate::schema::clients::BoxedQuery;

    // Use defaults if None
    let order_by_category = order_by_category.unwrap_or(ClientOrderCategories::Id);
    let asc = asc.unwrap_or(false);

    fn order_by<T: 'static>(
        query: BoxedQuery<'static, Sqlite>,
        sort_on: T,
        ascending: bool,
    ) -> BoxedQuery<'static, Sqlite>
    where
        T: ExpressionMethods
            + QueryFragment<Sqlite>
            + AppearsOnTable<crate::schema::clients::table>,
    {
        if ascending {
            query.order_by(sort_on.asc())
        } else {
            query.order_by(sort_on.desc())
        }
    }

    let query = clients::clients.into_boxed();
    let query = match order_by_category {
        ClientOrderCategories::DateCreated => order_by(query, clients::date_created, asc),
        ClientOrderCategories::Creator => order_by(query, clients::creator_id, asc),
        ClientOrderCategories::Description => order_by(query, clients::description, asc),
        ClientOrderCategories::Associated => order_by(query, clients::associated_with, asc),
        _ => order_by(query, clients::id, asc),
    };
    let query = match (offset, limit) {
        (Some(offset), Some(limit)) => query.offset(offset.into()).limit(limit.into()),
        (None, Some(limit)) => query.limit(limit.into()),
        (Some(offset), None) => query.offset(offset.into()).limit(i64::MAX),
        _ => query,
    };
    let query = match disabled {
        Some(v) => query.filter(clients::disabled.eq(v)),
        None => query,
    };
    match from_creator {
        Some(v) => query.filter(clients::creator_id.eq(v)),
        None => query,
    }
}

/// Get all clients that meet the specified conditions.
///
/// # Arguments
/// * `conn` - Database to perform the operation on
/// * `order_by_category` - Category to order by; default = `id`.
///   Possible options:
///   - `date_created`
///   - `creator_id`
///   - `description`
///   - `associated_with`
/// * `asc` - Order, either ascending or descending; default = [false]
/// * `disabled` - Only return disabled nor enabled clients, use [None] to ignore this filter
/// * `from_creator` - Only return clients created by a specific user, use [None] to ignore this
/// filter
pub fn get_clients_filtered(
    conn: &SqliteConnection,
    order_by_category: Option<ClientOrderCategories>,
    asc: Option<bool>,
    disabled: Option<bool>,
    from_creator: Option<String>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<Vec<Client>, anyhow::Error> {
    let q = query_clients_filtered(
        Some(ClientOrderCategories::Id),
        asc,
        disabled,
        Some("test".to_string()),
        offset,
        limit,
    );
    let dq = diesel::debug_query::<Sqlite, _>(&q);
    trace!("debug: {}", dq.to_string());
    query_clients_filtered(
        order_by_category,
        asc,
        disabled,
        from_creator,
        offset,
        limit,
    )
    .load::<Client>(conn)
    .map_err(|err| {
        trace!("E: {}", err);
        return err;
    })
    .map_err(anyhow::Error::from)
}

pub fn get_clients_filtered_count(
    conn: &SqliteConnection,
    order_by_category: Option<ClientOrderCategories>,
    asc: Option<bool>,
    disabled: Option<bool>,
    from_creator: Option<String>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<i64, anyhow::Error> {
    query_clients_filtered(
        order_by_category,
        asc,
        disabled,
        from_creator,
        offset,
        limit,
    )
    .count()
    .get_result(conn)
    .map_err(anyhow::Error::from)
}

pub fn search(conn: &SqliteConnection, query: &str) -> Result<Vec<ClientRank>, anyhow::Error> {
    sql_query("SELECT c.id, c.description, c.associated_with, c.creator_id, c.date_created, c.disabled, rank FROM clients_fts AS cfts, clients AS c WHERE clients_fts = ? AND cfts.id = c.id ORDER BY rank")
        .bind::<Text, _>(query).load::<ClientRank>(conn).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Initialize a clean in-memory database with the schema for testing purposes
    fn clean_db() -> SqliteConnection {
        let connection = SqliteConnection::establish(":memory:").expect("database connection");
        embed_migrations!();
        embedded_migrations::run(&connection).expect("setup database schema");
        connection
    }

    #[test]
    fn user_management() -> Result<(), anyhow::Error> {
        let connection = clean_db();

        let name = "test_user".to_string();
        let pass_1 = "123456".to_string();
        let pass_2 = pass_1.to_owned() + "_new";

        let n_users_prior = get_users(&connection)?.len();
        // Add a sample user
        assert_eq!(add_user(&connection, name.clone(), pass_1.clone())?, ());
        // Verify that the user is not disabled
        assert_eq!(user_is_enabled(&connection, &name).ok(), Some(true));
        // Check if the user is in the list of all users
        assert!(get_users(&connection)?.contains(&UserPasswordless {
            name: name.clone(),
            disabled: false,
        }));
        assert_eq!(get_users(&connection)?.len(), n_users_prior + 1);
        // Login with the correct password
        assert_eq!(
            verify_user(&connection, &name.clone(), &pass_1.clone()).ok(),
            Some(PasswordVerification::Success)
        );
        // Login with a wrong password
        assert_eq!(
            verify_user(
                &connection,
                &name.clone(),
                &(pass_2.to_owned() + "_some_text_to_change_the_password")
            )
            .ok(),
            Some(PasswordVerification::FailureNoMatch)
        );

        // Change the password and check login with the new and old password
        assert_eq!(add_user(&connection, name.clone(), pass_2.clone())?, ());
        assert_eq!(get_users(&connection)?.len(), n_users_prior + 1);
        assert_eq!(
            verify_user(&connection, &name.clone(), &pass_2.clone()).ok(),
            Some(PasswordVerification::Success)
        );
        assert_eq!(
            verify_user(&connection, &name.clone(), &pass_1.clone()).ok(),
            Some(PasswordVerification::FailureNoMatch)
        );

        Ok(())
    }
}
