use crate::*;
use assert_cmd::{assert::Assert, Command};
use database::{models::UserPasswordless, PasswordVerification};
use diesel::{sql_query, Connection, RunQueryDsl, SqliteConnection};
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Establish connection to an in-memory database setup with a sample data
fn establish_connection(source: Option<&str>) -> SqliteConnection {
    let connection =
        SqliteConnection::establish(source.unwrap_or(":memory:")).expect("database connection");
    embed_migrations!();
    diesel_migrations::run_pending_migrations(&connection).expect("database migrations");
    connection
}

fn test_instance() -> (NamedTempFile, NamedTempFile) {
    let mut config = NamedTempFile::new().unwrap();
    let db = NamedTempFile::new().unwrap();
    writeln!(
        config,
        "[global.databases]\nswmn_db = {{ url = \"{}\" }}\n",
        db.path().to_str().expect("temp database path")
    )
    .unwrap();
    config.flush().unwrap();
    (config, db)
}

macro_rules! swmn_cmd {
    ($instance:ident) => {
        Command::cargo_bin("swmn")
            .unwrap()
            .env("ROCKET_CONFIG", $instance.0.path().to_str().unwrap())
    };
}

#[test]
#[ignore]
fn user_list() {
    let instance = test_instance();
    let conn = establish_connection(instance.1.path().to_str());
    sql_query("INSERT INTO users (name, password, disabled) VALUES ('test', '1234', false), ('tset', '4321', false), ('user', 'password', true);")
        .execute(&conn)
        .expect("database insert sample data");

    let success = swmn_cmd!(instance)
        .args(&["user", "list"])
        .assert()
        .success();
    let output = success.get_output();
    // Search the output to see if all users (their usernames) in the database are listed
    for user in database::get_users(&conn).expect("user list") {
        Assert::new(output.clone()).stdout(predicate::str::contains(user.name));
    }
}

#[test]
#[ignore]
fn user_set_remove() {
    let instance = test_instance();
    let conn = establish_connection(instance.1.path().to_str());
    assert!(!database::get_users(&conn)
        .expect("user list")
        .contains(&UserPasswordless {
            name: "test".to_owned(),
            disabled: false,
        }));
    let username = "testio";
    let password_first = "1234";
    let password_second = "5678";
    swmn_cmd!(instance)
        .args(&["user", "set", username, password_first])
        .assert()
        .success();

    // Check the login
    let verification =
        database::verify_user(&conn, &username.to_owned(), &password_first.to_owned());
    assert!(verification.is_ok());
    assert_eq!(verification.unwrap(), PasswordVerification::Success);

    swmn_cmd!(instance)
        .args(&["user", "set", username, password_second])
        .assert()
        .success();
    // Old password should no longer work
    let verification =
        database::verify_user(&conn, &username.to_owned(), &password_first.to_owned());
    assert!(verification.is_ok());
    assert_eq!(verification.unwrap(), PasswordVerification::FailureNoMatch);
    // The new one should, however
    let verification =
        database::verify_user(&conn, &username.to_owned(), &password_second.to_owned());
    assert!(verification.is_ok());
    assert_eq!(verification.unwrap(), PasswordVerification::Success);

    swmn_cmd!(instance)
        .args(&["user", "remove", username])
        .assert()
        .success();
    // Login should now fail, because the user doesn't exist anymore
    let verification =
        database::verify_user(&conn, &username.to_owned(), &password_second.to_owned());
    assert!(verification.is_ok());
    assert_eq!(verification.unwrap(), PasswordVerification::FailureNotFound);
}

#[test]
#[ignore]
fn user_enable_disable() {
    let instance = test_instance();
    let conn = establish_connection(instance.1.path().to_str());
    assert!(!database::get_users(&conn)
        .expect("user list")
        .contains(&UserPasswordless {
            name: "test".to_owned(),
            disabled: false,
        }));
    let username = "player2";
    let password = "abcd";
    swmn_cmd!(instance)
        .args(&["user", "set", username, password])
        .assert()
        .success();

    // The new user should be enabled by default
    let user_is_enabled = database::user_is_enabled(&conn, &username.to_owned());
    assert!(user_is_enabled.is_ok());
    assert!(user_is_enabled.unwrap());
    // Check the login
    let verification = database::verify_user(&conn, &username.to_owned(), &password.to_owned());
    assert!(verification.is_ok());
    assert_eq!(verification.unwrap(), PasswordVerification::Success);

    // Enabling an enabled user shouldn't change anything
    swmn_cmd!(instance)
        .args(&["user", "enable", username])
        .assert()
        .success();
    let user_is_enabled = database::user_is_enabled(&conn, &username.to_owned());
    eprintln!("e == --- {:?}", user_is_enabled);
    assert!(user_is_enabled.is_ok());
    assert!(user_is_enabled.unwrap());

    swmn_cmd!(instance)
        .args(&["user", "disable", username])
        .assert()
        .success();
    // User should now be disabled
    let user_is_disabled = database::user_is_enabled(&conn, &username.to_owned());
    assert!(user_is_disabled.is_ok());
    assert!(!user_is_disabled.unwrap());
    // And consequently not able to login
    let verification = database::verify_user(&conn, &username.to_owned(), &password.to_owned());
    assert!(verification.is_ok());
    assert_eq!(verification.unwrap(), PasswordVerification::FailureDisabled);

    // Re-enable the user
    swmn_cmd!(instance)
        .args(&["user", "enable", username])
        .assert()
        .success();
    // Should be enabled again and able to login
    let user_is_enabled = database::user_is_enabled(&conn, &username.to_owned());
    assert!(user_is_enabled.is_ok());
    assert!(user_is_enabled.unwrap());
    let verification = database::verify_user(&conn, &username.to_owned(), &password.to_owned());
    assert!(verification.is_ok());
    assert_eq!(verification.unwrap(), PasswordVerification::Success);
}
