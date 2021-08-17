#![doc = include_str!("../README.md")]
use std::path::PathBuf;

use clap::{clap_app, value_t, ArgMatches};
use rocket::{figment::Figment, Build, Rocket};

use common::CaPass;

#[macro_use]
extern crate rocket;
extern crate rocket_sync_db_pools;

#[macro_use]
extern crate diesel_migrations;
extern crate diesel;

extern crate database;

mod cli;
mod db;

#[cfg(not(feature = "no-rest-api"))]
mod rest;

#[cfg(test)]
mod tests;

fn rocket(figment: Figment) -> Rocket<Build> {
    let config = figment.focus("swmn");
    let script_module = config
        .extract_inner::<String>("script.module")
        .unwrap_or_else(|_| "manage".to_string());
    let script_path = config
        .extract_inner::<PathBuf>("script.path")
        .unwrap_or_else(|_| PathBuf::from("scripts/manage.py"));
    assert!(script_path.exists(), "Script must exist");

    let rocket = rocket::custom(figment)
        .manage(cert::Config::new(script_module, script_path))
        .attach(db::stage());

    #[cfg(not(feature = "no-rest-api"))]
    fn attach_rest(rocket: Rocket<Build>) -> Rocket<Build> {
        rocket.attach(rest::stage()).attach(rest::login::stage())
    }
    #[cfg(not(feature = "no-rest-api"))]
    let rocket = attach_rest(rocket);

    #[cfg(feature = "web-interface")]
    fn attach_web(rocket: Rocket<Build>) -> Rocket<Build> {
        use rocket_dyn_templates::Template;

        rocket
            .attach(Template::custom(|engines| {
                web::customize(&mut engines.handlebars);
            }))
            .attach(web::stage())
    }
    #[cfg(feature = "web-interface")]
    let rocket = attach_web(rocket);

    rocket.manage(if let Ok(passphrase) = extract_passphrase(config) {
        CaPass::new(&passphrase)
    } else {
        CaPass::empty()
    })
}

pub(crate) fn extract_passphrase(config: Figment) -> anyhow::Result<String> {
    fn cmd(config: &Figment) -> anyhow::Result<String> {
        use std::process::Command;
        let passphrase_cmd = config.extract_inner::<String>("ca.passphrase_cmd")?;
        let args = shell_words::split(&passphrase_cmd)?;
        let output = Command::new(args[0].clone())
            .args(&args[1..])
            .stdout(std::process::Stdio::piped())
            .output()?;
        String::from_utf8(output.stdout).map_err(anyhow::Error::from)
    }
    fn keyring() -> anyhow::Result<String> {
        const SERVICE: &str = "swmn";
        const USERNAME: &str = "Certificate Authority";
        keyring::Keyring::new(SERVICE, USERNAME)
            .get_password()
            .map_err(|err| anyhow::anyhow!("{}", err))
    }

    if let Ok(passphrase) = cmd(&config) {
        debug!("Retrieved CA passphrase from command (`ca.passphrase_cmd`)");
        return Ok(passphrase);
    }
    if let Ok(passphrase) = keyring() {
        debug!("Retrieved CA passphrase from keyring");
        return Ok(passphrase);
    }
    if let Ok(passphrase) = config.extract_inner::<String>("ca.passphrase") {
        debug!("Retrieved CA passphrase from plaintext (`ca.passphrase`)");
        return Ok(passphrase);
    }

    Err(anyhow::anyhow!("No passphrase provided"))
}

fn cli<'a>() -> clap::Result<ArgMatches<'a>> {
    let clap = clap_app!(myapp =>
        (version: "0.1.0")
        (author: "Filip Skubacz <filip.skubacz00@gmail.com>")
        (about: "Certificate management interface")
        (@arg LOG_LEVEL: -l --log +takes_value "Log level from 0 (off) to 5 (trace)")
        (@subcommand user =>
            (about: "Administrative user management, exists after completion")
            (@setting SubcommandRequiredElseHelp)
            (@subcommand set =>
                (about: "Set an user's password or create a new one")
                (@arg USERNAME: index(1) +required +takes_value "Username")
                (@arg SOURCE: --file +takes_value "Path to password file")
                (@arg PASS: index(2) +takes_value "Password")
                (@arg NOT_INTERACTIVE: -ni --not-interactive "Disable interactive password input as backup")
            )
            (@subcommand enable =>
                (about: "Enable a user")
                (@arg USERNAME: index(1) +required +takes_value "Username")
            )
            (@subcommand disable =>
                (about: "Disable a user")
                (@arg USERNAME: index(1) +required +takes_value "Username")
            )
            (@subcommand list =>
                (about: "List all users")
            )
            (@subcommand remove =>
                (about: "Remove an existing user; This does not revoke existing session cookies!")
                (@arg USERNAME: index(1) +required +takes_value "Username")
            )
        )
    );
    if cfg!(test) {
        clap.get_matches_safe()
    } else {
        Ok(clap.get_matches())
    }
}

fn setup_logger(level: u32) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(match level {
            0 => log::LevelFilter::Off,
            1 => log::LevelFilter::Error,
            2 => log::LevelFilter::Warn,
            4 => log::LevelFilter::Debug,
            5 => log::LevelFilter::Trace,
            _ => log::LevelFilter::Info,
        })
        .chain(std::io::stdout())
        .chain(fern::log_file("output.log")?)
        .apply()?;
    Ok(())
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = cli()?;
    setup_logger(value_t!(matches, "LOG_LEVEL", u32).unwrap_or(3))?;
    match matches.subcommand() {
        ("user", Some(matches)) => {
            use diesel::{Connection, SqliteConnection};
            let figment = rocket::Config::figment().focus("databases.swmn_db");
            let url = figment
                .extract_inner::<String>("url")
                .unwrap_or_else(|_| "swmn.db".to_string());

            // Connect to database and initialize if necessary
            let connection = SqliteConnection::establish(&url).expect("database connection");
            embed_migrations!();
            diesel_migrations::run_pending_migrations(&connection).expect("database migrations");

            match matches.subcommand() {
                ("set", Some(set_user_matches)) => {
                    cli::user::set(set_user_matches, connection)?;
                    println!(
                        "Password successfully changed (or user created, if it didn't exist before)"
                    );
                }
                ("enable", Some(enable_user_matches)) => {
                    let result = cli::user::set_status(enable_user_matches, connection, true)?;
                    println!(
                        "{}",
                        match result {
                            true => "Successfully enabled user",
                            false => "Failed to enable user",
                        }
                    );
                }
                ("disable", Some(disable_user_matches)) => {
                    let result = cli::user::set_status(disable_user_matches, connection, false)?;
                    println!(
                        "{}",
                        match result {
                            true => "Successfully disabled user",
                            false => "Failed to disable user",
                        }
                    );
                }
                ("list", Some(list_user_matches)) => {
                    cli::user::list(list_user_matches, connection)?;
                }
                ("remove", Some(remove_user_matches)) => {
                    let result = cli::user::remove(remove_user_matches, connection)?;
                    println!(
                        "{}",
                        match result {
                            true => "Successfully removed user",
                            false => "Failed to remove user",
                        }
                    );
                }
                _ => unreachable!(),
            }
            Ok(())
        }
        _ => match rocket(rocket::Config::figment()).launch().await {
            Err(e) => {
                drop(e);
                Ok(())
            }
            _ => Ok(()),
        },
    }
}

#[cfg(test)]
pub async fn run_test_setup(rocket: Rocket<Build>) -> Rocket<Build> {
    use database::models::{ClientNew, Db};

    let db = Db::get_one(&rocket).await.expect("database connection");
    db.run(|conn| {
        embed_migrations!();
        embedded_migrations::run(conn).expect("setup database schema");

        let user = "test".to_string();
        database::add_user(conn, user.clone(), "1234".to_owned()).expect("sample user creation");
        database::create_client(
            conn,
            ClientNew {
                id: "123".to_string(),
                description: None,
                associated_with: None,
                passphrase: None,
                ca_passphrase: Some("test".to_string()),
                disabled: false,
            },
            &user,
        )
        .expect("sample client creation failed");
    })
    .await;

    rocket
}
