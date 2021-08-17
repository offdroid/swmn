use std::fmt::Display;

use clap::ArgMatches;
use diesel::SqliteConnection;

fn extract_pass(matches: &ArgMatches) -> std::io::Result<String> {
    if let Some(pass) = matches.value_of("PASS") {
        return Ok(pass.to_string());
    }
    if let Some(source) = matches.value_of("SOURCE") {
        // Load from file
        match std::fs::read_to_string(source) {
            Ok(pass) => return Ok(pass),
            Err(err) => {
                println!("Failed to open file `{}`: {}", source, err);
                if matches.is_present("NOT_INTERACTIVE") {
                    return Err(err);
                }
            }
        }
    }

    const PROMPT: &str = "Enter (new) password: ";
    if cfg!(test) {
        rpassword::prompt_password_stdout(PROMPT)
    } else {
        match rpassword::read_password_from_tty(Some(PROMPT)) {
            Ok(pass) => Ok(pass),
            Err(_) => rpassword::prompt_password_stdout(PROMPT),
        }
    }
}

pub mod user {
    use super::*;

    #[derive(Debug)]
    enum UserSetError {
        MissingArgument,
    }
    impl Display for UserSetError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Self::MissingArgument => write!(f, "Missing cli argument"),
            }
        }
    }
    impl std::error::Error for UserSetError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            None
        }
    }

    pub fn set(
        matches: &ArgMatches,
        connection: SqliteConnection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pass = extract_pass(matches)?;
        database::add_user(
            &connection,
            matches
                .value_of("USERNAME")
                .ok_or(UserSetError::MissingArgument)?
                .to_string(),
            pass,
        )?;
        Ok(())
    }

    pub fn list(
        _matches: &ArgMatches,
        connection: SqliteConnection,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match database::get_users(&connection) {
            Ok(users) => {
                println!("{0: <10} | {1: <8}", "Username", "Disabled");
                println!("{:-<11}+{:-<9}", "", "");
                for user in users {
                    println!("{0: <10} | {1: <8}", user.name, user.disabled);
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_status(
        matches: &ArgMatches,
        connection: SqliteConnection,
        enabled: bool,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        database::set_user_status(
            &connection,
            matches
                .value_of("USERNAME")
                .ok_or(UserSetError::MissingArgument)?
                .to_string(),
            !enabled,
        )
        .map_err(Box::from)
    }

    pub fn remove(
        matches: &ArgMatches,
        connection: SqliteConnection,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        database::remove_user(
            &connection,
            matches
                .value_of("USERNAME")
                .ok_or(UserSetError::MissingArgument)?
                .to_string(),
        )
        .map_err(Box::from)
    }
}
