//! Data models
use crate::{schema::*, PasswordVerification};
use chrono::naive::NaiveDateTime;
use diesel::SqliteConnection;
use rocket::{
    http::Status,
    outcome::IntoOutcome,
    request::{FromRequest, Outcome},
    Request,
};
use rocket_sync_db_pools::database;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Queryable, Insertable)]
pub struct User {
    pub name: String,
    pub password: String,
    #[serde(default)]
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct UserPasswordless {
    pub name: String,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Queryable, Insertable)]
#[table_name = "clients"]
pub struct ClientPartial {
    pub id: String,
    pub description: Option<String>,
    pub associated_with: Option<String>,
    pub date_created: Option<NaiveDateTime>,
    pub creator_id: String,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Queryable, QueryableByName, Insertable, Serialize)]
#[table_name = "clients"]
pub struct Client {
    pub id: String,
    pub description: Option<String>,
    pub associated_with: Option<String>,
    pub date_created: NaiveDateTime,
    pub creator_id: String,
    pub disabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, FromForm)]
pub struct ClientNew {
    pub id: String,
    pub description: Option<String>,
    pub associated_with: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub ca_passphrase: Option<String>,
    #[serde(skip)]
    pub disabled: bool,
}

impl ClientNew {
    pub fn into_client(&self, creator: &str) -> ClientPartial {
        ClientPartial {
            id: self.id.to_owned(),
            description: self.description.to_owned(),
            associated_with: self.associated_with.to_owned(),
            date_created: None,
            creator_id: creator.to_string(),
            disabled: Some(self.disabled),
        }
    }
}

#[derive(Debug, Clone, Deserialize, FromForm, AsChangeset)]
#[table_name = "clients"]
pub struct ClientDelta {
    pub description: Option<String>,
    pub associated_with: Option<String>,
}

#[derive(QueryableByName, Debug, Clone, Serialize)]
pub struct ClientRank {
    #[diesel(embed)]
    #[serde(flatten)]
    pub client: Client,
    #[sql_type = "diesel::sql_types::Float"]
    pub rank: f32,
}

impl From<ClientRank> for Client {
    fn from(cr: ClientRank) -> Self {
        cr.client
    }
}

#[database("swmn_db")]
#[derive(Clone)]
pub struct Db(SqliteConnection);

/// Error from a login attempt
#[derive(thiserror::Error, Debug)]
pub enum LoginError {
    #[error("Invalid username password combination")]
    InvalidPassword,
    #[error("No user with the requested name")]
    UserNotFound,
    #[error("Login not possible because the user is disabled")]
    UserDisabled,
    #[error("Unknown error")]
    Unknown,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedUser(String);

impl AuthenticatedUser {
    pub fn id(self) -> String {
        self.0
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = LoginError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        fn from_header(headers: &'_ rocket::http::HeaderMap) -> Option<(String, String)> {
            if let (Some(username), Some(password)) =
                (headers.get_one("Username"), headers.get_one("Password"))
            {
                Some((username.to_string(), password.to_string()))
            } else if let Some(authorization) = headers.get_one("Authorization") {
                match base64::decode(authorization) {
                    Ok(decoded) => match std::str::from_utf8(&decoded) {
                        Ok(concatenated) => concatenated
                            .split_once(":")
                            .map(|(a, b)| (a.to_string(), b.to_string())),
                        _ => None,
                    },
                    _ => None,
                }
            } else {
                None
            }
        }
        if let Some((username, password)) = from_header(request.headers()) {
            let pool: Db = Db::from_request(request).await.unwrap();
            let (user, pass) = (username.to_owned(), password.to_owned());
            return match pool
                .run(move |conn| crate::verify_user(conn, &user, &pass))
                .await
            {
                Ok(PasswordVerification::Success) => {
                    Outcome::Success(AuthenticatedUser(username.to_owned()))
                }
                Ok(PasswordVerification::FailureNotFound) => {
                    Outcome::Failure((Status::Forbidden, LoginError::UserNotFound))
                }
                Ok(PasswordVerification::FailureDisabled) => {
                    Outcome::Failure((Status::Forbidden, LoginError::UserDisabled))
                }
                Ok(PasswordVerification::FailureNoMatch) => {
                    Outcome::Failure((Status::Forbidden, LoginError::InvalidPassword))
                }
                Err(e) => {
                    let b: String = e
                        .chain()
                        .enumerate()
                        .rev()
                        .fold(String::new(), |acc, (idx, x)| {
                            format!("{}\n  {}. {}", acc, e.chain().count() - idx, x)
                        });
                    warn!("Backtrace: {}", b);
                    Outcome::Failure((Status::Forbidden, LoginError::Unknown))
                }
            };
        } else {
            request
                .cookies()
                .get_private("user_id")
                .and_then(|cookie| cookie.value().parse().ok())
                .map(AuthenticatedUser)
                .into_outcome((Status::Unauthorized, LoginError::InvalidPassword))
        }
    }
}
