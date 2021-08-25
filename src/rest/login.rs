use database::{
    models::{AuthenticatedUser, Db},
    PasswordVerification,
};
use rocket::{
    fairing::AdHoc,
    http::{Cookie, CookieJar, Status},
    serde::{json::Json, Deserialize, Serialize},
};

pub(crate) const COOKIE_USER_ID: &str = "user_id";

#[derive(Debug, Clone, Deserialize, Serialize, FromForm)]
pub(crate) struct UserLogin {
    pub(crate) username: String,
    pub(crate) password: String,
}

#[post("/login", format = "json", data = "<user_login>")]
async fn login(db: Db, cookies: &CookieJar<'_>, user_login: Json<UserLogin>) -> Status {
    let username = user_login.username.clone();
    let password = user_login.password.clone();
    match db
        .run(move |conn| database::verify_user(conn, &username, &password))
        .await
    {
        Ok(PasswordVerification::Success) => {
            let cookie = Cookie::build(COOKIE_USER_ID, user_login.username.clone())
                .path("/")
                .max_age(time::Duration::days(1))
                .secure(
                    std::env::var("SECURE_COOKIES")
                        .map(|x| matches!(x.to_lowercase().as_str(), "1" | "true" | "yes"))
                        .unwrap_or(false),
                )
                .finish();
            cookies.add_private(cookie);
            Status::Ok
        }
        Ok(e) => {
            warn!("Failed login attempt: {:?}", e);
            Status::Unauthorized
        }
        Err(e) => {
            warn!("Internal server error: {}", e);
            Status::InternalServerError
        }
    }
}

#[post("/logout")]
async fn logout(cookies: &CookieJar<'_>) {
    cookies.remove_private(Cookie::named(COOKIE_USER_ID));
}

#[get("/whoami")]
async fn me(user: AuthenticatedUser) -> Json<String> {
    user.id().into()
}

pub(crate) fn stage() -> AdHoc {
    AdHoc::on_ignite("Login Stage", |rocket| async {
        rocket.mount("/api", routes![login, logout, me])
    })
}

#[cfg(test)]
mod test {
    use crate::{db::TEST_LOGIN, rocket, tests};
    use rocket::{
        http::{Header, Status},
        local::blocking::Client,
    };

    use super::UserLogin;

    #[test]
    fn login() {
        let db = tests::TempDb::new();
        let client = Client::tracked(rocket(db.rocket())).expect("valid rocket instance");
        let response = client
            .post("/api/login")
            .json(&UserLogin {
                username: TEST_LOGIN.0.to_string(),
                password: TEST_LOGIN.1.to_string(),
            })
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let response = client
            .post("/api/login")
            .json(&UserLogin {
                username: TEST_LOGIN.0.to_string(),
                password: format!("{}{}", TEST_LOGIN.1.to_string(), "mtpw"),
            })
            .dispatch();
        assert_eq!(response.status(), Status::Unauthorized);

        let response = client
            .get("/api/client/123")
            .header(Header::new("username", TEST_LOGIN.0))
            .header(Header::new("password", TEST_LOGIN.1))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }
}
