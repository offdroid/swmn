use database::models::Db;
use rocket::fairing::AdHoc;
#[cfg(not(test))]
use rocket::{Build, Rocket};

#[cfg(not(test))]
async fn run_migrations(rocket: Rocket<Build>) -> Rocket<Build> {
    debug!("Checking/Running database migrations");
    embed_migrations!();
    let conn = Db::get_one(&rocket).await.expect("database connection");
    conn.run(|c| embedded_migrations::run(c))
        .await
        .expect("diesel migrations");

    rocket
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Database stage", |rocket| async {
        let rocket = rocket.attach(Db::fairing());
        #[cfg(test)]
        let rocket = rocket.attach(AdHoc::on_ignite(
            "Database test setup",
            crate::run_test_setup,
        ));
        #[cfg(not(test))]
        let rocket = rocket.attach(AdHoc::on_ignite("Database migrations", run_migrations));
        rocket
    })
}

#[cfg(test)]
pub(crate) const TEST_LOGIN: (&str, &str) = ("test", "1234");
