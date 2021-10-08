//! Webfrontend for user interaction with swmn
#[macro_use]
extern crate rocket;

use std::io::Cursor;

use cert::PythonError;
use common::CaPass;
use database::{
    models::{AuthenticatedUser, Client, ClientDelta, ClientNew, ClientRank, Db},
    ClientOrderCategories, PasswordVerification,
};
use diesel::result::{DatabaseErrorKind, Error::DatabaseError};
use rocket::{
    fairing::AdHoc,
    form::Form,
    http::{ContentType, Cookie, CookieJar, RawStr, Status},
    response::{self, content::Html, Redirect, Responder},
    Request, Response, State,
};
use rocket_dyn_templates::{
    handlebars::{self, Handlebars, JsonRender},
    Template,
};
use serde::Deserialize;
use serde_json::json;

const COOKIE_USER_ID: &str = "user_id";

#[derive(Debug, Clone, FromForm)]
pub(crate) struct UserLogin {
    pub(crate) username: String,
    pub(crate) password: String,
}

/// Take the first argument or the second one if the first is `None`
macro_rules! prio {
    ($first:expr, $second:expr) => {
        $first
            .as_deref()
            .unwrap_or_else(|| $second.unwrap().as_str())
    };
}

/// Filter options for client lists
#[derive(Debug, Deserialize, FromForm, PartialEq, Default, Clone)]
pub(crate) struct Filters {
    pub(crate) order_by_category: Option<ClientOrderCategories>,
    pub(crate) asc: Option<bool>,
    pub(crate) disabled: Option<bool>,
    pub(crate) from_creator: Option<String>,
    pub(crate) offset: Option<u32>,
    pub(crate) limit: Option<u32>,
}

/// Wrapper around a downloadable config as a file with a filename
struct DownloadableConfig {
    name: String,
    content: String,
}

impl<'r> Responder<'r, 'static> for DownloadableConfig {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'static> {
        Response::build()
            .sized_body(self.content.len(), Cursor::new(self.content))
            .raw_header(
                "Content-Disposition",
                format!(
                    "attachment; filename=\"{}.ovpn\"",
                    self.name.replace("\"", "'")
                ),
            )
            .header(ContentType::new("application", "x-openvpn-profile"))
            .ok()
    }
}

#[get("/login?<invalid>")]
pub(crate) fn login(invalid: Option<bool>, user: Option<AuthenticatedUser>) -> Html<Template> {
    let context = json!({
        "title": "Login",
        "parent": "default_parent",
        "invalid": invalid.unwrap_or(false),
        "username": user.map(AuthenticatedUser::id),
    });
    Html(Template::render("login", context))
}

/// Form request handlers
mod request {
    use common::CaPass;
    use database::models::Db;

    use api as core_api;

    use super::*;

    #[post("/login", data = "<user_login>")]
    pub(crate) async fn login(
        db: Db,
        cookies: &CookieJar<'_>,
        user_login: Form<UserLogin>,
    ) -> Redirect {
        let username = user_login.username.clone();
        let password = user_login.password.clone();
        match db
            .run(move |conn| database::verify_user(conn, &username, &password))
            .await
        {
            Ok(PasswordVerification::Success) => {
                let cookie = Cookie::build(COOKIE_USER_ID, user_login.username.to_owned())
                    .path("/")
                    .max_age(time::Duration::days(1))
                    .secure(
                        std::env::var("SECURE_COOKIES")
                            .map(|x| matches!(x.to_lowercase().as_str(), "1" | "true" | "yes"))
                            .unwrap_or(false),
                    )
                    .finish();
                cookies.add_private(cookie);
                Redirect::to(uri!("/web", dashboard))
            }
            Ok(e) => {
                warn!("Failed login attempt: {:?}", e);
                Redirect::to(uri!("/web", super::login(invalid = Some(true))))
            }
            Err(e) => {
                warn!("Internal server error: {}", e);
                Redirect::to(uri!("/web", super::login(invalid = Some(false))))
            }
        }
    }

    #[post("/logout")]
    pub(crate) async fn logout(cookies: &CookieJar<'_>) -> Redirect {
        cookies.remove_private(Cookie::named(COOKIE_USER_ID));
        Redirect::to(uri!("/"))
    }

    #[post("/edit/<id>", data = "<delta>")]
    pub(crate) async fn edit_client(
        db: Db,
        _user: AuthenticatedUser,
        id: String,
        delta: Form<ClientDelta>,
    ) -> Result<Redirect, Status> {
        core_api::update_client(&db, id.clone(), delta.into_inner())
            .await
            .map_err(|err| match err.downcast::<diesel::result::Error>() {
                Ok(diesel::result::Error::NotFound) => Status::NotFound,
                _ => Status::InternalServerError,
            })?;
        Ok(Redirect::to(uri!("/web", super::view_client(id = id))))
    }

    #[post("/new_client", data = "<new>")]
    pub(crate) async fn new_client(
        db: Db,
        user: AuthenticatedUser,
        ca_pass: &State<CaPass>,
        cert: &State<cert::Config>,
        new: Form<ClientNew>,
    ) -> Result<Redirect, Status> {
        let mut new_client = new.into_inner();
        if new_client.disabled {
            new_client.disabled = false;
        }
        if let Some(true) = new_client.passphrase.as_ref().map(|s| s.is_empty()) {
            new_client.passphrase = None;
        }
        if let Some(true) = new_client.ca_passphrase.as_ref().map(|s| s.is_empty()) {
            new_client.ca_passphrase = None;
        }
        if !ca_pass.is_present() && new_client.ca_passphrase.is_none() {
            return Err(Status::BadRequest);
        }

        core_api::create_client(
            &db,
            user.id(),
            new_client.clone(),
            prio!(new_client.ca_passphrase, ca_pass.expose()),
            cert,
        )
        .await
        .map(|_| Redirect::to(uri!("/web", super::view_client(id = new_client.id))))
        .map_err(|err| {
            if let Some(DatabaseError(DatabaseErrorKind::UniqueViolation, _)) =
                err.downcast_ref::<diesel::result::Error>()
            {
                return Status::Conflict;
            } else if let Some(PythonError { source }) = err.downcast_ref::<PythonError>() {
                warn!("Certifiacte creation failed `{}`", source);
                return Status::InternalServerError;
            }

            let b: String = err
                .chain()
                .enumerate()
                .rev()
                .fold(String::new(), |acc, (idx, x)| {
                    format!("{}\n{}. {}", acc, err.chain().count() - idx, x)
                });
            warn!("Backtrace: {}", b);
            Status::InternalServerError
        })
    }

    #[derive(FromForm)]
    pub(crate) struct RevokeConfirmation {
        confirm: bool,
        ca_passphrase: Option<String>,
    }

    #[post("/cr/<id>", data = "<confirmation>")]
    pub(crate) async fn revoke_client(
        db: Db,
        _user: AuthenticatedUser,
        id: String,
        ca_pass: &State<CaPass>,
        cert: &State<cert::Config>,
        confirmation: Form<RevokeConfirmation>,
    ) -> Result<Redirect, Status> {
        let mut confirmation = confirmation.into_inner();
        if !confirmation.confirm {
            return Err(Status::BadRequest);
        }
        if let Some(true) = confirmation.ca_passphrase.as_ref().map(|s| s.is_empty()) {
            confirmation.ca_passphrase = None;
        }
        if !ca_pass.is_present() && confirmation.ca_passphrase.is_none() {
            return Err(Status::BadRequest);
        }

        core_api::revoke_client(
            &db,
            id.clone(),
            prio!(confirmation.ca_passphrase, ca_pass.expose()),
            cert,
        )
        .await
        .map(|_| Redirect::to(uri!("/web", super::view_client(id = id))))
        .map_err(|err| {
            if let Some(DatabaseError(DatabaseErrorKind::UniqueViolation, _)) =
                err.downcast_ref::<diesel::result::Error>()
            {
                return Status::Conflict;
            } else if let Some(PythonError { source: _ }) = err.downcast_ref::<PythonError>() {
                let b: String = err
                    .chain()
                    .enumerate()
                    .rev()
                    .fold(String::new(), |acc, (idx, x)| {
                        format!("{}\n{}. {}", acc, err.chain().count() - idx, x)
                    });
                warn!("Backtrace: {}", b);
                return Status::InternalServerError;
            }
            warn!("Other error = `{}`", err);
            Status::InternalServerError
        })
    }

    #[derive(FromForm)]
    pub(crate) struct RevokeRemoveConfirmation {
        id_confirm: String,
        ca_passphrase: Option<String>,
    }

    #[post("/crr/<id>", data = "<confirmation>")]
    pub(crate) async fn revoke_remove_client(
        db: Db,
        _user: AuthenticatedUser,
        id: String,
        ca_pass: &State<CaPass>,
        cert: &State<cert::Config>,
        confirmation: Form<RevokeRemoveConfirmation>,
    ) -> Result<Redirect, Status> {
        let mut confirmation = confirmation.into_inner();
        if confirmation.id_confirm.trim() != id.trim() {
            return Err(Status::BadRequest);
        }
        if let Some(true) = confirmation.ca_passphrase.as_ref().map(|s| s.is_empty()) {
            confirmation.ca_passphrase = None;
        }
        if !ca_pass.is_present() && confirmation.ca_passphrase.is_none() {
            return Err(Status::BadRequest);
        }

        core_api::revoke_remove_client(
            &db,
            id.clone(),
            prio!(confirmation.ca_passphrase, ca_pass.expose()),
            cert,
        )
        .await
        .map(|_| Redirect::to(uri!("/web", super::dashboard)))
        .map_err(|err| {
            if let Some(DatabaseError(DatabaseErrorKind::UniqueViolation, _)) =
                err.downcast_ref::<diesel::result::Error>()
            {
                return Status::Conflict;
            } else if let Some(PythonError { source: _ }) = err.downcast_ref::<PythonError>() {
                let b: String = err
                    .chain()
                    .enumerate()
                    .rev()
                    .fold(String::new(), |acc, (idx, x)| {
                        format!("{}\n{}. {}", acc, err.chain().count() - idx, x)
                    });
                warn!("Backtrace: {}", b);
                return Status::InternalServerError;
            }
            warn!("Other error = `{}`", err);
            Status::InternalServerError
        })
    }
}

#[get("/dashboard")]
pub(crate) fn dashboard(user: AuthenticatedUser) -> Html<Template> {
    let context = json!({
        "title": "Dashboard",
        "parent": "default_parent",
        "username": user.id(),
    });
    Html(Template::render("dashboard", context))
}

/// List of clients optionally filtered
#[get("/list?<filter..>")]
pub(crate) async fn list(
    db: Db,
    user: AuthenticatedUser,
    filter: Filters,
) -> Result<Html<Template>, Status> {
    trace!("filters = {:?}", filter);
    let f = filter.clone();
    let clients: Vec<Client> = api::get_clients_filtered(
        &db,
        f.order_by_category,
        f.asc,
        f.disabled,
        match f.from_creator {
            Some(a) if a.is_empty() => None,
            _ => f.from_creator,
        },
        f.offset,
        if let Some(0) = f.limit { None } else { f.limit },
    )
    .await
    .map_err(|_err| Status::InternalServerError)?;

    let context = json!({
        "title": "Client list",
        "parent": "default_parent",
        "username": user.id(),
        "clients": clients,
        "dangerous": true,
        "order_by_category": if let Some(v) = filter.order_by_category { format!("{:?}", v) } else { "None".to_string() },
        "from_creator": filter.from_creator.unwrap_or_else(String::new),
        "disabled": if let Some(v) = filter.disabled { format!("{:?}", v) } else { "None".to_string() },
        "asc": filter.asc.unwrap_or(false),
        "offset": filter.offset.unwrap_or(0),
        "limit": filter.limit.unwrap_or(0),
    });
    Ok(Html(Template::render("list", context)))
}

/// Search clients with SQLite FTS
#[get("/search?<q>", rank = 1)]
pub(crate) async fn search(
    db: Db,
    user: AuthenticatedUser,
    q: String,
) -> Result<Html<Template>, Status> {
    trace!("Search with query = {:?}", q);
    let clients: Vec<ClientRank> = api::search(&db, q.clone()).await.map_err(|err| {
        error!("{}", err);
        Status::InternalServerError
    })?;
    let context = json!({
        "title": "Client list",
        "parent": "default_parent",
        "username": user.id(),
        "clients": clients,
        "dangerous": true,
        "is_search": true,
        "query": q,
    });
    Ok(Html(Template::render("list", context)))
}

#[get("/search", rank = 2)]
pub(crate) async fn search_no_query(user: AuthenticatedUser) -> Result<Html<Template>, Status> {
    let context = json!({
        "title": "Client list",
        "parent": "default_parent",
        "username": user.id(),
        "dangerous": true,
        "is_search": true,
        "query": "",
        "is_no_query": true,
    });
    Ok(Html(Template::render("list", context)))
}

#[get("/new_client")]
pub(crate) fn new_client(user: AuthenticatedUser, ca_pass: &State<CaPass>) -> Html<Template> {
    let context = json!({
        "title": "New client",
        "parent": "default_parent",
        "username": user.id(),
        "ca_pass_required": !ca_pass.is_present(),
    });
    Html(Template::render("new_client", context))
}

#[get("/edit/<id>")]
pub(crate) async fn edit_client(
    db: Db,
    user: AuthenticatedUser,
    id: String,
) -> Result<Html<Template>, Status> {
    let client: Client = api::get_client(&db, id.clone()).await.map_err(|err| {
        match err.downcast::<diesel::result::Error>() {
            Ok(diesel::result::Error::NotFound) => Status::NotFound,
            _ => Status::InternalServerError,
        }
    })?;
    let context = json!({
        "title": format!("Edit {}", id),
        "parent": "default_parent",
        "username": user.id(),
        "client": client,
        "dangerous": true,
        "is_edit": true,
    });
    Ok(Html(Template::render("details_client", context)))
}

#[get("/view/<id>")]
pub(crate) async fn view_client(
    db: Db,
    user: AuthenticatedUser,
    id: String,
) -> Result<Html<Template>, Status> {
    let client: Client = api::get_client(&db, id.clone()).await.map_err(|err| {
        match err.downcast::<diesel::result::Error>() {
            Ok(diesel::result::Error::NotFound) => Status::NotFound,
            _ => Status::InternalServerError,
        }
    })?;
    let context = json!({
        "title": format!("Edit {}", id),
        "parent": "default_parent",
        "username": user.id(),
        "client": client,
        "dangerous": true,
        "is_edit": false,
    });
    Ok(Html(Template::render("details_client", context)))
}

#[get("/download/<id>")]
pub(crate) async fn download_client_config(
    db: Db,
    user: AuthenticatedUser,
    id: String,
    cert: &State<cert::Config>,
) -> Result<DownloadableConfig, Status> {
    info!(
        "Client config retrieval: client id = `{}`, requester = `{}`",
        id,
        user.clone().id(),
    );
    api::get_client_cert(&db, id.clone(), cert)
        .await
        .map(|config| DownloadableConfig {
            name: id,
            content: config,
        })
        .map_err(|_| Status::InternalServerError)
}

#[get("/cr/<id>")]
pub(crate) async fn confirm_revoke(
    db: Db,
    user: AuthenticatedUser,
    ca_pass: &State<CaPass>,
    id: String,
) -> Result<Html<Template>, Status> {
    let client: Client = api::get_client(&db, id.clone()).await.map_err(|err| {
        match err.downcast::<diesel::result::Error>() {
            Ok(diesel::result::Error::NotFound) => Status::NotFound,
            _ => Status::InternalServerError,
        }
    })?;
    let context = json!({
        "title": format!("Edit {}", id),
        "parent": "default_parent",
        "username": user.id(),
        "client": client,
        "is_remove": false,
        "ca_pass_required": !ca_pass.is_present(),
    });
    Ok(Html(Template::render("confirm_revoke", context)))
}

#[get("/crr/<id>")]
pub(crate) async fn confirm_revoke_remove(
    db: Db,
    user: AuthenticatedUser,
    ca_pass: &State<CaPass>,
    id: String,
) -> Result<Html<Template>, Status> {
    let client: Client = api::get_client(&db, id.clone()).await.map_err(|err| {
        match err.downcast::<diesel::result::Error>() {
            Ok(diesel::result::Error::NotFound) => Status::NotFound,
            _ => Status::InternalServerError,
        }
    })?;
    let context = json!({
        "title": format!("Edit {}", id),
        "parent": "default_parent",
        "username": user.id(),
        "client": client,
        "is_remove": true,
        "ca_pass_required": !ca_pass.is_present(),
    });
    Ok(Html(Template::render("confirm_revoke", context)))
}

#[get("/")]
pub(crate) fn root(user: Option<AuthenticatedUser>) -> Redirect {
    if user.is_some() {
        Redirect::to(uri!("/web", dashboard))
    } else {
        Redirect::to(uri!("/web", login(invalid = None::<bool>)))
    }
}

#[get("/")]
pub(crate) fn web(user: Option<AuthenticatedUser>) -> Redirect {
    if user.is_some() {
        Redirect::to(uri!("/web", dashboard))
    } else {
        Redirect::to(uri!("/web", login(invalid = None::<bool>)))
    }
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Web frontend", |rocket| async {
        rocket
            .mount(
                "/web",
                routes![
                    login,
                    request::login,
                    request::logout,
                    dashboard,
                    new_client,
                    request::new_client,
                    edit_client,
                    request::edit_client,
                    view_client,
                    download_client_config,
                    list,
                    confirm_revoke,
                    request::revoke_client,
                    confirm_revoke_remove,
                    request::revoke_remove_client,
                    search,
                    search_no_query,
                    web,
                ],
            )
            .mount("/", routes![root])
    })
}

fn url_encode_helper(
    h: &handlebars::Helper<'_, '_>,
    _: &handlebars::Handlebars,
    _: &handlebars::Context,
    _: &mut handlebars::RenderContext<'_, '_>,
    out: &mut dyn handlebars::Output,
) -> handlebars::HelperResult {
    if let Some(param) = h.param(0) {
        out.write(
            RawStr::new(&param.value().render())
                .percent_encode()
                .as_str(),
        )?;
    }
    Ok(())
}

pub fn customize(hbs: &mut Handlebars) {
    hbs.register_helper("url_encode", Box::new(url_encode_helper));
}
