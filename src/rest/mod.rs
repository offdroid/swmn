//! Programmatic interface for interacting with swmn
pub(crate) mod login;

use crate::database;
use api::AlreadyRevoked;
use cert::PythonError;
use common::{CaPass, LocalCaPass};
use database::{
    models::{AuthenticatedUser, Client, ClientDelta, ClientNew, ClientRank, Db},
    ClientOrderCategories,
};
use diesel::result::{DatabaseErrorKind, Error::DatabaseError};
use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::response::{self, Responder};
use rocket::serde::{json::Json, Deserialize};
use rocket::*;
use serde_json::{json, Value};

#[derive(Debug, Deserialize, FromForm, PartialEq, Default, Clone)]
pub(crate) struct Filters {
    pub(crate) order_by_category: Option<ClientOrderCategories>,
    pub(crate) asc: Option<bool>,
    pub(crate) disabled: Option<bool>,
    pub(crate) from_creator: Option<String>,
    pub(crate) offset: Option<u32>,
    pub(crate) limit: Option<u32>,
}

macro_rules! prio {
    ($first:expr, $second:expr) => {
        $first
            .as_deref()
            .unwrap_or_else(|| $second.unwrap().as_str())
    };
}

#[derive(Debug)]
pub(crate) enum ApiError {
    BadRequest { reason: String },
    ClientConflict,
    ClientNotFound,
    ClientAlreadyRevoked,
    PythonError(anyhow::Error),
    Generic(anyhow::Error),
}

/// Custom responder for the error type
#[rocket::async_trait]
impl<'r> Responder<'r, 'static> for ApiError {
    fn respond_to(self, req: &'r Request<'_>) -> response::Result<'static> {
        use rocket::serde::Serialize;
        #[derive(Serialize)]
        struct ErrorResponse {
            status: &'static str,
            message: String,
        }
        impl From<ApiError> for ErrorResponse {
            fn from(error: ApiError) -> Self {
                match error {
                    ApiError::BadRequest { ref reason } => ErrorResponse {
                        status: "BadRequest",
                        message: reason.to_string(),
                    },
                    ApiError::ClientConflict => ErrorResponse {
                        status: "Conflict",
                        message: "A client with the id already exists".to_string(),
                    },
                    ApiError::ClientNotFound => ErrorResponse {
                        status: "Not Found",
                        message: "No client found with the given id".to_string(),
                    },
                    ApiError::ClientAlreadyRevoked => ErrorResponse {
                        status: "Already Revoked",
                        message: "The client was already revoked".to_string(),
                    },
                    ApiError::PythonError(trace) => ErrorResponse {
                        status: "BadRequest",
                        message: trace.to_string(),
                    },
                    ApiError::Generic(ref e) => {
                        let b: String = e
                            .chain()
                            .enumerate()
                            .rev()
                            .fold(String::new(), |acc, (idx, x)| {
                                format!("{}\n{}. {}", acc, e.chain().count() - idx, x)
                            });
                        warn!("Backtrace: {}", b);
                        ErrorResponse {
                            status: "Unknown",
                            message: "See server logs for details".to_string(),
                        }
                    }
                }
            }
        }

        let status = match self {
            ApiError::ClientConflict => Status::Conflict,
            ApiError::ClientNotFound => Status::NotFound,
            ApiError::ClientAlreadyRevoked => Status::Gone,
            ApiError::BadRequest { reason: _ } => Status::BadRequest,
            _ => Status::InternalServerError,
        };

        Json(ErrorResponse::from(self))
            .respond_to(req)
            .map(|mut res| {
                res.set_status(status);
                res
            })
    }
}

/// Information whether the CA passphrase is required for requests such as client creation.
/// The reply should always be true unless the ca passphrase is available through the keychain
/// (thus was setup accordingly).
#[get("/ca_pass_required")]
pub(crate) async fn ca_pass_required(ca_pass: &State<CaPass>) -> Value {
    json!({
        "ca_pass_required": ca_pass.is_present()
    })
}

/// Create a new client from the options provided as the json body.
///
/// # Schema
///
/// The json body must be of the following schema, where `id` is always present.
/// The remaining fields are optional, except for `ca_passphrase` which must be set if the CA
/// passphrase isn't available through e.g. the keyring.
/// ```json
/// {
///    "id": <string>,
///    "description": <string>,
///    "associated_with": <string>,
///    "ca_passphrase": <string>
/// }
/// ```
/// c.f. [`ClientNew`]
#[post("/client", format = "json", data = "<new>")]
pub(crate) async fn create_client(
    db: Db,
    user: AuthenticatedUser,
    new: Json<ClientNew>,
    ca_pass: &State<CaPass>,
    cert: &State<cert::Config>,
) -> Result<(), ApiError> {
    let new_client = new.into_inner();
    assert!(!new_client.disabled);
    if !ca_pass.is_present() && new_client.ca_passphrase.is_none() {
        return Err(ApiError::BadRequest {
            reason: "The CA passphrase field is required".to_string(),
        });
    }

    info!(
        "Client creation by {}: client id = {}",
        user.clone().id(),
        new_client.id
    );
    api::create_client(
        &db,
        user.id(),
        new_client.clone(),
        prio!(new_client.ca_passphrase, ca_pass.expose()),
        cert,
    )
    .await
    .map_err(|err| {
        if let Some(DatabaseError(DatabaseErrorKind::UniqueViolation, _)) =
            err.downcast_ref::<diesel::result::Error>()
        {
            ApiError::ClientConflict
        } else if let Some(PythonError { source }) = err.downcast_ref::<PythonError>() {
            warn!("Certifiacte creation failed `{}`", source);
            let source = err.downcast::<PythonError>().unwrap().source;
            ApiError::PythonError(source)
        } else {
            ApiError::Generic(err)
        }
    })
}

/// Update a client specified by its id and the changes in the json body.
///
/// # Schema
///
/// The json body must be of the following schema, where each item is optional:
/// ```json
/// {
///    "description": <string>,
///    "associated_with": <string>,
/// }
/// ```
/// c.f. [`ClientDelta`]
#[patch("/client/<id>", format = "json", data = "<delta>")]
pub(crate) async fn update_client(
    db: Db,
    user: AuthenticatedUser,
    id: String,
    delta: Json<ClientDelta>,
) -> Result<(), ApiError> {
    info!(
        "Client update: client id = `{}`, requester = `{}`",
        id,
        user.clone().id()
    );
    api::update_client(&db, id, delta.into_inner())
        .await
        .map_err(|err| {
            if let Some(diesel::result::Error::NotFound) =
                err.downcast_ref::<diesel::result::Error>()
            {
                ApiError::ClientNotFound
            } else {
                ApiError::Generic(err)
            }
        })
}

/// Get the data model from a client specified by the given id parameter in the url path
#[get("/client/<id>")]
pub(crate) async fn get_client(
    db: Db,
    user: AuthenticatedUser,
    id: String,
) -> Result<Json<Client>, ApiError> {
    info!(
        "Client retrieval: client id = `{}`, requester = `{}`",
        id,
        user.clone().id(),
    );
    api::get_client(&db, id).await.map(Json).map_err(|err| {
        if let Some(diesel::result::Error::NotFound) = err.downcast_ref::<diesel::result::Error>() {
            ApiError::ClientNotFound
        } else {
            ApiError::Generic(err)
        }
    })
}

/// Get the client configuration and certifiacte
#[get("/client/<id>/cert")]
pub(crate) async fn get_client_cert(
    db: Db,
    user: AuthenticatedUser,
    id: String,
    cert: &State<cert::Config>,
) -> Result<String, ApiError> {
    info!(
        "Client cert/config retrieval: client id = `{}`, requester = `{}`",
        id,
        user.clone().id(),
    );
    api::get_client_cert(&db, id, cert).await.map_err(|err| {
        if let Some(DatabaseError(DatabaseErrorKind::UniqueViolation, _)) =
            err.downcast_ref::<diesel::result::Error>()
        {
            ApiError::ClientConflict
        } else if let Some(PythonError { source: _ }) = err.downcast_ref::<PythonError>() {
            let source = err.downcast::<PythonError>().unwrap().source;
            ApiError::PythonError(source)
        } else {
            ApiError::Generic(err)
        }
    })
}

#[get("/clients_overview?<filter..>")]
pub(crate) async fn get_clients_count(
    db: Db,
    user: AuthenticatedUser,
    filter: Filters,
) -> Result<Value, ApiError> {
    info!("Client pagination: requester = `{}`", user.clone().id());
    trace!("filters = {:?}", filter);
    api::get_clients_filtered_count(
        &db,
        filter.order_by_category,
        filter.asc,
        filter.disabled,
        filter.from_creator,
        filter.offset,
        filter.limit,
    )
    .await
    .map(|v| json!({ "n": v as u32 }))
    .map_err(ApiError::Generic)
}

/// Get a list of clients
#[get("/client?<filter..>")]
pub(crate) async fn get_clients(
    db: Db,
    user: AuthenticatedUser,
    cert: &State<cert::Config>,
    filter: Filters,
) -> Result<Json<Vec<Client>>, ApiError> {
    info!("Client list retrieval: requester = `{}`", user.clone().id());
    trace!("cert list = {:?}", cert.list_certs(None));
    trace!("filters = {:?}", filter);
    api::get_clients_filtered(
        &db,
        filter.order_by_category,
        filter.asc,
        filter.disabled,
        filter.from_creator,
        filter.offset,
        filter.limit,
    )
    .await
    .map(Json)
    .map_err(ApiError::Generic)
}

#[delete("/client/<id>", format = "json", data = "<local>")]
pub(crate) async fn revoke_client(
    db: Db,
    user: AuthenticatedUser,
    local: Option<Json<LocalCaPass>>,
    global: &State<CaPass>,
    id: String,
    cert: &State<cert::Config>,
) -> Result<(), ApiError> {
    if !global.is_present() && local.is_none() {
        return Err(ApiError::BadRequest {
            reason: "The CA passphrase field is required".to_string(),
        });
    }
    info!(
        "Client revokation: client id = `{}`, requester = `{}`",
        id,
        user.clone().id()
    );
    let local: Option<String> = local.map(|x| x.into_inner().ca_passphrase);
    let result = api::revoke_client(&db, id.clone(), prio!(local, global.expose()), cert)
        .await
        .map_err(|err| {
            warn!(
                "Client revokation (client id = `{}`, requester = `{}`) failed because of: {}",
                id,
                user.clone().id(),
                err,
            );
            if let Some(DatabaseError(DatabaseErrorKind::UniqueViolation, _)) =
                err.downcast_ref::<diesel::result::Error>()
            {
                ApiError::ClientConflict
            } else if let Some(PythonError { source: _ }) = err.downcast_ref::<PythonError>() {
                let source = err.downcast::<PythonError>().unwrap().source;
                ApiError::PythonError(source)
            } else if err.is::<AlreadyRevoked>() {
                ApiError::ClientAlreadyRevoked
            } else {
                ApiError::Generic(err)
            }
        })?;
    if result {
        Ok(())
    } else {
        Err(ApiError::Generic(anyhow::anyhow!("Revokation failed")))
    }
}

#[delete("/client/<id>/remove", format = "json", data = "<local>")]
pub(crate) async fn revoke_remove_client(
    db: Db,
    user: AuthenticatedUser,
    local: Option<Json<LocalCaPass>>,
    global: &State<CaPass>,
    id: String,
    cert: &State<cert::Config>,
) -> Result<(), ApiError> {
    if !global.is_present() && local.is_none() {
        return Err(ApiError::BadRequest {
            reason: "The CA passphrase field is required".to_string(),
        });
    }
    info!(
        "Client revokation & removal: client id = `{}`, requester = `{}`",
        id,
        user.clone().id()
    );
    let local: Option<String> = local.map(|x| x.into_inner().ca_passphrase);
    let result = api::revoke_remove_client(&db, id.clone(), prio!(local, global.expose()), cert)
        .await
        .map_err(|err| {
            warn!(
                "Client revokation & removal (client id = `{}`, requester = `{}`) failed because of: {}",
                id,
                user.clone().id(),
                err,
            );
            if let Some(DatabaseError(DatabaseErrorKind::UniqueViolation, _)) =
                err.downcast_ref::<diesel::result::Error>()
            {
                ApiError::ClientConflict
            } else if let Some(PythonError { source: _ }) = err.downcast_ref::<PythonError>() {
                let source = err.downcast::<PythonError>().unwrap().source;
                ApiError::PythonError(source)
            } else {
                ApiError::Generic(err)
            }
        })?;
    if result {
        Ok(())
    } else {
        Err(ApiError::Generic(anyhow::anyhow!(
            "Revokation & removal failed"
        )))
    }
}

/// Search clients with SQLite FTS
#[get("/search?<q>")]
pub(crate) async fn search(
    db: Db,
    _user: AuthenticatedUser,
    q: String,
) -> Result<Json<Vec<ClientRank>>, ApiError> {
    api::search(&db, q)
        .await
        .map(Json)
        .map_err(ApiError::Generic)
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Rest API Stage", |rocket| async {
        rocket.mount(
            "/api",
            routes![
                ca_pass_required,
                create_client,
                update_client,
                get_client,
                get_client_cert,
                get_clients,
                get_clients_count,
                revoke_client,
                revoke_remove_client,
                search
            ],
        )
    })
}
