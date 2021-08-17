use database::models::Client;
use database::models::ClientDelta;
use database::models::ClientNew;
use database::models::ClientRank;
use database::models::Db;
use database::ClientOrderCategories;
use log::warn;

pub async fn create_client(
    db: &Db,
    user: String,
    new_client: ClientNew,
    ca_pass: &str,
    config: &cert::Config,
) -> anyhow::Result<()> {
    db.run({
        let new_client = new_client.clone();
        let user = user.clone();
        move |conn| database::create_client(conn, new_client, &user).map(|_| Some(()))
    })
    .await?;

    let client_id = new_client.id.clone();
    if let Err(err) = config.make_certificate(
        new_client.id,
        new_client.passphrase,
        String::from(ca_pass),
        None,
    ) {
        warn!("Certifiacte creation failed, is being rolled back");
        db.run(move |conn| database::delete_client(conn, &client_id))
            .await?;
        return Err(err);
    }
    Ok(())
}

pub async fn update_client(db: &Db, id: String, delta: ClientDelta) -> anyhow::Result<()> {
    db.run(move |conn| database::update_client(conn, id, &delta).map(|_| ()))
        .await
}

pub async fn get_client(db: &Db, id: String) -> anyhow::Result<Client> {
    db.run(move |conn| database::get_client(conn, id.as_str()))
        .await
}

pub async fn get_client_cert(db: &Db, id: String, cert: &cert::Config) -> anyhow::Result<String> {
    let cn: String = id.to_owned();
    // Check the existance in the database before delegating to the script
    db.run(move |conn| database::get_client(conn, id.as_str()))
        .await?;
    cert.get_client_config(cn, None)
}

pub async fn get_clients_filtered(
    db: &Db,
    order_by_category: Option<ClientOrderCategories>,
    asc: Option<bool>,
    disabled: Option<bool>,
    from_creator: Option<String>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> anyhow::Result<Vec<Client>> {
    db.run(move |conn| {
        database::get_clients_filtered(
            conn,
            order_by_category,
            asc,
            disabled,
            from_creator,
            offset,
            limit,
        )
    })
    .await
}

pub async fn get_clients_filtered_count(
    db: &Db,
    order_by_category: Option<ClientOrderCategories>,
    asc: Option<bool>,
    disabled: Option<bool>,
    from_creator: Option<String>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> anyhow::Result<i64> {
    db.run(move |conn| {
        database::get_clients_filtered_count(
            conn,
            order_by_category,
            asc,
            disabled,
            from_creator,
            offset,
            limit,
        )
    })
    .await
}

pub async fn search(db: &Db, query: String) -> anyhow::Result<Vec<ClientRank>> {
    db.run(move |conn| database::search(conn, &query)).await
}

#[derive(thiserror::Error, Debug)]
#[error("Client was already revoked")]
pub struct AlreadyRevoked;

pub async fn revoke_client(
    db: &Db,
    id: String,
    ca_pass: &str,
    cert: &cert::Config,
) -> anyhow::Result<bool> {
    let client = db
        .run({
            let id = id.clone();
            move |conn| database::get_client(conn, &id)
        })
        .await?;
    if client.disabled {
        Err(AlreadyRevoked.into())
    } else {
        cert.revoke_certificate(id.clone(), String::from(ca_pass), None)?;
        db.run(move |conn| database::set_disabled_client(conn, &id, true))
            .await
    }
}

pub async fn revoke_remove_client(
    db: &Db,
    id: String,
    ca_pass: &str,
    cert: &cert::Config,
) -> anyhow::Result<bool> {
    let client = db
        .run({
            let id = id.clone();
            move |conn| database::get_client(conn, &id)
        })
        .await?;
    cert.revoke_remove_certificate(id.clone(), String::from(ca_pass), client.disabled, None)?;
    db.run(move |conn| database::delete_client(conn, &id))
        .await
        .map(|x| x == 1)
}
