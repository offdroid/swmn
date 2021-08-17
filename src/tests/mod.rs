mod cli;

use rocket::figment::Figment;

pub struct TempDb(pub String);

impl TempDb {
    pub fn new() -> Self {
        use tempfile::NamedTempFile;

        let tmp_db = NamedTempFile::new()
            .expect("tempfile generation")
            .into_temp_path();
        let tmp_path: &str = tmp_db.to_str().expect("path retrieval");
        Self(tmp_path.to_string())
    }

    #[cfg(test)]
    pub fn rocket(self) -> Figment {
        use rocket::figment::{
            map,
            value::{Map, Value},
        };
        let db: Map<_, Value> = map! {
            "url" => self.0.clone().into(),
            "pool_size" => 2.into(),
        };
        rocket::Config::figment().merge(("databases", map!["swmn_db" => db]))
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        debug!("Removing temporary database `{}`", self.0);
        if let Err(e) = std::fs::remove_file(self.0.clone()) {
            warn!("Failed to delete temporary database: {}", e);
        }
    }
}
