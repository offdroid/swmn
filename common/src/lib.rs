use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
pub struct LocalCaPass {
    pub ca_passphrase: String,
}

#[derive(Debug)]
pub struct CaPass(Option<SecretString>);

impl CaPass {
    pub fn new(secret: &str) -> Self {
        Self(Some(SecretString::from_str(secret).unwrap()))
    }

    pub fn empty() -> Self {
        Self(None)
    }

    pub fn is_present(&self) -> bool {
        self.0.is_some()
    }

    pub fn expose(&self) -> Option<&String> {
        self.0.as_ref().map(|secret| secret.expose_secret())
    }
}
