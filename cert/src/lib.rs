use anyhow::Result;
use std::path::PathBuf;
use std::{collections::HashMap, fs};
use thiserror::Error;

use pyo3::prelude::*;

pub struct Config {
    script_module: String,
    script_path: PathBuf,
}

#[derive(Debug, Error)]
#[error("Python interpreter failed")]
pub struct PythonError {
    #[source]
    pub source: anyhow::Error,
}

impl Config {
    pub fn new(module: String, path: PathBuf) -> Self {
        Self {
            script_module: module,
            script_path: path,
        }
    }

    /// Create a new certificate.
    /// This should generate a private key, corresponding certificate signing request and signed
    /// certifacte using the provided CA passphrase.
    ///
    /// # Arguments
    /// * `cn` - Common name/id of the client
    /// * `passphrase` - Optional passphrase to secure the private key
    /// * `ca_passphrase` - Passphrase of the certificate authority, necessary for signing the CSR
    /// * `data` - Additional options script
    pub fn make_certificate(
        &self,
        cn: String,
        passphrase: Option<String>,
        ca_passphrase: String,
        data: Option<HashMap<String, String>>,
    ) -> anyhow::Result<()> {
        let code = fs::read_to_string(self.script_path.clone())?;
        Python::with_gil(|py| {
            let cert = PyModule::from_code(
                py,
                &code,
                &self.script_path.to_string_lossy(),
                &self.script_module,
            )?;
            let a: Result<(), anyhow::Error> = cert
                .getattr("make_cert")?
                .call1((cn, passphrase, ca_passphrase, data))
                .map(|_| ())
                .map_err(anyhow::Error::from);
            a
        })
        .map_err(|err| PythonError { source: err }.into())
    }

    /// Revoke a certifacte, keeping the associated files
    ///
    /// # Arguments
    /// * `cn` - Common name/id of the client to delete
    /// * `ca_passphrase` - Passphrase of the certificate authority, necessary for revoking the
    /// certifacte
    /// * `data` - Additional options
    pub fn revoke_certificate(
        &self,
        cn: String,
        ca_passphrase: String,
        data: Option<HashMap<String, String>>,
    ) -> anyhow::Result<()> {
        let code = fs::read_to_string(self.script_path.clone())?;
        Python::with_gil(|py| {
            let cert = PyModule::from_code(
                py,
                &code,
                &self.script_path.to_string_lossy(),
                &self.script_module,
            )?;
            cert.getattr("revoke_cert")?
                .call1((cn, ca_passphrase, data))
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .map_err(|err| PythonError { source: err }.into())
    }

    /// First revoke a certifacte then delete it
    ///
    /// # Arguments
    /// * `cn` - Common name/id of the client to delete
    /// * `ca_passphrase` - Passphrase of the certificate authority, necessary for revoking the
    /// certifacte
    /// * `already_revoked` - True if the client is already revoked, meaning only removal is
    /// necessary
    /// * `data` - Additional options
    pub fn revoke_remove_certificate(
        &self,
        cn: String,
        ca_passphrase: String,
        already_revoked: bool,
        data: Option<HashMap<String, String>>,
    ) -> anyhow::Result<()> {
        let code = fs::read_to_string(self.script_path.clone())?;
        Python::with_gil(|py| {
            let cert = PyModule::from_code(
                py,
                &code,
                &self.script_path.to_string_lossy(),
                &self.script_module,
            )?;
            cert.getattr("revoke_and_remove_cert")?
                .call1((cn, ca_passphrase, already_revoked, data))
                .map(|_| ())
                .map_err(anyhow::Error::from)
        })
        .map_err(|err| PythonError { source: err }.into())
    }

    /// Get a specific OpenVPN client configuration as a string
    pub fn get_client_config(
        &self,
        cn: String,
        data: Option<HashMap<String, String>>,
    ) -> anyhow::Result<String> {
        let code = fs::read_to_string(self.script_path.clone())?;
        Python::with_gil(|py| {
            let cert = PyModule::from_code(
                py,
                &code,
                &self.script_path.to_string_lossy(),
                &self.script_module,
            )?;
            cert.getattr("get_config")?
                .call1((cn, data))
                .map_err(anyhow::Error::from)?
                .extract::<String>()
                .map_err(anyhow::Error::from)
        })
        .map_err(|err| PythonError { source: err }.into())
    }

    /// Retrieve a list of all certificates
    ///
    /// # Arguments
    /// * `data` - Additional options for the list, could be used to filter said list
    pub fn list_certs(&self, data: Option<HashMap<String, String>>) -> anyhow::Result<Vec<String>> {
        let code = fs::read_to_string(self.script_path.clone())?;
        Python::with_gil(|py| {
            let cert = PyModule::from_code(
                py,
                &code,
                &self.script_path.to_string_lossy(),
                &self.script_module,
            )?;
            cert.getattr("list_certs")?
                .call1((data,))
                .map_err(anyhow::Error::from)?
                .extract::<Vec<String>>()
                .map_err(anyhow::Error::from)
        })
        .map_err(|err| PythonError { source: err }.into())
    }

    #[cfg(test)]
    pub(crate) fn test_config(case: u16) -> Self {
        Self {
            script_module: format!("case_{}", case).to_string(),
            script_path: PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../scripts/test.py")),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{array::IntoIter, iter::FromIterator};

    use super::*;

    #[test]
    fn make_cert() -> Result<(), anyhow::Error> {
        Config::test_config(1).make_certificate(
            "test".to_string(),
            Some("1234".to_string()),
            "5678".to_string(),
            None,
        )?;
        Config::test_config(2).make_certificate(
            "what".to_string(),
            None,
            "abcdef".to_string(),
            Some(HashMap::new()),
        )?;
        let test_3_data = HashMap::<_, _>::from_iter(IntoIter::new([
            ("key".to_owned(), "value".to_owned()),
            ("one".to_owned(), "two".to_owned()),
        ]));
        Config::test_config(3).make_certificate(
            "which".to_string(),
            Some("this".to_string()),
            "qwerty".to_string(),
            Some(test_3_data),
        )?;
        assert!(Config::test_config(4)
            .make_certificate(
                "test".to_string(),
                Some("1234".to_string()),
                "5678".to_string(),
                None,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn revoke_cert() -> Result<(), anyhow::Error> {
        Config::test_config(1).make_certificate(
            "test".to_string(),
            Some("1234".to_string()),
            "5678".to_string(),
            None,
        )?;
        Config::test_config(2).make_certificate(
            "what".to_string(),
            None,
            "abcdef".to_string(),
            Some(HashMap::new()),
        )?;
        let test_3_data = HashMap::<_, _>::from_iter(IntoIter::new([
            ("key".to_owned(), "value".to_owned()),
            ("one".to_owned(), "two".to_owned()),
        ]));
        Config::test_config(3).make_certificate(
            "which".to_string(),
            Some("this".to_string()),
            "qwerty".to_string(),
            Some(test_3_data),
        )?;
        assert!(Config::test_config(4)
            .make_certificate(
                "test".to_string(),
                Some("1234".to_string()),
                "5678".to_string(),
                None,
            )
            .is_err());
        Ok(())
    }
}
