//! Generate and persist per-Frame hotspot credentials.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};

use super::{config, random_id};

#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub ssid: String,
    pub psk: String,
}

impl Credentials {
    pub fn generate() -> Result<Self> {
        let mut name = [0; 4];

        let mut password = [0; 16];

        rand_bytes(&mut name)?;
        rand_bytes(&mut password)?;

        Ok(Self {
            ssid: format!("frame_{}", config::hex(&name).to_uppercase()),
            psk: config::hex(&password),
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.ssid.is_empty()
                && self.ssid.len() <= 32
                && !self.ssid.chars().any(char::is_control),
            "SSID must contain 1–32 bytes without control characters"
        );

        ensure!(
            (8..=63).contains(&self.psk.len()) && self.psk.bytes().all(|b| (32..=126).contains(&b)),
            "password must contain 8–63 printable ASCII characters"
        );

        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Saved {
    client_id: u64,
    confirmed: bool,
    #[serde(flatten)]
    credentials: Credentials,
}

/// Connecting to a previously provisioned AP needs neither Steam nor a LAN
/// route to the Frame. Select only from the local per-Frame credential files.
pub fn saved(client: Option<u64>) -> Result<Credentials> {
    saved_in(&state_directory()?, client)
}

fn saved_in(directory: &Path, client: Option<u64>) -> Result<Credentials> {
    let id = if let Some(id) = client {
        id
    } else {
        let mut ids = Vec::new();

        for entry in fs::read_dir(directory).context("no saved credentials; run set-creds first")? {
            let entry = entry?;

            if entry.path().extension().is_some_and(|e| e == "json")
                && let Some(id) = entry
                    .path()
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.parse::<u64>().ok())
            {
                ids.push(id);
            }
        }

        ensure!(
            ids.len() == 1,
            "no unique saved Frame; run set-creds first or select saved credentials with --client ID"
        );

        ids[0]
    };

    read_saved(&directory.join(format!("{id}.json")), id, true)
}

pub(super) fn load_saved(id: u64, confirmed: bool) -> Result<Credentials> {
    read_saved(&state_path(id)?, id, confirmed)
}

fn read_saved(path: &Path, id: u64, confirmed: bool) -> Result<Credentials> {
    let contents = fs::read(path).with_context(|| {
        format!(
            "no saved credentials in {}; run set-creds first",
            path.display()
        )
    })?;

    let saved: Saved = serde_json::from_slice(&contents)?;

    ensure!(
        saved.client_id == id,
        "saved credentials belong to a different Frame"
    );

    ensure!(
        !confirmed || saved.confirmed,
        "saved credentials were not confirmed by the Frame; run set-creds --saved to verify/retry the same credentials"
    );

    saved.credentials.validate()?;

    Ok(saved.credentials)
}

fn state_directory() -> Result<PathBuf> {
    let root = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) => PathBuf::from(path),
        None => {
            PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?).join(".local/state")
        }
    };

    Ok(root.join("steamframe-link"))
}

fn state_path(id: u64) -> Result<PathBuf> {
    Ok(state_directory()?.join(format!("{id}.json")))
}

pub(super) fn save(id: u64, creds: &Credentials, confirmed: bool) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    let path = state_path(id)?;

    let parent = path.parent().unwrap();

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;

    ensure!(
        !fs::symlink_metadata(parent)?.file_type().is_symlink(),
        "credential directory must not be a symlink"
    );

    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;

    let temp = parent.join(format!(".pending-{}-{}", std::process::id(), random_id()?));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;

    let saved = Saved {
        client_id: id,
        confirmed,
        credentials: creds.clone(),
    };

    // Poor girls try-catch blocks - c'mon, rust!
    let result = (|| -> Result<()> {
        let contents = serde_json::to_vec_pretty(&saved)?;

        file.write_all(&contents)?;
        file.sync_all()?;

        fs::rename(&temp, &path)?;

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(temp);
    }

    result?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_validate_ssid_bytes_and_sae_passwords() {
        let mut c = Credentials::generate().unwrap();

        c.validate().unwrap();
        c.psk = "short".into();

        assert!(c.validate().is_err());

        c.psk = "12345678".into();
        c.ssid = "é".repeat(17);

        assert!(c.validate().is_err());

        c.ssid = "name\ninjection".into();

        assert!(c.validate().is_err());
    }

    #[test]
    fn cached_setup_needs_no_steam_and_rejects_unconfirmed_or_ambiguous_files() {
        let dir =
            std::env::temp_dir().join(format!("steamframe-cache-test-{}", random_id().unwrap()));

        fs::create_dir(&dir).unwrap();

        let creds = Credentials {
            ssid: "frame_TEST".into(),
            psk: "test-password".into(),
        };

        let mut saved = Saved {
            client_id: 1,
            confirmed: false,
            credentials: creds.clone(),
        };

        let path = dir.join("1.json");

        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();

        assert!(saved_in(&dir, None).is_err());

        assert_eq!(read_saved(&path, 1, false).unwrap().ssid, creds.ssid);

        saved.confirmed = true;

        fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();

        assert_eq!(saved_in(&dir, None).unwrap().ssid, creds.ssid);

        assert!(read_saved(&path, 2, true).is_err());

        saved.client_id = 2;

        fs::write(dir.join("2.json"), serde_json::to_vec(&saved).unwrap()).unwrap();

        assert!(saved_in(&dir, None).is_err());

        assert_eq!(saved_in(&dir, Some(1)).unwrap().psk, creds.psk);

        fs::remove_dir_all(dir).unwrap();
    }
}
