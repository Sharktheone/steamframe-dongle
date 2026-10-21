//! Authenticated Remote Play LAN provisioning. No Steam library or headset SSH.

mod config;
mod credentials;
mod discovery;
mod proto;
mod transport;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use openssl::hash::{MessageDigest, hash};
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, encrypt};

pub use credentials::{Credentials, saved};

use credentials::{load_saved, save};
use proto::{blob, bytes, fixed, number, uint};
use transport::{Connection, Message, Transport};

#[derive(Clone, Debug)]
pub struct Device {
    pub id: u64,
    pub name: String,
    pub address: SocketAddr,
    pub frame: bool,
}

struct Local {
    id: u64,
    instance: u64,
    status: Vec<u8>,
    users: Vec<(u64, u64)>,
}

pub struct Lan {
    root: PathBuf,
    local: Local,
    pub devices: Vec<Device>,
}

fn random_id() -> Result<u64> {
    let mut b = [0; 8];

    rand_bytes(&mut b)?;

    Ok(u64::from_le_bytes(b) | 1)
}

impl Lan {
    pub fn select(&self, id: Option<u64>) -> Result<&Device> {
        let found = self
            .devices
            .iter()
            .filter(|d| d.frame && id.is_none_or(|id| d.id == id))
            .collect::<Vec<_>>();

        match found.as_slice() {
            [device] => Ok(device),
            [] => bail!(
                "no matching Steam Frame on the LAN; keep it awake, enable Remote Play, or use --host IP"
            ),
            _ => bail!("several Frames are visible; select one with --client ID"),
        }
    }

    pub fn load_saved(&self, device: &Device, confirmed: bool) -> Result<Credentials> {
        load_saved(device.id, confirmed)
    }

    pub fn provision(
        &self,
        device: &Device,
        creds: &Credentials,
        timeout: Duration,
    ) -> Result<PathBuf> {
        creds.validate()?;

        let auth = config::authentication(&self.root, &self.local.users, device.id)?;

        let path = save(device.id, creds, false)?;

        eprintln!(
            "Setting hotspot credentials on {} ({}) over authenticated LAN; this can interrupt its current Wi-Fi connection.",
            device.name, device.id
        );

        let deadline = Instant::now() + timeout;

        let expected_hash = network_hash(creds)?;

        let mut sent = false;

        // A second Steam connection using the same paired PC identity can be
        // reclaimed by Steam. Reconnect only to observe the configured hash;
        // never silently send a second provisioning request after an EOF.
        for attempt in 0..4 {
            ensure!(
                Instant::now() < deadline,
                "provisioning timed out; credentials remain saved in {}",
                path.display()
            );

            let mut connection = Connection::open(device, &auth, deadline).with_context(|| {
                format!(
                    "credentials saved in {}; {}",
                    path.display(),
                    if sent {
                        "request was sent earlier and may have been applied"
                    } else {
                        "request not sent"
                    }
                )
            })?;

            match self.exchange(
                &mut connection,
                device,
                &auth,
                creds,
                expected_hash,
                &mut sent,
                deadline,
            ) {
                Ok(true) => {
                    save(device.id, creds, true)?;

                    return Ok(path);
                }

                Ok(false) if sent && attempt < 3 => {
                    eprintln!(
                        "Steam reclaimed the LAN connection; checking the Frame's configured network."
                    );
                }

                Ok(false) => break,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "credentials saved in {}; {}",
                            path.display(),
                            if sent {
                                "request sent; the Frame may already have applied them"
                            } else {
                                "request not sent"
                            }
                        )
                    });
                }
            }
        }

        bail!(
            "Frame did not confirm provisioning; {}. Credentials saved in {}. Retry with the same SSID/password rather than generating new ones",
            if sent {
                "request was sent and may have been applied"
            } else {
                "no request was sent"
            },
            path.display()
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &self,
        connection: &mut impl Transport,
        device: &Device,
        auth: &config::Auth,
        creds: &Credentials,
        expected: u64,
        sent: &mut bool,
        deadline: Instant,
    ) -> Result<bool> {
        let job = random_id()?;

        let mut identified = false;

        let mut status = self.local.status.clone();

        // Last-value protobuf semantics override Steam's hardware capability.
        uint(&mut status, 29, 1);

        let mut own = Vec::new();

        uint(&mut own, 1, self.local.id);
        uint(&mut own, 2, self.local.instance);
        blob(&mut own, 3, &status);

        let mut request_status = Vec::new();

        uint(&mut request_status, 1, self.local.id);
        uint(&mut request_status, 2, self.local.instance);

        connection.send(9515, &request_status, &[])?;

        while Instant::now() < deadline {
            let Some(message) = connection.receive()? else {
                return Ok(false);
            };

            let Message { kind, header, body } = message;

            match kind {
                9515 => {
                    connection.send(9516, &own, &[])?;
                }
                9516 => {
                    ensure!(
                        number(&body, 1)? == Some(device.id),
                        "TLS peer has a different Steam client ID"
                    );

                    identified = true;

                    if !*sent {
                        let mut request = Vec::new();

                        blob(&mut request, 1, creds.ssid.as_bytes());
                        blob(&mut request, 2, creds.psk.as_bytes());
                        uint(&mut request, 3, 1);

                        let mut header = Vec::new();

                        fixed(&mut header, 10, job);

                        // Mark before writing: a partial write is ambiguous.
                        *sent = true;

                        connection.send(9524, &request, &header)?;
                    }
                }
                9521 => {
                    ensure!(
                        identified,
                        "Frame requested authorization before identifying itself"
                    );

                    let challenge = bytes(&body, 1)?.context("missing authorization challenge")?;

                    ensure!(
                        challenge.len() == 16,
                        "unexpected authorization challenge length"
                    );

                    let mut reply = Vec::new();

                    blob(&mut reply, 1, &proof(&auth.paired, challenge)?);

                    if let Some(id) = number(&body, 2)? {
                        uint(&mut reply, 2, id);
                    }

                    let mut reply_header = Vec::new();

                    if let Some(source) = number(&header, 10)? {
                        fixed(&mut reply_header, 11, source);
                    }

                    connection.send(9522, &reply, &reply_header)?;
                }
                9523 if identified => {
                    if number(&body, 5)? == Some(expected) {
                        eprintln!("Frame reports the requested hotspot network hash.");

                        return Ok(true);
                    }
                }
                9525 if identified && number(&header, 11)? == Some(job) => {
                    let result = number(&body, 1)?.unwrap_or(2);

                    if result == 1 {
                        eprintln!("Frame completed hotspot provisioning.");

                        return Ok(true);
                    }

                    if result != 8 {
                        bail!(
                            "Frame rejected hotspot provisioning: {}",
                            pair_error(result)
                        );
                    }

                    if let (Some(done), Some(total)) = (number(&body, 4)?, number(&body, 5)?) {
                        eprintln!("Frame provisioning: {done}/{total}");
                    }
                }
                9505 => connection.send(9506, &[], &[])?,
                _ => {}
            }
        }

        bail!("timed out waiting for the Frame to confirm its hotspot")
    }
}

fn proof(key: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0; 16];

    rand_bytes(&mut iv)?;

    let mut encrypted_iv = encrypt(Cipher::aes_256_ecb(), key, None, &iv)?;

    // Steam encrypts the IV as one unpadded ECB block.
    encrypted_iv.truncate(16);

    encrypted_iv.extend(encrypt(Cipher::aes_256_cbc(), key, Some(&iv), challenge)?);

    Ok(encrypted_iv)
}

fn network_hash(creds: &Credentials) -> Result<u64> {
    let joined = [creds.ssid.as_bytes(), creds.psk.as_bytes()].concat();

    let digest = hash(MessageDigest::sha1(), &joined)?;

    Ok(u64::from_be_bytes(digest[..8].try_into()?).max(1))
}

fn pair_error(code: u64) -> &'static str {
    match code {
        2 => "configuration failed",
        3 => "LAN network error",
        4 => "PC pairing authorization rejected",
        5 => "no dongle or supported provisioning role",
        6 => "authorization timed out",
        7 => "canceled",
        9 => "hotspot configuration/connection failed",
        _ => "unknown result",
    }
}
