//! Authenticated Remote Play LAN provisioning. No Steam library or headset SSH.
mod config;
mod proto;

use anyhow::{Context, Result, bail, ensure};
use openssl::{
    hash::{MessageDigest, hash},
    rand::rand_bytes,
    ssl::{SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion},
    symm::{Cipher, encrypt},
};
use proto::{blob, bytes, fixed, number, uint};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const PORT: u16 = 27036;
const MAGIC: &[u8; 8] = b"\xff\xff\xff\xff\x21\x4c\x5f\xa0";
const MAX_PACKET: usize = 1024 * 1024;

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
    pub fn discover(directory: Option<&Path>, host: Option<IpAddr>) -> Result<Self> {
        ensure!(
            host.is_none_or(|h| h.is_ipv4()),
            "LAN discovery currently requires an IPv4 address"
        );
        let root = config::root(directory)?;
        let my_id = config::client_id(&root)?;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let mut header = Vec::new();
        uint(&mut header, 1, random_id()?);
        uint(&mut header, 2, 0);
        let mut body = Vec::new();
        uint(&mut body, 1, 1);
        let mut packet = MAGIC.to_vec();
        packet.extend((header.len() as u32).to_le_bytes());
        packet.extend(header);
        packet.extend((body.len() as u32).to_le_bytes());
        packet.extend(body);
        let target = host.unwrap_or(IpAddr::V4(Ipv4Addr::BROADCAST));
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut next_probe = Instant::now();
        let mut buf = [0; 65535];
        let mut local = None;
        let mut devices: Vec<Device> = Vec::new();
        while Instant::now() < deadline {
            if Instant::now() >= next_probe {
                socket.send_to(&packet, (Ipv4Addr::LOCALHOST, PORT))?;
                socket.send_to(&packet, (target, PORT))?;
                next_probe = Instant::now() + Duration::from_secs(1);
            }
            let (len, source) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let Ok((header, status)) = discovery_packet(&buf[..len]) else {
                continue;
            };
            if number(header, 2)? != Some(1) {
                continue;
            }
            let Some(id) = number(header, 1)? else {
                continue;
            };
            if source.ip().is_loopback() && id == my_id {
                let mut users = Vec::new();
                for (field, value) in proto::fields(status)? {
                    if let (9, proto::Value::Bytes(user)) = (field, value)
                        && let (Some(id), Some(key)) = (number(user, 1)?, number(user, 2)?)
                    {
                        users.push((id, key));
                    }
                }
                local = Some(Local {
                    id,
                    instance: number(header, 3)?.context("Steam status has no instance ID")?,
                    status: status.to_vec(),
                    users,
                });
            } else if id != my_id && host.is_none_or(|h| source.ip() == h) {
                let port = u16::try_from(number(status, 3)?.unwrap_or(PORT.into()))?;
                if port == 0 {
                    continue;
                }
                let device = Device {
                    id,
                    name: String::from_utf8_lossy(bytes(status, 4)?.unwrap_or(b"unknown"))
                        .into_owned(),
                    address: SocketAddr::new(source.ip(), port),
                    frame: number(status, 31)? == Some(5001),
                };
                if !devices.iter().any(|d| d.id == id) {
                    devices.push(device);
                }
            }
        }
        Ok(Self { root, local: local.context("running Steam did not answer loopback discovery; enable Remote Play and run as its desktop user")?, devices })
    }

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

fn discovery_packet(packet: &[u8]) -> Result<(&[u8], &[u8])> {
    ensure!(
        packet.len() >= 16 && &packet[..8] == MAGIC,
        "invalid discovery packet"
    );
    let hlen = u32::from_le_bytes(packet[8..12].try_into()?) as usize;
    let end = 12usize
        .checked_add(hlen)
        .context("discovery length overflow")?;
    ensure!(end <= packet.len() - 4, "truncated discovery header");
    let blen = u32::from_le_bytes(packet[end..end + 4].try_into()?) as usize;
    ensure!(blen == packet.len() - end - 4, "truncated discovery body");
    Ok((&packet[12..end], &packet[end + 4..]))
}

struct Message {
    kind: u32,
    header: Vec<u8>,
    body: Vec<u8>,
}
struct Connection {
    stream: SslStream<TcpStream>,
    buffer: Vec<u8>,
    deadline: Instant,
}
trait Transport {
    fn send(&mut self, kind: u32, body: &[u8], header: &[u8]) -> Result<()>;
    fn receive(&mut self) -> Result<Option<Message>>;
}
impl Connection {
    fn open(device: &Device, auth: &config::Auth, deadline: Instant) -> Result<Self> {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        ensure!(!remaining.is_zero(), "connection deadline expired");
        let socket = TcpStream::connect_timeout(&device.address, remaining)
            .context("connecting to Frame Remote Play")?;
        socket.set_read_timeout(Some(remaining))?;
        socket.set_write_timeout(Some(remaining))?;
        let mut builder = SslConnector::builder(SslMethod::tls_client())?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        // EOF is never confirmation: it only triggers the observe-only retry.
        builder.set_options(SslOptions::IGNORE_UNEXPECTED_EOF);
        // Steam authenticates TLS with the account's shared PSK, not an X.509 certificate.
        builder.set_verify(SslVerifyMode::NONE);
        builder.set_cipher_list(
            "PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256:PSK-AES256-CBC-SHA:PSK-AES128-CBC-SHA",
        )?;
        let shared = auth.shared.clone();
        builder.set_psk_client_callback(move |_, _, identity, key| {
            if identity.len() < 6 || key.len() < shared.len() {
                return Ok(0);
            }
            identity[..6].copy_from_slice(b"steam\0");
            key[..shared.len()].copy_from_slice(&shared);
            Ok(shared.len())
        });
        let stream = builder.build().configure()?.use_server_name_indication(false).verify_hostname(false).connect("steam",socket).map_err(|_| anyhow::anyhow!("Frame TLS-PSK handshake failed; check the active Steam account and LAN connectivity"))?;
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok(Self {
            stream,
            buffer: Vec::new(),
            deadline,
        })
    }
}
impl Transport for Connection {
    fn send(&mut self, kind: u32, body: &[u8], header: &[u8]) -> Result<()> {
        let len = 8 + header.len() + body.len();
        ensure!(len <= MAX_PACKET, "outgoing packet too large");
        let mut packet = Vec::with_capacity(len + 8);
        packet.extend((len as u32).to_le_bytes());
        packet.extend(b"VT01");
        packet.extend((kind | 0x80000000).to_le_bytes());
        packet.extend((header.len() as u32).to_le_bytes());
        packet.extend(header);
        packet.extend(body);
        self.stream
            .write_all(&packet)
            .context("writing Remote Play message")
    }
    fn receive(&mut self) -> Result<Option<Message>> {
        loop {
            if let Some((message, used)) = decode_packet(&self.buffer)? {
                self.buffer.drain(..used);
                return Ok(Some(message));
            }
            ensure!(
                Instant::now() < self.deadline,
                "Remote Play response timed out"
            );
            let mut data = [0; 16384];
            match self.stream.read(&mut data) {
                Ok(0) => return Ok(None),
                Ok(n) => self.buffer.extend_from_slice(&data[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e).context("reading Remote Play message"),
            }
            ensure!(
                self.buffer.len() <= MAX_PACKET + 8,
                "Remote Play input limit exceeded"
            );
        }
    }
}

fn decode_packet(data: &[u8]) -> Result<Option<(Message, usize)>> {
    if data.len() < 8 {
        return Ok(None);
    }
    let len = u32::from_le_bytes(data[..4].try_into()?) as usize;
    ensure!(
        (8..=MAX_PACKET).contains(&len) && &data[4..8] == b"VT01",
        "invalid Remote Play frame"
    );
    if data.len() < len + 8 {
        return Ok(None);
    }
    let kind = u32::from_le_bytes(data[8..12].try_into()?);
    ensure!(
        kind & 0x80000000 != 0,
        "expected protobuf Remote Play message"
    );
    let hlen = u32::from_le_bytes(data[12..16].try_into()?) as usize;
    ensure!(hlen <= len - 8, "invalid Remote Play header length");
    Ok(Some((
        Message {
            kind: kind & 0x7fffffff,
            header: data[16..16 + hlen].to_vec(),
            body: data[16 + hlen..len + 8].to_vec(),
        },
        len + 8,
    )))
}

fn proof(key: &[u8], challenge: &[u8]) -> Result<Vec<u8>> {
    let mut iv = [0; 16];
    rand_bytes(&mut iv)?;
    let mut encrypted_iv = encrypt(Cipher::aes_256_ecb(), key, None, &iv)?;
    encrypted_iv.truncate(16); // Steam encrypts the IV as one unpadded ECB block.
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
fn load_saved(id: u64, confirmed: bool) -> Result<Credentials> {
    read_saved(&state_path(id)?, id, confirmed)
}
fn read_saved(path: &Path, id: u64, confirmed: bool) -> Result<Credentials> {
    let saved: Saved = serde_json::from_slice(&fs::read(path).with_context(|| {
        format!(
            "no saved credentials in {}; run set-creds first",
            path.display()
        )
    })?)?;
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
fn save(id: u64, creds: &Credentials, confirmed: bool) -> Result<PathBuf> {
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
    let result = (|| -> Result<()> {
        file.write_all(&serde_json::to_vec_pretty(&saved)?)?;
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
    use std::collections::VecDeque;

    struct Script {
        input: VecDeque<Message>,
        output: Vec<Message>,
        result: Option<u64>,
    }
    impl Transport for Script {
        fn send(&mut self, kind: u32, body: &[u8], header: &[u8]) -> Result<()> {
            self.output.push(Message {
                kind,
                body: body.to_vec(),
                header: header.to_vec(),
            });
            if kind == 9524
                && let Some(result) = self.result
            {
                let job = number(header, 10)?.unwrap();
                let mut challenge = Vec::new();
                blob(&mut challenge, 1, &[0x34; 16]);
                uint(&mut challenge, 2, 42);
                let mut challenge_header = Vec::new();
                fixed(&mut challenge_header, 10, 123);
                self.input.push_back(Message {
                    kind: 9521,
                    header: challenge_header,
                    body: challenge,
                });
                // An unrelated successful response must not complete this job.
                self.input.push_back(response(job.wrapping_add(1), 1));
                self.input.push_back(response(job, 8));
                self.input.push_back(response(job, result));
            }
            Ok(())
        }
        fn receive(&mut self) -> Result<Option<Message>> {
            Ok(self.input.pop_front())
        }
    }
    fn response(job: u64, result: u64) -> Message {
        let mut header = Vec::new();
        fixed(&mut header, 11, job);
        let mut body = Vec::new();
        uint(&mut body, 1, result);
        Message {
            kind: 9525,
            header,
            body,
        }
    }
    fn session() -> (Lan, Device, config::Auth, Credentials, Script) {
        let device = Device {
            id: 99,
            name: "Frame".into(),
            address: "127.0.0.1:27036".parse().unwrap(),
            frame: true,
        };
        let lan = Lan {
            root: PathBuf::new(),
            local: Local {
                id: 12,
                instance: 13,
                status: vec![],
                users: vec![],
            },
            devices: vec![device.clone()],
        };
        let auth = config::Auth {
            shared: vec![0x12; 32],
            paired: vec![0x56; 32],
        };
        let creds = Credentials {
            ssid: "frame_TEST".into(),
            psk: "test-password".into(),
        };
        let mut status = Vec::new();
        uint(&mut status, 1, 99);
        let script = Script {
            input: VecDeque::from([
                Message {
                    kind: 9515,
                    header: vec![],
                    body: vec![],
                },
                Message {
                    kind: 9516,
                    header: vec![],
                    body: status,
                },
            ]),
            output: vec![],
            result: Some(1),
        };
        (lan, device, auth, creds, script)
    }
    #[test]
    fn authenticated_provisioning_correlates_job_and_answers_proof() {
        let (lan, device, auth, creds, mut script) = session();
        let mut sent = false;
        assert!(
            lan.exchange(
                &mut script,
                &device,
                &auth,
                &creds,
                network_hash(&creds).unwrap(),
                &mut sent,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
        );
        assert!(sent);
        let request = script.output.iter().find(|m| m.kind == 9524).unwrap();
        assert_eq!(
            bytes(&request.body, 1).unwrap(),
            Some(creds.ssid.as_bytes())
        );
        assert_eq!(bytes(&request.body, 2).unwrap(), Some(creds.psk.as_bytes()));
        let response = script.output.iter().find(|m| m.kind == 9522).unwrap();
        assert_eq!(number(&response.header, 11).unwrap(), Some(123));
        assert_eq!(number(&response.body, 2).unwrap(), Some(42));
        assert_eq!(bytes(&response.body, 1).unwrap().unwrap().len(), 48);
        let status = script.output.iter().find(|m| m.kind == 9516).unwrap();
        assert_eq!(
            number(bytes(&status.body, 3).unwrap().unwrap(), 29).unwrap(),
            Some(1)
        );
    }
    #[test]
    fn unauthorized_and_unrelated_success_never_confirm_provisioning() {
        let (lan, device, auth, creds, mut script) = session();
        script.result = Some(4);
        let mut sent = false;
        let error = lan
            .exchange(
                &mut script,
                &device,
                &auth,
                &creds,
                1,
                &mut sent,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
        assert!(error.to_string().contains("authorization rejected"));
    }
    #[test]
    fn reconnect_observes_network_hash_without_reprovisioning() {
        let (lan, device, auth, creds, mut script) = session();
        let expected = network_hash(&creds).unwrap();
        let mut body = Vec::new();
        fixed(&mut body, 5, expected);
        script.input.push_back(Message {
            kind: 9523,
            header: vec![],
            body,
        });
        let mut sent = true;
        assert!(
            lan.exchange(
                &mut script,
                &device,
                &auth,
                &creds,
                expected,
                &mut sent,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
        );
        assert!(!script.output.iter().any(|m| m.kind == 9524));
    }
    #[test]
    fn eof_is_not_success_and_wrong_device_is_rejected_before_provisioning() {
        let (lan, mut device, auth, creds, mut script) = session();
        script.result = None;
        let mut sent = false;
        assert!(
            !lan.exchange(
                &mut script,
                &device,
                &auth,
                &creds,
                1,
                &mut sent,
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap()
        );
        assert!(sent);
        let (_, _, _, _, mut script) = session();
        device.id = 100;
        sent = false;
        assert!(
            lan.exchange(
                &mut script,
                &device,
                &auth,
                &creds,
                1,
                &mut sent,
                Instant::now() + Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(!sent);
        assert!(!script.output.iter().any(|m| m.kind == 9524));
    }

    #[test]
    fn fragmented_framing_and_corrupt_lengths() {
        let wire = [
            10, 0, 0, 0, b'V', b'T', b'0', b'1', 0x35, 0x25, 0, 0x80, 0, 0, 0, 0, 8, 1,
        ];
        for n in 0..wire.len() {
            assert!(decode_packet(&wire[..n]).unwrap().is_none());
        }
        let (msg, used) = decode_packet(&wire).unwrap().unwrap();
        assert_eq!(used, 18);
        assert_eq!(msg.kind, 9525);
        assert_eq!(msg.body, [8, 1]);
        let mut bad = wire;
        bad[12] = 255;
        assert!(decode_packet(&bad).is_err());
        bad = wire;
        bad[4] = 0;
        assert!(decode_packet(&bad).is_err());
    }
    #[test]
    fn proof_uses_steam_encrypted_iv_and_pkcs7() {
        use openssl::symm::decrypt;
        let key = [0x12; 32];
        let challenge = [0x34; 16];
        let result = proof(&key, &challenge).unwrap();
        assert_eq!(result.len(), 48);
        // ECB decrypt without padding, since this block represents an IV.
        let mut cipher = openssl::symm::Crypter::new(
            Cipher::aes_256_ecb(),
            openssl::symm::Mode::Decrypt,
            &key,
            None,
        )
        .unwrap();
        cipher.pad(false);
        let mut iv = [0; 32];
        let n = cipher.update(&result[..16], &mut iv).unwrap();
        let m = cipher.finalize(&mut iv[n..]).unwrap();
        assert_eq!(n + m, 16);
        assert_eq!(
            decrypt(Cipher::aes_256_cbc(), &key, Some(&iv[..16]), &result[16..]).unwrap(),
            challenge
        );
    }
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
    fn network_hash_matches_independent_sha1_fixture() {
        let creds = Credentials {
            ssid: "frame_TEST".into(),
            psk: "test-password".into(),
        };
        assert_eq!(network_hash(&creds).unwrap(), 0x9d208a29fce58fc9);
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
