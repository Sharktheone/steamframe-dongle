//! TLS-PSK transport and bounded Remote Play message framing.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, ensure};
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};

use super::Device;
use super::config;

const MAX_PACKET: usize = 1024 * 1024;

pub(super) struct Message {
    pub kind: u32,
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

pub(super) struct Connection {
    stream: SslStream<TcpStream>,
    buffer: Vec<u8>,
    deadline: Instant,
}

pub(super) trait Transport {
    fn send(&mut self, kind: u32, body: &[u8], header: &[u8]) -> Result<()>;

    fn receive(&mut self) -> Result<Option<Message>>;
}

impl Connection {
    pub(super) fn open(device: &Device, auth: &config::Auth, deadline: Instant) -> Result<Self> {
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

        let configuration = builder
            .build()
            .configure()?
            .use_server_name_indication(false)
            .verify_hostname(false);

        let stream = configuration.connect("steam", socket).map_err(|_| {
            anyhow!(
                "Frame TLS-PSK handshake failed; check the active Steam account and LAN connectivity"
            )
        })?;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
