//! UDP discovery of the running Steam client and Frames on the LAN.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};

use super::config;
use super::proto::{self, bytes, number, uint};
use super::{Device, Lan, Local, random_id};

const PORT: u16 = 27036;
const MAGIC: &[u8; 8] = b"\xff\xff\xff\xff\x21\x4c\x5f\xa0";

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

        let local = local.context(
            "running Steam did not answer loopback discovery; enable Remote Play and run as its desktop user",
        )?;

        Ok(Self {
            root,
            local,
            devices,
        })
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
