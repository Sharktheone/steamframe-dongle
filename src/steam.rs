//! Steam's private local IPC interface. Steam performs the authenticated LAN
//! exchange; we never implement Remote Play authentication or read NM secrets.

mod client;
mod info;
mod library;

pub use info::LibraryInfo;

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail, ensure};

use crate::Creds;
use client::{Client, Device};

pub struct Steam {
    client: Client,
}

impl Steam {
    pub fn connect(directory: Option<&Path>, ignore_signatures: bool) -> Result<Self> {
        Ok(Self {
            client: Client::connect(directory, ignore_signatures)?,
        })
    }

    pub fn devices(&self) -> Result<Vec<Device>> {
        self.client.devices()
    }

    pub fn credentials(&self, client: Option<u64>, timeout: Duration) -> Result<Creds> {
        let devices = self.devices()?;

        let device = select_device(&devices, client)?;

        eprintln!(
            "Requesting Wi-Fi pairing with {} ({}) over Steam Remote Play on the LAN.",
            device.name, device.id
        );

        eprintln!("Keep the headset awake; approve the pairing PIN in Steam if prompted.");

        // Drain old broadcasts so an earlier pairing cannot satisfy this request.
        self.client.drain_callbacks(None)?;

        let call = self.client.pair(device.id);

        ensure!(
            call != 0 && call != u64::MAX,
            "Steam refused Wi-Fi pairing; enable the streaming adapter in Steam and on the headset"
        );

        let deadline = Instant::now() + timeout;

        loop {
            if let Some(status) = self.client.drain_callbacks(Some(call))? {
                check_pair_result(status)?;

                // Steam writes these keys when the LAN response arrives, before
                // it posts the pairing result. Never use cached keys on failure.
                let ssid = self
                    .client
                    .config_string(c"streaming_v2\\WifiAPPairedSSID")?;
                let psk = self
                    .client
                    .config_string(c"streaming_v2\\WifiAPPairedPassword")?;

                ensure!(
                    !ssid.is_empty() && ssid.len() <= 32,
                    "Steam paired but did not provide a valid hotspot SSID"
                );

                ensure!(
                    !psk.is_empty(),
                    "Steam paired but did not provide the hotspot password"
                );

                return Ok(Creds {
                    ssid,
                    psk,
                    origin: format!("Steam LAN pairing with {} ({})", device.name, device.id),
                });
            }

            ensure!(
                Instant::now() < deadline,
                "Steam Wi-Fi pairing timed out after {}s; keep both devices on the LAN, the headset awake, and approve any Steam PIN prompt",
                timeout.as_secs()
            );

            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn select_device(devices: &[Device], requested: Option<u64>) -> Result<&Device> {
    if let Some(id) = requested {
        let device = devices
            .iter()
            .find(|d| d.id == id)
            .ok_or_else(|| anyhow!("Steam cannot see client {id}; run `steam-devices`"))?;

        ensure!(
            device.local,
            "{} has no LAN Remote Play connection",
            device.name
        );

        // Steam's UI capability flag also depends on its own dongle detection.
        // Explicit selection can still request the LAN exchange to get credentials.
        return Ok(device);
    }

    let candidates = devices
        .iter()
        .filter(|d| d.local && d.can_pair)
        .collect::<Vec<_>>();

    match candidates.as_slice() {
        [device] => Ok(device),
        [] => bail!(
            "Steam reports no Wi-Fi pairing candidates on the LAN; run `steam-devices` and use --steam-client ID to request pairing explicitly (Steam's capability flag also depends on dongle detection)"
        ),
        _ => bail!(
            "several headsets are available; run `steam-devices` and select one with --steam-client ID"
        ),
    }
}

fn check_pair_result(result: i32) -> Result<()> {
    match result {
        1 => Ok(()),
        2 => bail!("Steam Wi-Fi pairing failed"),
        3 => bail!("Steam Wi-Fi pairing failed: LAN network error"),
        4 => bail!("Steam Wi-Fi pairing failed: PIN authorization rejected"),
        5 => bail!("Steam Wi-Fi pairing failed: no streaming dongle detected by Steam"),
        6 => bail!("Steam Wi-Fi pairing failed: authorization timed out"),
        7 => bail!("Steam Wi-Fi pairing was canceled"),
        _ => bail!("Steam returned an unsupported Wi-Fi pairing result ({result})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client::fake::{self, CLIENT};
    use std::mem::ManuallyDrop;

    fn fake_steam(reject: bool) -> ManuallyDrop<Steam> {
        ManuallyDrop::new(Steam {
            client: ManuallyDrop::into_inner(fake::client(reject)),
        })
    }

    #[test]
    fn fresh_pairing_reads_credentials_without_networkmanager() {
        let steam = fake_steam(false);
        let creds = steam
            .credentials(Some(CLIENT), Duration::from_millis(10))
            .unwrap();
        assert_eq!(creds.ssid, "frame_TEST");
        assert_eq!(creds.psk, "test-password");
        assert!(creds.origin.contains("Steam LAN pairing"));
        assert!(fake::drained());
        assert_eq!(fake::reads(), 2);
    }

    #[test]
    fn pairing_failure_never_returns_cached_credentials() {
        let steam = fake_steam(true);
        let error = steam
            .credentials(Some(CLIENT), Duration::from_millis(10))
            .err()
            .unwrap();
        assert!(error.to_string().contains("PIN authorization rejected"));
        assert_eq!(fake::reads(), 0);
    }

    #[test]
    fn explicit_selection_does_not_require_steam_dongle_detection() {
        let devices = [Device {
            id: CLIENT,
            name: "Frame".into(),
            local: true,
            can_pair: false,
        }];
        assert_eq!(select_device(&devices, Some(CLIENT)).unwrap().id, CLIENT);
        assert!(select_device(&devices, None).is_err());
        assert!(select_device(&devices, Some(999)).is_err());
    }

    #[test]
    fn ambiguous_and_non_lan_peers_are_rejected() {
        let mut devices = vec![
            Device {
                id: 1,
                name: "A".into(),
                local: true,
                can_pair: true,
            },
            Device {
                id: 2,
                name: "B".into(),
                local: true,
                can_pair: true,
            },
        ];
        assert!(select_device(&devices, None).is_err());
        devices[1].local = false;
        assert_eq!(select_device(&devices, None).unwrap().id, 1);
        assert!(select_device(&devices, Some(2)).is_err());
    }
}
