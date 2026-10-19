//! Minimal NetworkManager D-Bus client (org.freedesktop.NetworkManager).
//!
//! Secrets go over D-Bus, never through a command line, so the PSK does not
//! show up in `ps` or shell history.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
const CONN_IFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";

/// The profile the Steam client itself creates for the adapter.
pub const STEAM_PROFILE: &str = "Steam Frame Wireless Adapter";

type Settings = HashMap<String, HashMap<String, OwnedValue>>;

pub struct Nm {
    bus: Connection,
}

pub struct WifiProfile<'a> {
    pub name: &'a str,
    pub mac: &'a [u8],
    pub ssid: &'a str,
    pub psk: &'a str,
    /// true: WPA3-SAE with mandatory PMF (what the Frame's 6 GHz AP wants).
    /// false: WPA2-PSK like Steam's own profile.
    pub sae: bool,
    pub autoconnect: bool,
}

fn get_str(s: &Settings, sec: &str, key: &str) -> Option<String> {
    s.get(sec)?.get(key)?.downcast_ref::<String>().ok()
}

fn get_bytes(s: &Settings, sec: &str, key: &str) -> Option<Vec<u8>> {
    let v = s.get(sec)?.get(key)?.try_clone().ok()?;

    Vec::<u8>::try_from(v).ok()
}

impl Nm {
    pub fn connect() -> Result<Self> {
        Ok(Self {
            bus: Connection::system().context("connecting to the system D-Bus")?,
        })
    }

    fn proxy<'p>(&self, path: &'p str, iface: &'p str) -> Result<Proxy<'p>> {
        Ok(Proxy::new(&self.bus, NM, path, iface)?)
    }

    fn settings_of(&self, path: &ObjectPath) -> Result<Settings> {
        let p = self.proxy(path.as_str(), CONN_IFACE)?;

        Ok(p.call("GetSettings", &())?)
    }

    /// Object paths of all saved profiles with the given `connection.id`.
    pub fn find_by_name(&self, name: &str) -> Result<Vec<OwnedObjectPath>> {
        let settings = self.proxy(SETTINGS_PATH, SETTINGS_IFACE)?;

        let all: Vec<OwnedObjectPath> = settings.call("ListConnections", &())?;

        let mut hits = Vec::new();

        for path in all {
            let s = self.settings_of(&path)?;

            if get_str(&s, "connection", "id").as_deref() == Some(name) {
                hits.push(path);
            }
        }

        Ok(hits)
    }

    /// Reads SSID + PSK out of an existing Wi-Fi profile (e.g. the one Steam
    /// wrote after receiving the credentials from the headset).
    pub fn read_wifi_credentials(&self, name: &str) -> Result<(String, String)> {
        let path = self
            .find_by_name(name)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no NetworkManager profile named {name:?}"))?;

        let s = self.settings_of(&path)?;

        let ssid = get_bytes(&s, "802-11-wireless", "ssid")
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .ok_or_else(|| anyhow!("profile {name:?} has no SSID"))?;

        let p = self.proxy(path.as_str(), CONN_IFACE)?;

        let secrets: Settings = p
            .call("GetSecrets", &("802-11-wireless-security",))
            .context("GetSecrets refused (try running as root or via polkit)")?;

        let psk = get_str(&secrets, "802-11-wireless-security", "psk")
            .ok_or_else(|| anyhow!("profile {name:?} has no stored PSK"))?;

        Ok((ssid, psk))
    }

    /// Creates (or replaces) a Wi-Fi station profile pinned to the dongle.
    pub fn upsert_wifi(&self, w: &WifiProfile) -> Result<OwnedObjectPath> {
        let mut connection = HashMap::new();

        connection.insert("id", Value::from(w.name));
        connection.insert("type", Value::from("802-11-wireless"));

        // Pinned by permanent MAC only, so it survives moving the dongle to
        // another USB port (which renames the interface).
        connection.insert("autoconnect", Value::from(w.autoconnect));

        let mut wifi = HashMap::new();
        wifi.insert("ssid", Value::from(w.ssid.as_bytes().to_vec()));
        wifi.insert("mode", Value::from("infrastructure"));

        // The Frame's AP is hidden, so probe for it explicitly.
        wifi.insert("hidden", Value::from(true));
        wifi.insert("mac-address", Value::from(w.mac.to_vec()));

        // Streaming hates power-save latency spikes. 2 = disable.
        wifi.insert("powersave", Value::from(2u32));

        let mut sec = HashMap::new();

        sec.insert(
            "key-mgmt",
            Value::from(if w.sae { "sae" } else { "wpa-psk" }),
        );

        sec.insert("psk", Value::from(w.psk));
        sec.insert("psk-flags", Value::from(0u32));

        // 3 = required, 1 = optional (NM_SETTING_WIRELESS_SECURITY_PMF_*).
        sec.insert("pmf", Value::from(if w.sae { 3i32 } else { 1i32 }));

        // The link is point-to-point to the headset (it hands out 10.35.78.x
        // via DHCP); never let it steal the default route or DNS.
        let mut ipv4 = HashMap::new();
        ipv4.insert("method", Value::from("auto"));
        ipv4.insert("never-default", Value::from(true));
        ipv4.insert("ignore-auto-dns", Value::from(true));

        let mut ipv6 = HashMap::new();
        ipv6.insert("method", Value::from("auto"));
        ipv6.insert("never-default", Value::from(true));
        ipv6.insert("ignore-auto-dns", Value::from(true));

        let mut s: HashMap<&str, HashMap<&str, Value>> = HashMap::new();
        s.insert("connection", connection);
        s.insert("802-11-wireless", wifi);
        s.insert("802-11-wireless-security", sec);
        s.insert("ipv4", ipv4);
        s.insert("ipv6", ipv6);

        if let Some(existing) = self.find_by_name(w.name)?.into_iter().next() {
            self.proxy(existing.as_str(), CONN_IFACE)?
                .call::<_, _, ()>("Update", &(s,))?;

            Ok(existing)
        } else {
            let settings = self.proxy(SETTINGS_PATH, SETTINGS_IFACE)?;

            Ok(settings.call("AddConnection", &(s,))?)
        }
    }

    pub fn delete(&self, name: &str) -> Result<usize> {
        let hits = self.find_by_name(name)?;

        for path in &hits {
            self.proxy(path.as_str(), CONN_IFACE)?
                .call::<_, _, ()>("Delete", &())?;
        }

        Ok(hits.len())
    }

    pub fn activate(&self, conn: &ObjectPath, iface: &str) -> Result<OwnedObjectPath> {
        let nm = self.proxy(NM_PATH, NM)?;

        let dev: OwnedObjectPath = nm
            .call("GetDeviceByIpIface", &(iface,))
            .with_context(|| format!("NetworkManager does not know device {iface}"))?;

        let root = ObjectPath::try_from("/")?;

        Ok(nm.call("ActivateConnection", &(conn, &*dev, root))?)
    }

    /// Burned-in MAC of a Wi-Fi device. sysfs `address` may be a randomized
    /// scan MAC, which would make a MAC-pinned profile never match.
    pub fn perm_mac(&self, iface: &str) -> Result<String> {
        let nm = self.proxy(NM_PATH, NM)?;

        let dev: OwnedObjectPath = nm.call("GetDeviceByIpIface", &(iface,))?;

        let wifi = self.proxy(
            dev.as_str(),
            "org.freedesktop.NetworkManager.Device.Wireless",
        )?;

        Ok(wifi.get_property("PermHwAddress")?)
    }

    pub fn deactivate_on(&self, iface: &str) -> Result<bool> {
        let nm = self.proxy(NM_PATH, NM)?;

        let dev: OwnedObjectPath = nm.call("GetDeviceByIpIface", &(iface,))?;

        let devp = self.proxy(dev.as_str(), "org.freedesktop.NetworkManager.Device")?;

        let active: OwnedObjectPath = devp.get_property("ActiveConnection")?;

        if active.as_str() == "/" {
            return Ok(false);
        }

        nm.call::<_, _, ()>("DeactivateConnection", &(&*active,))?;

        Ok(true)
    }
}
