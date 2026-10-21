//! Locating the Steam Frame Wireless Adapter (USB 28de:2432, Realtek RTL8852CU)
//! through sysfs.

use std::fs;
use std::path::Path;

pub const VALVE_VID: &str = "28de";
// TODD: is this the same for all dongles?
pub const FRAME_DONGLE_PID: &str = "2432";

#[derive(Debug, Clone)]
pub struct Dongle {
    pub iface: String,
    pub mac: String,
    pub serial: Option<String>,
    pub driver: Option<String>,
}

fn read_trim(p: impl AsRef<Path>) -> Option<String> {
    // TODO: this is a bit wasteful, but it's fine for now.
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn matches_trim(p: impl AsRef<Path>, val: &str) -> bool {
    fs::read_to_string(p)
        .ok()
        .map(|s| s.trim() == val)
        .unwrap_or(false)
}

/// An explicitly selected wireless interface, including ordinary PCI/USB radios.
pub fn by_iface(iface: &str) -> anyhow::Result<Dongle> {
    anyhow::ensure!(
        !iface.is_empty() && iface != "." && iface != ".." && !iface.contains('/'),
        "invalid network interface name"
    );

    let net = Path::new("/sys/class/net").join(iface);

    anyhow::ensure!(
        net.join("phy80211").exists(),
        "{iface} is not a wireless interface"
    );

    let mac = read_trim(net.join("address"))
        .ok_or_else(|| anyhow::anyhow!("cannot read the MAC address of {iface}"))?;

    parse_mac(&mac)?;

    let driver = fs::read_link(net.join("device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));

    Ok(Dongle {
        iface: iface.to_owned(),
        mac,
        serial: None,
        driver,
    })
}

/// Every wireless netdev whose USB parent is the Steam Frame adapter.
pub fn find_all() -> Vec<Dongle> {
    let mut out = Vec::new();

    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return out;
    };

    for entry in entries.flatten() {
        let iface = entry.file_name().to_string_lossy().into_owned();

        let net = entry.path();

        //TODO: validate this is the same on all machines!
        if !net.join("phy80211").exists() {
            continue;
        }

        // /sys/class/net/<if>/device -> .../usbX/X-Y/X-Y:1.0 (USB interface);
        // its parent is the USB device that carries idVendor/idProduct/serial.
        let Ok(intf) = fs::canonicalize(net.join("device")) else {
            continue;
        };

        let Some(usbdev) = intf.parent() else {
            continue;
        };

        if !matches_trim(usbdev.join("idVendor"), VALVE_VID)
            || !matches_trim(usbdev.join("idProduct"), FRAME_DONGLE_PID)
        {
            continue;
        }

        let driver = fs::read_link(intf.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));

        out.push(Dongle {
            mac: read_trim(net.join("address")).unwrap_or_default(),
            serial: read_trim(usbdev.join("serial")),
            driver,
            iface,
        });
    }

    out.sort_by(|a, b| a.iface.cmp(&b.iface));

    out
}

pub fn parse_mac(mac: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = mac
        .split(':')
        .map(|b| u8::from_str_radix(b, 16))
        .collect::<Result<Vec<_>, _>>()?;

    anyhow::ensure!(bytes.len() == 6, "invalid MAC address {mac}");

    Ok(bytes)
}
