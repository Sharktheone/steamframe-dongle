//! steamframe-link: connect the Steam Frame Wireless Adapter to the headset's
//! hotspot on Linux using Steam's LAN Remote Play pairing channel.
//!
//! How Steam itself does it: the headset runs a hidden AP (`frame_XXXXXXXX`,
//! 32-char generated password) on its second radio `wlanap`. When the PC and
//! headset are paired for Remote Play, the headset ships the AP credentials
//! over the authenticated Remote Play control channel (EMsg 9523
//! `CMsgRemoteClientWifiAPStatus` / 9524-9525 `CMsgRemoteClientPairWifiAP[Response]`,
//! both carrying `ssid` + `password`). When connecting the Dongle, the Steam client then writes a
//! NetworkManager profile "Steam Frame Wireless Adapter" and activates it on
//! the dongle every ~60 s. This tool asks the running Steam client to pair over
//! that channel and reads Steam's live configuration, even before the dongle
//! has ever connected. NetworkManager is only needed to set up the Wi-Fi link.

use std::fmt::Write as _;
mod dongle;
mod nm;
mod steam;

use std::borrow::Cow;
use std::io::{BufRead, IsTerminal, Write};
use std::process::Command;
use std::{iter, process};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};

const DEFAULT_PROFILE: &str = "Steam Frame Link (steamframe-link)";

#[derive(Parser)]
#[command(
    version,
    about = "Connect the Steam Frame Wireless Adapter to the headset hotspot"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List Steam Frame Wireless Adapters plugged into this machine.
    Detect,
    /// List the Remote Play clients visible to the running Steam client.
    SteamDevices {
        /// Steam installation directory (auto-detected by default).
        #[arg(long)]
        steam_dir: Option<std::path::PathBuf>,
    },
    /// Fetch and print the hotspot credentials (PSK masked unless --reveal).
    Creds {
        #[command(flatten)]
        src: CredSource,
        #[arg(long)]
        reveal: bool,
    },
    /// Create/update the NetworkManager profile and connect.
    Setup {
        #[command(flatten)]
        src: CredSource,
        #[command(flatten)]
        target: Target,
        /// Use WPA2-PSK instead of WPA3-SAE (SAE + PMF is the default; the
        /// Frame's 6 GHz AP requires it, and it avoids the packet loss seen
        /// with Steam's own wpa-psk profile).
        #[arg(long)]
        wpa2: bool,
        /// Don't autoconnect when the dongle is plugged in.
        #[arg(long)]
        no_autoconnect: bool,
        /// Only write the profile, don't activate it now.
        #[arg(long)]
        no_connect: bool,
    },
    /// Activate the profile on the dongle.
    Up {
        #[command(flatten)]
        target: Target,
    },
    /// Disconnect the dongle.
    Down {
        #[command(flatten)]
        target: Target,
    },
    /// Delete the profile created by this tool.
    Remove {
        #[arg(long, default_value = DEFAULT_PROFILE)]
        name: String,
    },
}

#[derive(Args)]
struct CredSource {
    /// Hotspot SSID (e.g. frame_58F5FA82). Needs --psk or --psk-stdin.
    #[arg(long, requires = "psk_given")]
    ssid: Option<String>,
    /// Hotspot password. Visible in `ps`; prefer --psk-stdin.
    #[arg(long, group = "psk_given", requires = "ssid")]
    psk: Option<String>,
    /// Read the hotspot password from stdin.
    #[arg(long, group = "psk_given", requires = "ssid")]
    psk_stdin: bool,
    /// Pair over Steam Remote Play on the LAN and read Steam's credentials
    /// (the default source). No existing NetworkManager profile is required.
    #[arg(long, conflicts_with_all = ["ssid", "from_ssh", "from_nm"])]
    from_steam: bool,
    /// Copy credentials from Steam's existing NetworkManager profile.
    #[arg(long, conflicts_with_all = ["ssid", "from_ssh"])]
    from_nm: bool,
    /// Read credentials from the headset over SSH (Developer Mode), e.g.
    /// steamos@frame.local or steamos@10.35.78.1.
    #[arg(long, value_name = "USER@HOST", conflicts_with = "ssid")]
    from_ssh: Option<String>,
    /// Remote Play client ID from `steam-devices`; required if several
    /// headsets are available.
    #[arg(long, conflicts_with_all = ["ssid", "from_ssh", "from_nm"])]
    steam_client: Option<u64>,
    /// Steam installation directory (auto-detected by default).
    #[arg(long, conflicts_with_all = ["ssid", "from_ssh", "from_nm"])]
    steam_dir: Option<std::path::PathBuf>,
    /// Seconds to wait for Steam's Wi-Fi pairing response and credentials.
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u64).range(1..=600))]
    timeout: u64,
}

#[derive(Args)]
struct Target {
    /// Dongle interface; auto-detected via USB ID 28de:2432 by default.
    #[arg(long)]
    iface: Option<String>,
    /// NetworkManager profile name.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    name: String,
}

struct Creds {
    ssid: String,
    psk: String,
    origin: String,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Detect => detect(),
        Cmd::SteamDevices { steam_dir } => {
            let steam = steam::Steam::connect(steam_dir.as_deref())?;

            for device in steam.devices()? {
                println!(
                    "{}  {}  LAN={}  wifi-pairing={}",
                    device.id, device.name, device.local, device.can_pair
                );
            }

            Ok(())
        }
        Cmd::Creds { src, reveal } => {
            let c = resolve_creds(&src)?;

            println!("source: {}", c.origin);
            println!("ssid:   {}", c.ssid);
            println!(
                "psk:    {}",
                if reveal {
                    Cow::Borrowed(&c.psk)
                } else {
                    Cow::Owned(mask(&c.psk))
                }
            );

            Ok(())
        }
        Cmd::Setup {
            src,
            target,
            wpa2,
            no_autoconnect,
            no_connect,
        } => {
            let d = pick_dongle(target.iface.as_deref())?;

            let creds = resolve_creds(&src)?;

            let nm = nm::Nm::connect()?;

            let perm = nm.perm_mac(&d.iface).unwrap_or_else(|_| d.mac.clone());

            let mac = dongle::parse_mac(&perm)?;

            let path = nm.upsert_wifi(&nm::WifiProfile {
                name: &target.name,
                mac: &mac,
                ssid: &creds.ssid,
                psk: &creds.psk,
                sae: !wpa2,
                autoconnect: !no_autoconnect,
            })?;

            println!(
                "profile {:?} -> ssid {} on {} ({}), {} (credentials from {})",
                target.name,
                creds.ssid,
                d.iface,
                perm,
                if wpa2 { "WPA2-PSK" } else { "WPA3-SAE" },
                creds.origin
            );

            if !no_connect {
                nm.activate(&path, &d.iface)?;

                println!(
                    "activation started; check with `nmcli device show {}`",
                    d.iface
                );

                println!("headset must be awake with its hotspot up, or this will time out");
            }

            Ok(())
        }
        Cmd::Up { target } => {
            let d = pick_dongle(target.iface.as_deref())?;

            let nm = nm::Nm::connect()?;

            let path = nm
                .find_by_name(&target.name)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("no profile {:?}; run `setup` first", target.name))?;

            nm.activate(&path, &d.iface)?;

            println!("activating {:?} on {}", target.name, d.iface);

            Ok(())
        }
        Cmd::Down { target } => {
            let d = pick_dongle(target.iface.as_deref())?;

            if nm::Nm::connect()?.deactivate_on(&d.iface)? {
                println!("{} disconnected", d.iface);
            } else {
                println!("{} was not connected", d.iface);
            }

            Ok(())
        }
        Cmd::Remove { name } => {
            anyhow::ensure!(
                name != nm::STEAM_PROFILE,
                "refusing to delete Steam's own profile use nmcli if you really want that lol"
            );

            let n = nm::Nm::connect()?.delete(&name)?;

            println!("deleted {n} profile(s) named {name:?}");

            Ok(())
        }
    }
}

fn detect() -> Result<()> {
    let found = dongle::find_all();

    if found.is_empty() {
        bail!(
            "no Steam Frame Wireless Adapter found (USB {}:{} with a wireless netdev). \
             Is it plugged in and is rtw89_8852cu loaded (Linux >= 7.2)?",
            dongle::VALVE_VID,
            dongle::FRAME_DONGLE_PID
        );
    }

    let nm = nm::Nm::connect().ok();

    for d in found {
        let perm = nm.as_ref().and_then(|nm| nm.perm_mac(&d.iface).ok());

        println!(
            "{}  mac {} (current {})  serial {}  driver {}",
            d.iface,
            perm.as_deref().unwrap_or("?"),
            d.mac,
            d.serial.as_deref().unwrap_or("?"),
            d.driver.as_deref().unwrap_or("?")
        );
    }

    Ok(())
}

fn pick_dongle(iface: Option<&str>) -> Result<dongle::Dongle> {
    let found = dongle::find_all();

    match iface {
        Some(i) => found
            .into_iter()
            .find(|d| d.iface == i)
            .ok_or_else(|| anyhow!("{i} is not a Steam Frame Wireless Adapter")),

        None => match found.len() {
            0 => bail!("no Steam Frame Wireless Adapter found; run `detect` for details"),
            1 => Ok(found.into_iter().next().unwrap()),
            _ => bail!("several adapters found; pick one with --iface"),
        },
    }
}

fn resolve_creds(src: &CredSource) -> Result<Creds> {
    if src.from_nm {
        let (ssid, psk) = nm::Nm::connect()?.read_wifi_credentials(nm::STEAM_PROFILE)?;

        return Ok(Creds {
            ssid,
            psk,
            origin: format!("Steam profile {:?}", nm::STEAM_PROFILE),
        });
    }

    if let Some(host) = &src.from_ssh {
        return creds_over_ssh(host);
    }

    if src.ssid.is_none() {
        return steam::Steam::connect(src.steam_dir.as_deref())?.credentials(
            src.steam_client,
            std::time::Duration::from_secs(src.timeout),
        );
    }

    let ssid = src
        .ssid
        .clone()
        .ok_or_else(|| anyhow!("give --ssid/--psk, --from-steam, --from-nm or --from-ssh"))?;

    let psk = match (&src.psk, src.psk_stdin) {
        (Some(p), _) => p.clone(),
        (None, true) => {
            if std::io::stdin().is_terminal() {
                eprint!("hotspot password: ");
            }

            let mut line = String::new();

            std::io::stdin().lock().read_line(&mut line)?;

            line.trim_end_matches(['\r', '\n']).to_string()
        }
        (None, false) => bail!("--ssid needs --psk or --psk-stdin"),
    };

    anyhow::ensure!(!psk.is_empty(), "empty password");

    Ok(Creds {
        ssid,
        psk,
        origin: "command line".into(),
    })
}

/// Runs on the headset. The hotspot lives on `wlanap`; prefer NetworkManager's
/// view of it, fall back to whatever hostapd config is running.
const REMOTE_SCRIPT: &str = r#"
name=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null | awk -F: '$NF=="wlanap"{print $1; exit}')
if [ -n "$name" ]; then
  echo "ssid=$(nmcli -g 802-11-wireless.ssid connection show "$name")"
  echo "psk=$(nmcli -s -g 802-11-wireless-security.psk connection show "$name" 2>/dev/null || sudo -n nmcli -s -g 802-11-wireless-security.psk connection show "$name")"
  exit 0
fi
for f in $(ps -o args= -C hostapd 2>/dev/null | tr ' ' '\n' | grep '\.conf$'); do
  cat "$f" 2>/dev/null || sudo -n cat "$f"
done | grep -E '^(ssid|wpa_passphrase|sae_password)='
"#;

fn creds_over_ssh(host: &str) -> Result<Creds> {
    let out = Command::new("ssh")
        .args(["-o", "ConnectTimeout=10", host, "sh", "-s"])
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(REMOTE_SCRIPT.as_bytes())?;

            child.wait_with_output()
        })
        .context("running ssh")?;

    anyhow::ensure!(
        out.status.success(),
        "ssh to {host} failed ({})",
        out.status
    );

    let (mut ssid, mut psk) = (None, None);

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };

        // nmcli -g escapes ':' and '\' in values.
        let v = v.replace("\\:", ":").replace("\\\\", "\\");

        match k {
            "ssid" if !v.is_empty() => ssid = Some(v),
            "psk" | "wpa_passphrase" | "sae_password" if !v.is_empty() => psk = Some(v),
            _ => {}
        }
    }

    match (ssid, psk) {
        (Some(ssid), Some(psk)) => Ok(Creds {
            ssid,
            psk,
            origin: format!("ssh {host}"),
        }),
        _ => bail!(
            "could not read the hotspot from {host}: is Developer Mode on, the hotspot up \
             (wlanap), and does the user have sudo without a password prompt?"
        ),
    }
}

fn mask(s: &str) -> String {
    let n = s.len();

    if n <= 4 {
        return "*".repeat(n);
    }

    let mut buf = String::with_capacity(n + 8 + (n.ilog10() + 1) as usize);

    buf.extend(s.chars().take(2));

    buf.extend(iter::repeat_n('*', n - 4));

    buf.extend(s.chars().skip(n - 2));

    let _ = write!(buf, "({n} chars)");

    buf
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn credential_sources_and_steam_options_are_unambiguous() {
        Cli::command().debug_assert();
        for args in [
            vec!["link", "creds"],
            vec!["link", "setup", "--from-steam"],
            vec!["link", "creds", "--steam-client", "4804027141443423938"],
            vec!["link", "creds", "--from-nm"],
            vec!["link", "creds", "--from-ssh", "steamos@frame.local"],
            vec!["link", "creds", "--ssid", "frame_TEST", "--psk-stdin"],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");
        }
        for args in [
            vec!["link", "creds", "--from-steam", "--from-nm"],
            vec!["link", "creds", "--from-steam", "--from-ssh", "frame"],
            vec!["link", "creds", "--from-nm", "--steam-client", "42"],
            vec!["link", "creds", "--psk", "orphan-password"],
            vec!["link", "creds", "--ssid", "frame_TEST"],
            vec!["link", "creds", "--timeout", "0"],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }
}
