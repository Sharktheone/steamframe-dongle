//! Provision a Steam Frame over authenticated LAN, then connect any Wi-Fi radio.
mod dongle;
mod lan;
mod nm;

use anyhow::{Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use lan::Credentials;
use std::{
    io::{BufRead, IsTerminal},
    net::IpAddr,
    path::PathBuf,
    time::Duration,
};

const DEFAULT_PROFILE: &str = "Steam Frame Link (steamframe-link)";

#[derive(Parser)]
#[command(
    version,
    about = "Set Steam Frame hotspot credentials over LAN and connect your Wi-Fi radio"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List attached Valve wireless adapters.
    Detect,
    /// Discover Remote Play devices on the LAN (read-only).
    #[command(alias = "steam-devices")]
    Devices {
        #[command(flatten)]
        network: Network,
    },
    /// Set the Frame's hotspot SSID/password over LAN; generates both by default.
    SetCreds {
        #[command(flatten)]
        network: Network,
        #[command(flatten)]
        credentials: Input,
        /// Retry/verify the last saved credentials, including an unconfirmed request.
        #[arg(long, conflicts_with = "ssid")]
        saved: bool,
        /// Display the password (normally masked).
        #[arg(long)]
        reveal: bool,
    },
    /// Connect a radio using saved credentials, or an explicit SSID/password.
    Setup {
        #[command(flatten)]
        network: Network,
        #[command(flatten)]
        credentials: Input,
        #[command(flatten)]
        target: Target,
        /// First set the Frame's hotspot credentials over LAN; generates them if omitted.
        #[arg(long, conflicts_with = "from_nm")]
        provision: bool,
        /// Copy Steam's existing NetworkManager profile instead of saved credentials.
        #[arg(long, conflicts_with = "ssid")]
        from_nm: bool,
        /// Use WPA2 instead of WPA3-SAE (the Frame's 6 GHz AP requires WPA3).
        #[arg(long)]
        wpa2: bool,
        /// Disable automatic connection for this profile.
        #[arg(long)]
        no_autoconnect: bool,
        /// Save the profile without connecting the PC radio.
        #[arg(long)]
        no_connect: bool,
    },
    /// Activate the saved NetworkManager profile on a radio.
    Up {
        #[command(flatten)]
        target: Target,
    },
    /// Disconnect the selected radio.
    Down {
        #[command(flatten)]
        target: Target,
    },
    /// Delete the NetworkManager profile created by this tool.
    Remove {
        #[arg(long, default_value = DEFAULT_PROFILE)]
        name: String,
    },
}

#[derive(Args)]
struct Network {
    /// Remote Play client ID from `devices`; required if several Frames are visible.
    #[arg(long, alias = "steam-client")]
    client: Option<u64>,
    /// Frame LAN IP, for networks that block broadcast discovery.
    #[arg(long)]
    host: Option<IpAddr>,
    /// Steam installation directory (auto-detected).
    #[arg(long)]
    steam_dir: Option<PathBuf>,
    /// Seconds to wait for provisioning confirmation.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
    timeout: u64,
}
impl Network {
    fn discover(&self) -> Result<lan::Lan> {
        lan::Lan::discover(self.steam_dir.as_deref(), self.host)
    }
}

#[derive(Args)]
struct Input {
    /// Hotspot SSID (1–32 bytes); supply --psk-stdin or --psk as well.
    #[arg(long, requires = "password")]
    ssid: Option<String>,
    /// Read the hotspot password from stdin; preferred over --psk.
    #[arg(long, group = "password", requires = "ssid")]
    psk_stdin: bool,
    /// Hotspot password; visible in process arguments and shell history.
    #[arg(long, group = "password", requires = "ssid")]
    psk: Option<String>,
}
impl Input {
    fn read(&self) -> Result<Option<Credentials>> {
        let Some(ssid) = &self.ssid else {
            return Ok(None);
        };
        let psk = if self.psk_stdin {
            if std::io::stdin().is_terminal() {
                eprint!("hotspot password: ");
            }
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        } else {
            self.psk.clone().expect("clap requires a password")
        };
        let creds = Credentials {
            ssid: ssid.clone(),
            psk,
        };
        creds.validate()?;
        Ok(Some(creds))
    }
}

#[derive(Args)]
struct Target {
    /// Any Wi-Fi interface; auto-detect the Valve adapter if omitted.
    #[arg(long)]
    iface: Option<String>,
    /// NetworkManager profile name.
    #[arg(long, default_value = DEFAULT_PROFILE)]
    name: String,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Detect => detect(),
        Cmd::Devices { network } => {
            for d in network.discover()?.devices {
                println!(
                    "{}  {}  {}  Frame={}",
                    d.id,
                    d.name,
                    d.address.ip(),
                    d.frame
                );
            }
            Ok(())
        }
        Cmd::SetCreds {
            network,
            credentials,
            saved,
            reveal,
        } => {
            let input = credentials.read()?;
            let lan = network.discover()?;
            let device = lan.select(network.client)?;
            let creds = if saved {
                lan.load_saved(device, false)?
            } else {
                input.unwrap_or(Credentials::generate()?)
            };
            let path = lan.provision(device, &creds, Duration::from_secs(network.timeout))?;
            println!("Frame confirmed hotspot configuration.");
            println!("ssid: {}", creds.ssid);
            println!(
                "psk:  {}",
                if reveal {
                    creds.psk.as_str()
                } else {
                    "********"
                }
            );
            println!("Saved credentials: {}", path.display());
            println!("Connect a radio with: steamframe-link setup --iface INTERFACE");
            Ok(())
        }
        Cmd::Setup {
            network,
            credentials,
            target,
            provision,
            from_nm,
            wpa2,
            no_autoconnect,
            no_connect,
        } => {
            let adapter = pick_adapter(target.iface.as_deref())?;
            let input = credentials.read()?;
            let creds = if from_nm {
                let (ssid, psk) = nm::Nm::connect()?.read_wifi_credentials(nm::STEAM_PROFILE)?;
                Credentials { ssid, psk }
            } else if provision {
                let lan = network.discover()?;
                let device = lan.select(network.client)?;
                let creds = input.unwrap_or(Credentials::generate()?);
                let path = lan.provision(device, &creds, Duration::from_secs(network.timeout))?;
                println!(
                    "Frame confirmed hotspot configuration; credentials saved in {}",
                    path.display()
                );
                creds
            } else if let Some(creds) = input {
                creds
            } else {
                lan::saved(network.client)?
            };
            creds.validate()?;
            let nm = nm::Nm::connect()?;
            let permanent = nm
                .perm_mac(&adapter.iface)
                .unwrap_or_else(|_| adapter.mac.clone());
            let mac = dongle::parse_mac(&permanent)?;
            let path = nm.upsert_wifi(&nm::WifiProfile {
                name: &target.name,
                mac: &mac,
                ssid: &creds.ssid,
                psk: &creds.psk,
                sae: !wpa2,
                autoconnect: !no_autoconnect,
            })?;
            println!(
                "Profile {:?}: {} on {} ({})",
                target.name,
                creds.ssid,
                adapter.iface,
                if wpa2 { "WPA2-PSK" } else { "WPA3-SAE" }
            );
            if !no_connect {
                nm.activate(&path, &adapter.iface)?;
                println!(
                    "Activation started; check with nmcli device show {}",
                    adapter.iface
                );
            }
            Ok(())
        }
        Cmd::Up { target } => {
            let adapter = pick_adapter(target.iface.as_deref())?;
            let nm = nm::Nm::connect()?;
            let path = nm
                .find_by_name(&target.name)?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("no profile {:?}; run setup first", target.name))?;
            nm.activate(&path, &adapter.iface)?;
            println!("Activating {:?} on {}", target.name, adapter.iface);
            Ok(())
        }
        Cmd::Down { target } => {
            let adapter = pick_adapter(target.iface.as_deref())?;
            let changed = nm::Nm::connect()?.deactivate_on(&adapter.iface)?;
            println!(
                "{} {}",
                adapter.iface,
                if changed {
                    "disconnected"
                } else {
                    "was not connected"
                }
            );
            Ok(())
        }
        Cmd::Remove { name } => {
            ensure!(
                name != nm::STEAM_PROFILE,
                "refusing to delete Steam's own profile"
            );
            let count = nm::Nm::connect()?.delete(&name)?;
            println!("Deleted {count} profile(s) named {name:?}");
            Ok(())
        }
    }
}

fn pick_adapter(iface: Option<&str>) -> Result<dongle::Dongle> {
    if let Some(iface) = iface {
        return dongle::by_iface(iface);
    }
    let mut found = dongle::find_all();
    match found.len() {
        0 => bail!("no Valve adapter found; select your Wi-Fi radio with --iface INTERFACE"),
        1 => Ok(found.remove(0)),
        _ => bail!("several adapters found; select one with --iface"),
    }
}
fn detect() -> Result<()> {
    let found = dongle::find_all();
    ensure!(
        !found.is_empty(),
        "no Valve adapter attached; ordinary radios can be selected with --iface"
    );
    for d in found {
        println!(
            "{}  mac={}  driver={}  serial={}",
            d.iface,
            d.mac,
            d.driver.as_deref().unwrap_or("?"),
            d.serial.as_deref().unwrap_or("?")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn provisioning_is_explicit_and_password_inputs_are_unambiguous() {
        Cli::command().debug_assert();
        for args in [
            vec!["link", "set-creds"],
            vec!["link", "set-creds", "--saved"],
            vec!["link", "set-creds", "--ssid", "frame_TEST", "--psk-stdin"],
            vec!["link", "setup", "--iface", "wlan0"],
            vec!["link", "setup", "--provision", "--no-connect"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        for args in [
            vec!["link", "creds"],
            vec!["link", "set-creds", "--ssid", "name"],
            vec!["link", "set-creds", "--psk", "orphan"],
            vec![
                "link",
                "set-creds",
                "--saved",
                "--ssid",
                "name",
                "--psk-stdin",
            ],
            vec!["link", "setup", "--provision", "--from-nm"],
            vec!["link", "set-creds", "--timeout", "0"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }
}
