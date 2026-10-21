//! Read Steam's persisted identity and pairing keys, without loading its code.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

#[derive(Debug)]
enum Node {
    Text(String),
    Object(Vec<(String, Node)>),
}

impl Node {
    fn at(&self, path: &[&str]) -> Option<&Node> {
        if path.is_empty() {
            return Some(self);
        }

        let Self::Object(entries) = self else {
            return None;
        };

        let (_, value) = entries
            .iter()
            .rev()
            .find(|(key, _)| key.eq_ignore_ascii_case(path[0]))?;

        value.at(&path[1..])
    }

    fn text(&self, path: &[&str]) -> Option<&str> {
        match self.at(path)? {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
}

enum Token {
    Open,
    Close,
    Text(String),
}

impl Parser<'_> {
    fn token(&mut self) -> Result<Option<Token>> {
        loop {
            while self.pos < self.data.len() && self.data[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }

            if self.data.get(self.pos..self.pos + 2) == Some(b"//") {
                while self.pos < self.data.len() && self.data[self.pos] != b'\n' {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }

        let Some(&c) = self.data.get(self.pos) else {
            return Ok(None);
        };

        self.pos += 1;

        if c == b'{' {
            return Ok(Some(Token::Open));
        }

        if c == b'}' {
            return Ok(Some(Token::Close));
        }

        ensure!(c == b'"', "expected quoted VDF token");

        let mut out = Vec::new();

        while let Some(&c) = self.data.get(self.pos) {
            self.pos += 1;

            if c == b'"' {
                return Ok(Some(Token::Text(String::from_utf8(out)?)));
            }

            if c == b'\\' {
                let c = *self.data.get(self.pos).context("truncated VDF escape")?;

                self.pos += 1;

                out.push(match c {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'r' => b'\r',
                    _ => c,
                });
            } else {
                out.push(c);
            }
        }

        bail!("unterminated VDF string")
    }

    fn object(&mut self, nested: bool, depth: usize) -> Result<Node> {
        ensure!(depth < 64, "VDF nesting limit exceeded");

        let mut entries = Vec::new();

        while let Some(token) = self.token()? {
            let key = match token {
                Token::Close => {
                    ensure!(nested, "unexpected VDF brace");

                    return Ok(Node::Object(entries));
                }
                Token::Text(key) => key,
                Token::Open => bail!("missing VDF key"),
            };

            let node = match self.token()?.context("missing VDF value")? {
                Token::Open => self.object(true, depth + 1)?,
                Token::Text(text) => Node::Text(text),
                Token::Close => bail!("missing VDF value"),
            };

            entries.push((key, node));
        }

        ensure!(!nested, "unterminated VDF object");

        Ok(Node::Object(entries))
    }
}

fn parse(data: &[u8]) -> Result<Node> {
    Parser { data, pos: 0 }.object(false, 0)
}

pub fn root(directory: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = directory {
        ensure!(
            p.join("config/config.vdf").is_file(),
            "no Steam config/config.vdf in {}",
            p.display()
        );

        return Ok(p.to_owned());
    }

    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is unset; use --steam-dir")?);

    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"));

    [
        home.join(".steam/steam"),
        home.join(".steam/root"),
        data.join("Steam"),
        home.join(".var/app/com.valvesoftware.Steam/data/Steam"),
    ]
    .into_iter()
    .find(|r| r.join("config/config.vdf").is_file())
    .context("Steam installation not found; use --steam-dir")
}

pub fn client_id(root: &Path) -> Result<u64> {
    let doc = parse(&fs::read(root.join("config/config.vdf"))?)?;

    let text = doc
        .text(&["InstallConfigStore", "streaming", "ClientID"])
        .context("Steam has no Remote Play client ID")?;

    let id = parse_client_id(text)?;

    ensure!(id != 0, "Steam Remote Play client ID is zero");

    Ok(id)
}

fn parse_client_id(text: &str) -> Result<u64> {
    // Steam persists uint64 IDs through its signed int64 VDF accessor.
    if text.starts_with('-') {
        Ok(text.parse::<i64>()? as u64)
    } else {
        Ok(text.parse()?)
    }
}

pub struct Auth {
    pub shared: Vec<u8>,
    pub paired: Vec<u8>,
}

pub fn authentication(root: &Path, users: &[(u64, u64)], peer: u64) -> Result<Auth> {
    let peer_key = hex(&peer.to_le_bytes());

    let mut matches = Vec::new();

    for entry in fs::read_dir(root.join("userdata"))? {
        let entry = entry?;

        let Some(account) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };

        let steam_id = 76561197960265728 + u64::from(account);

        if !users.iter().any(|(id, _)| *id == steam_id) {
            continue;
        }

        let path = entry.path().join("config/localconfig.vdf");

        if !path.is_file() {
            continue;
        }

        let doc = parse(&fs::read(path)?)?;

        let base = doc
            .at(&["UserLocalConfigStore"])
            .context("missing user config root")?;

        let auth_id = base
            .text(&["SharedAuth", "id"])
            .and_then(|s| s.parse().ok());

        if !users
            .iter()
            .any(|&(id, key)| id == steam_id && Some(key) == auth_id)
        {
            continue;
        }

        let Some(shared) = base.text(&["SharedAuth", "AuthData"]) else {
            continue;
        };

        let Some(paired) = base.text(&["streaming", "Clients", &peer_key, "Key"]) else {
            continue;
        };

        matches.push(Auth {
            shared: key(shared)?,
            paired: key(paired)?,
        });
    }

    ensure!(
        matches.len() == 1,
        "no unique active Steam account with a saved Frame pairing key; pair this PC and Frame in Steam first"
    );

    Ok(matches.remove(0))
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn key(s: &str) -> Result<Vec<u8>> {
    ensure!(s.len() == 64 && s.is_ascii(), "invalid Steam key encoding");

    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid Steam key encoding"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vdf_paths_comments_escapes_and_bad_nesting() {
        let doc = parse(
            br#"// comment
        "Root" { "Key" "old" "key" "a\"b\\c" "Child" { "Value" "x" "Brace" "}" } }"#,
        )
        .unwrap();

        assert_eq!(doc.text(&["ROOT", "key"]), Some("a\"b\\c"));

        assert_eq!(doc.text(&["root", "child", "value"]), Some("x"));

        assert_eq!(doc.text(&["root", "child", "brace"]), Some("}"));

        for bad in [
            b"\"x\" {".as_slice(),
            b"}",
            b"\"x\"",
            b"\"x\" \"unterminated",
        ] {
            assert!(parse(bad).is_err());
        }
    }

    #[test]
    fn steam_client_ids_preserve_signed_vdf_bits() {
        assert_eq!(
            parse_client_id("-5235487125261387261").unwrap(),
            13211256948448164355
        );

        assert_eq!(
            parse_client_id("13211256948448164355").unwrap(),
            13211256948448164355
        );

        assert!(parse_client_id("-18446744073709551615").is_err());
    }

    #[test]
    fn authentication_uses_active_account_and_auth_id_and_requires_pairing() {
        let root = std::env::temp_dir().join(format!(
            "steamframe-auth-test-{}",
            super::super::random_id().unwrap()
        ));

        let peer = 0x42ab553b79120ec2;

        for account in [1, 2] {
            let dir = root.join(format!("userdata/{account}/config"));

            fs::create_dir_all(&dir).unwrap();

            let shared = if account == 1 {
                "11".repeat(32)
            } else {
                "22".repeat(32)
            };

            let paired = if account == 1 {
                "33".repeat(32)
            } else {
                "44".repeat(32)
            };

            let contents = format!(
                r#"
                "UserLocalConfigStore" {{
                    "SharedAuth" {{
                        "id" "{account}"
                        "AuthData" "{shared}"
                    }}
                    "streaming" {{
                        "Clients" {{
                            "c20e12793b55ab42" {{ "Key" "{paired}" }}
                        }}
                    }}
                }}
                "#
            );

            fs::write(dir.join("localconfig.vdf"), contents).unwrap();
        }

        let active = [(76561197960265730, 2)];

        let auth = authentication(&root, &active, peer).unwrap();

        assert_eq!(auth.shared, vec![0x22; 32]);

        assert_eq!(auth.paired, vec![0x44; 32]);

        assert!(authentication(&root, &[(76561197960265730, 1)], peer).is_err());

        assert!(authentication(&root, &active, peer + 1).is_err());

        assert!(authentication(&root, &[], peer).is_err());

        fs::remove_dir_all(root).unwrap();
    }
}
