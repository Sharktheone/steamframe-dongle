//! Inspect the same on-disk library selected by Client::connect without loading
//! native code or requiring a running Steam client.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::library;

pub struct LibraryInfo {
    selected: PathBuf,
    resolved: PathBuf,
    size: usize,
    sha256: String,
    build: Option<String>,
    build_id: Option<String>,
    client_version: Option<String>,
    manifest: PathBuf,
}

impl LibraryInfo {
    pub fn read(directory: Option<&Path>) -> Result<Self> {
        let selected = library::find(directory)?;

        let resolved = fs::canonicalize(&selected)
            .with_context(|| format!("resolving {}", selected.display()))?;

        // The manifest belongs to the selected installation, even if its library
        // is a symlink to a file outside that installation.
        let manifest = selected
            .parent()
            .and_then(Path::parent)
            .context("Steam library has no installation directory")?
            .join("package/steam_client_ubuntu12.manifest");

        let bytes =
            fs::read(&resolved).with_context(|| format!("reading {}", resolved.display()))?;

        library::validate_elf(&bytes)?;

        Ok(Self {
            selected,
            resolved,
            size: bytes.len(),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            build: embedded_build(&bytes).map(str::to_owned),
            build_id: elf_build_id(&bytes),
            client_version: fs::read_to_string(&manifest)
                .ok()
                .and_then(|text| manifest_version(&text).map(str::to_owned)),
            manifest,
        })
    }
}

impl fmt::Display for LibraryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Steam library selected for IPC (on disk):")?;

        writeln!(f, "  selected path:  {}", self.selected.display())?;

        writeln!(f, "  resolved path:  {}", self.resolved.display())?;

        writeln!(
            f,
            "  format:         ELF64, little-endian, x86_64 shared object"
        )?;

        writeln!(f, "  size:           {} bytes", self.size)?;

        writeln!(f, "  SHA-256:        {}", self.sha256)?;

        writeln!(
            f,
            "  GNU build ID:   {}",
            self.build_id.as_deref().unwrap_or("unavailable")
        )?;

        writeln!(
            f,
            "  library build:  {}",
            self.build.as_deref().unwrap_or("unavailable")
        )?;

        writeln!(
            f,
            "  client version: {} (installed manifest)",
            self.client_version.as_deref().unwrap_or("unavailable")
        )?;

        write!(f, "  manifest:       {}", self.manifest.display())
    }
}


const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn embedded_build(bytes: &[u8]) -> Option<&str> {
    bytes.split(|&b| b == 0).find_map(|entry| {
        let text = std::str::from_utf8(entry).ok()?;

        let stamp = text.strip_prefix("steam ")?;

        // __DATE__ and __TIME__, e.g. "Sep  3 2026 01:31:45". Do not
        // mistake an arbitrary Steam message for the embedded build string.
        if stamp.len() != 20 || !stamp.is_ascii() {
            return None;
        }

        if !MONTHS.contains(&&stamp[..3]) {
            return None;
        }

        let valid = stamp.as_bytes().iter().enumerate().all(|(i, b)| match i {
            0..=2 => b.is_ascii_alphabetic(),
            3 | 6 | 11 => *b == b' ',
            4 => *b == b' ' || b.is_ascii_digit(),
            14 | 17 => *b == b':',
            _ => b.is_ascii_digit(),
        });

        valid.then_some(text)
    })
}

fn manifest_version(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("\"version\"")?.trim();

        let value = rest.strip_prefix('"')?.strip_suffix('"')?;

        (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())).then_some(value)
    })
}

/// Read a GNU build ID from ELF64 little-endian PT_NOTE entries. All ranges
/// remain checked even though the library's loadable segments were validated.
fn elf_build_id(bytes: &[u8]) -> Option<String> {
    fn number(bytes: &[u8], offset: usize, size: usize) -> Option<usize> {
        let data = bytes.get(offset..offset.checked_add(size)?)?;

        let mut value = [0; 8];

        value.get_mut(..size)?.copy_from_slice(data);

        usize::try_from(u64::from_le_bytes(value)).ok()
    }

    fn align4(value: usize) -> Option<usize> {
        Some(value.checked_add(3)? & !3)
    }

    let table = number(bytes, 32, 8)?;

    let entry_size = number(bytes, 54, 2)?;

    let count = number(bytes, 56, 2)?;

    if entry_size < 56 || count > 1024 {
        return None;
    }

    for index in 0..count {
        let offset = table.checked_add(index.checked_mul(entry_size)?)?;

        let header = bytes.get(offset..offset.checked_add(56)?)?;

        if number(header, 0, 4)? != 4 {
            continue;
        }

        let start = number(header, 8, 8)?;

        let size = number(header, 32, 8)?;

        let notes = bytes.get(start..start.checked_add(size)?)?;

        let mut cursor: usize = 0;

        while cursor < notes.len() {
            let header = notes.get(cursor..cursor.checked_add(12)?)?;

            let name_size = number(header, 0, 4)?;

            let desc_size = number(header, 4, 4)?;

            let kind = number(header, 8, 4)?;

            let name_start = cursor.checked_add(12)?;

            let desc_start = name_start.checked_add(align4(name_size)?)?;

            let name = notes.get(name_start..name_start.checked_add(name_size)?)?;

            let desc = notes.get(desc_start..desc_start.checked_add(desc_size)?)?;

            if kind == 3 && name == b"GNU\0" && !desc.is_empty() {
                return Some(desc.iter().map(|b| format!("{b:02x}")).collect());
            }

            cursor = desc_start.checked_add(align4(desc_size)?)?;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_marker_is_optional_and_must_look_like_a_build() {
        assert_eq!(
            embedded_build(b"noise\0steam Sep  3 2026 01:31:45\0tail"),
            Some("steam Sep  3 2026 01:31:45")
        );
        assert_eq!(
            embedded_build(b"steam Oct 20 2026 23:59:59\0"),
            Some("steam Oct 20 2026 23:59:59")
        );
        assert_eq!(embedded_build(b"steam connection failed\0"), None);
        assert_eq!(embedded_build(b"steam Sep  3 2026 xx:31:45\0"), None);
        assert_eq!(embedded_build(b"\xff\0other\0"), None);
        assert_eq!(
            embedded_build("steam éé 3 2026 01:31:45\0".as_bytes()),
            None
        );
    }

    #[test]
    fn installed_manifest_version_accepts_whitespace_but_not_other_keys() {
        assert_eq!(
            manifest_version("\"ubuntu12\"\n{\n\t\"version\"\t\t\"1788652215\"\n}"),
            Some("1788652215")
        );
        assert_eq!(
            manifest_version("\"file\" \"123\"\n\"version\" \"abc\""),
            None
        );
        assert_eq!(manifest_version("\"version\" \"\""), None);
    }

    #[test]
    fn build_id_uses_note_type_owner_and_checked_ranges() {
        // One ELF64 program header, followed by a padded unrelated note and
        // a GNU build ID note. PT_NOTE parsing needs no section headers.
        let mut bytes = vec![0u8; 160];
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&4u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&120u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&40u64.to_le_bytes());
        bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
        bytes[124..128].copy_from_slice(&1u32.to_le_bytes());
        bytes[132] = b'x';
        bytes[140..144].copy_from_slice(&4u32.to_le_bytes());
        bytes[144..148].copy_from_slice(&4u32.to_le_bytes());
        bytes[148..152].copy_from_slice(&3u32.to_le_bytes());
        bytes[152..156].copy_from_slice(b"GNU\0");
        bytes[156..160].copy_from_slice(&[0, 0xab, 0xcd, 0xef]);
        assert_eq!(elf_build_id(&bytes).as_deref(), Some("00abcdef"));
        for end in 0..bytes.len() {
            assert_eq!(elf_build_id(&bytes[..end]), None);
        }
        bytes[152] = b'X';
        assert_eq!(elf_build_id(&bytes), None);
        bytes[152] = b'G';
        bytes[144..148].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(elf_build_id(&bytes), None);
        bytes[72..80].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(elf_build_id(&bytes), None);
    }
}
