//! Loading steamclient.so and resolving its exported symbols and interface
//! methods. Names locate IPC methods; typed code signatures check every
//! function before it can be called.

use std::ffi::{CStr, c_void};
use std::fs;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use libloading::os::unix;
use sha2::{Digest, Sha256};

pub(super) type Object = *mut c_void;

/// A reviewed function body and the Rust ABI used to call it. A matching name
/// or pointer size alone says nothing about the arguments a function expects.
pub(super) struct Signature<T> {
    name: &'static CStr,
    size: usize,
    sha256: [u8; 32],
    function: PhantomData<T>,
}

impl<T> Signature<T> {
    pub(super) const fn new(name: &'static CStr, size: usize, sha256: [u8; 32]) -> Self {
        Self {
            name,
            size,
            sha256,
            function: PhantomData,
        }
    }

    fn check(&self, code: &[u8]) -> Result<()> {
        ensure!(
            code.len() == self.size && Sha256::digest(code)[..] == self.sha256,
            "unsupported Steam signature for {}; Steam's private interfaces have changed",
            self.name.to_string_lossy()
        );

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct Segment {
    address: usize,
    offset: usize,
    size: usize,
    flags: u32,
}

pub(super) fn find(directory: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = directory {
        let path = dir.join("linux64/steamclient.so");

        ensure!(
            path.is_file(),
            "no linux64/steamclient.so in {}",
            dir.display()
        );

        return Ok(path);
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is unset; use --steam-dir")?;

    let mut roots = vec![home.join(".steam/steam"), home.join(".steam/root")];

    roots.push(
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("Steam"),
    );

    roots.push(home.join(".var/app/com.valvesoftware.Steam/data/Steam"));

    roots
        .into_iter()
        .map(|r| r.join("linux64/steamclient.so"))
        .find(|p| p.is_file())
        .context("Steam installation not found; use --steam-dir PATH")
}

pub(super) struct Library {
    handle: unix::Library,
    base: usize,
    bytes: Vec<u8>,
    segments: Vec<Segment>,
}

impl Library {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;

        let segments = elf_segments(&bytes)?;

        // SAFETY: Loading runs Steam's initializers, as Steam itself does.
        // NODELETE keeps its code mapped if its worker threads outlive the
        // final library reference.
        let handle = unsafe {
            unix::Library::open(
                Some(path),
                unix::RTLD_NOW | unix::RTLD_LOCAL | libc::RTLD_NODELETE,
            )
        }
        .with_context(|| format!("loading {} failed", path.display()))?;

        let mut library = Self {
            handle,
            base: 0,
            bytes,
            segments,
        };

        // SAFETY: dladdr only inspects the loader's mapping of this address.
        unsafe {
            // This address is only used to find the mapping, never called.
            let factory = library
                .handle
                .get::<*mut c_void>(c"CreateInterface")?
                .into_raw();

            let mut info: libc::Dl_info = std::mem::zeroed();

            ensure!(
                libc::dladdr(factory, &mut info) != 0,
                "cannot locate Steam's library mapping"
            );

            library.base = info.dli_fbase as usize;
        }

        Ok(library)
    }

    /// A library that resolves nothing, for tests with fake interfaces.
    #[cfg(test)]
    pub(super) fn empty() -> Self {
        Self {
            handle: unix::Library::this(),
            base: 0,
            bytes: vec![],
            segments: vec![],
        }
    }

    pub(super) unsafe fn symbol<T: Copy>(&self, signature: &Signature<T>) -> Result<T> {
        let symbol = unsafe { self.handle.get::<*mut c_void>(signature.name) }
            .with_context(|| format!("Steam is missing {}", signature.name.to_string_lossy()))?
            .into_raw();

        unsafe { self.function(symbol as usize, signature) }
    }

    /// An engine method by slot, checked against its reviewed function body.
    pub(super) unsafe fn engine_method<T: Copy>(
        &self,
        object: Object,
        slot: usize,
        signature: &Signature<T>,
    ) -> Result<T> {
        let address = unsafe { self.vtable(object) }?
            .get(slot)
            .copied()
            .context("unsupported Steam interface layout")?;

        unsafe { self.function(address, signature) }
    }

    /// An IPC proxy method found by its interface and method name. `slot` is
    /// where the method is expected; Steam seems to insert methods between releases,
    /// so the rest of the vtable is searched when that slot no longer matches.
    pub(super) unsafe fn method<T: Copy>(
        &self,
        object: Object,
        interface: &str,
        slot: usize,
        signature: &Signature<T>,
    ) -> Result<T> {
        let table = unsafe { self.vtable(object) }?;
        let method = signature.name.to_str()?;

        let matches = table
            .iter()
            .enumerate()
            .filter(|&(_, &address)| self.proxy_names(address) == (Some(interface), Some(method)))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();

        // Overloads share a name, so only an unambiguous match may move.
        let slot = match matches.as_slice() {
            _ if matches.contains(&slot) => slot,
            [moved] => *moved,
            [] => {
                bail!("Steam has no {interface}::{method}; Steam's private interfaces have changed")
            }
            _ => bail!(
                "Steam has several {interface}::{method} overloads and none at slot {slot}; Steam's private interfaces have changed"
            ),
        };

        unsafe { self.function(table[slot], signature) }
    }

    /// Check both the file and the actual code we'll call. This also rejects
    /// symbols resolved from dependencies and a different already-loaded build.
    unsafe fn function<T: Copy>(&self, address: usize, signature: &Signature<T>) -> Result<T> {
        ensure!(
            size_of::<T>() == size_of::<usize>(),
            "invalid function pointer size"
        );

        let code = self
            .code(address, signature.size)
            .with_context(|| format!("resolving Steam {}", signature.name.to_string_lossy()))?;

        signature.check(code)?;

        // SAFETY: The range is inside the readable executable mapping loaded
        // from this file. Code has no runtime relocations in supported builds.
        let loaded = unsafe { std::slice::from_raw_parts(address as *const u8, code.len()) };

        ensure!(
            loaded == code,
            "Steam's loaded {} differs from its file",
            signature.name.to_string_lossy()
        );

        // SAFETY: The typed signature binds T to the reviewed ABI, and the
        // complete loaded function body matches that signature.
        Ok(unsafe { std::mem::transmute_copy(&address) })
    }

    fn code(&self, address: usize, size: usize) -> Result<&[u8]> {
        let offset = self
            .file_offset(address, size, libc::PF_R | libc::PF_X)
            .context("unmapped Steam code")?;

        Ok(&self.bytes[offset..offset + size])
    }

    /// The vtable entries of `object`, up to the first one outside Steam's
    /// library. C++ vtables store no length, but the next table starts with
    /// its offset-to-top, which is never an address inside the library.
    /// This is btw some of the worst code I have ever written. I mean who cares about pointer provanance. It comes all from C anyway lol :/
    unsafe fn vtable(&self, object: Object) -> Result<Vec<usize>> {
        ensure!(!object.is_null(), "null Steam interface");
        ensure!(
            (object as usize).is_multiple_of(align_of::<usize>()),
            "unaligned Steam interface"
        );

        let table = unsafe { *object.cast::<*const usize>() };
        ensure!(
            (table as usize).is_multiple_of(align_of::<usize>()),
            "unaligned Steam vtable"
        );

        let mut entries = Vec::new();

        for slot in 0..1024 {
            let entry = (table as usize)
                .checked_add(slot * size_of::<usize>())
                .context("Steam vtable overflow")?;

            ensure!(
                self.file_offset(entry, size_of::<usize>(), libc::PF_R)
                    .is_some(),
                "unmapped Steam vtable"
            );

            // SAFETY: This complete, aligned entry is in Steam's readable mapping.
            let address = unsafe { *(entry as *const usize) };

            if self
                .file_offset(address, 1, libc::PF_R | libc::PF_X)
                .is_none()
            {
                break;
            }

            entries.push(address);
        }

        ensure!(!entries.is_empty(), "unsupported Steam interface layout");

        Ok(entries)
    }

    fn file_offset(&self, address: usize, size: usize, flags: u32) -> Option<usize> {
        let vaddr = address.checked_sub(self.base)?;

        self.segments.iter().find_map(|segment| {
            let delta = vaddr.checked_sub(segment.address)?;
            (segment.flags & flags == flags && delta.checked_add(size)? <= segment.size)
                .then(|| segment.offset + delta)
        })
    }

    /// The interface and method name an IPC proxy passes to Steam.
    /// Yeah, this just reads some of steams code to find out if we are reading the correct method - i am very sorry -_-
    fn proxy_names(&self, address: usize) -> (Option<&str>, Option<&str>) {
        let Ok(code) = self.code(address, 512) else {
            return (None, None);
        };

        let mut interface = None;
        let mut method = None;

        // x86_64 Steam IPC proxies load their interface name into RCX and their
        // method name into R8 using RIP-relative LEA. Take the first such
        // string loads, so a shifted slot cannot match a neighboring method.
        for (index, instruction) in code.windows(7).enumerate() {
            let name = match instruction[..3] {
                [0x48, 0x8d, 0x0d] if interface.is_none() => &mut interface,
                [0x4c, 0x8d, 0x05] if method.is_none() => &mut method,
                _ => continue,
            };

            let displacement = i32::from_le_bytes([
                instruction[3],
                instruction[4],
                instruction[5],
                instruction[6],
            ]);

            let target = (address + index + 7).wrapping_add_signed(displacement as isize);

            // clippy wants this from me, I am really not sure if this is the way to go? :/
            if let Some(offset) = self.file_offset(target, 128, libc::PF_R)
                && let Some(end) = self.bytes[offset..offset + 128]
                    .iter()
                    .position(|&b| b == 0)
                && let Ok(text) = std::str::from_utf8(&self.bytes[offset..offset + end])
                && !text.is_empty()
                && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                *name = Some(text);
            }
        }

        (interface, method)
    }
}

pub(super) fn validate_elf(bytes: &[u8]) -> Result<()> {
    elf_segments(bytes).map(|_| ())
}

fn elf_segments(bytes: &[u8]) -> Result<Vec<Segment>> {
    ensure!(
        bytes.get(..6) == Some(b"\x7fELF\x02\x01"),
        "Steam library must be a 64-bit little-endian ELF"
    );

    let number = |offset: usize, len: usize| -> Result<usize> {
        let data = bytes
            .get(offset..offset.checked_add(len).context("ELF offset overflow")?)
            .context("truncated Steam ELF header")?;

        let mut value = [0u8; 8];

        value[..len].copy_from_slice(data);

        Ok(u64::from_le_bytes(value).try_into()?)
    };

    ensure!(
        number(16, 2)? == 3 && number(18, 2)? == 62,
        "Steam library must be an x86_64 shared object"
    );

    let table = number(32, 8)?;

    let entry_size = number(54, 2)?;

    let count = number(56, 2)?;

    ensure!(
        entry_size >= 56 && count <= 1024,
        "invalid Steam ELF program headers"
    );

    let mut segments = Vec::new();

    for index in 0..count {
        let header = table
            .checked_add(
                index
                    .checked_mul(entry_size)
                    .context("ELF offset overflow")?,
            )
            .context("ELF offset overflow")?;
        ensure!(
            header <= bytes.len().saturating_sub(56),
            "truncated Steam ELF program header"
        );
        if number(header, 4)? == 1 {
            let offset = number(header + 8, 8)?;
            let address = number(header + 16, 8)?;
            let size = number(header + 32, 8)?;
            let memory_size = number(header + 40, 8)?;
            ensure!(
                offset
                    .checked_add(size)
                    .is_some_and(|end| end <= bytes.len()),
                "truncated Steam ELF segment"
            );
            ensure!(
                size <= memory_size && address.checked_add(memory_size).is_some(),
                "invalid Steam ELF segment range"
            );

            segments.push(Segment {
                address,
                offset,
                size,
                flags: number(header + 4, 4)? as u32,
            });
        }
    }
    ensure!(!segments.is_empty(), "Steam ELF has no loadable segments");
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Method = unsafe extern "C" fn(Object) -> i32;

    fn mapped(bytes: &[u8]) -> Library {
        Library {
            bytes: bytes.to_vec(),
            segments: vec![Segment {
                address: bytes.as_ptr() as usize,
                offset: 0,
                size: bytes.len(),
                flags: 5,
            }],
            ..Library::empty()
        }
    }

    fn map_table(library: &mut Library, table: &[usize]) {
        library.segments.push(Segment {
            address: table.as_ptr() as usize,
            offset: library.bytes.len(),
            size: size_of_val(table),
            flags: 4,
        });

        for entry in table {
            library.bytes.extend_from_slice(&entry.to_ne_bytes());
        }
    }

    #[test]
    fn signatures_reject_changed_bodies_and_loaded_code() {
        let mut code = [0x90; 64];
        let signature = Signature::<Method>::new(c"test", code.len(), Sha256::digest(code).into());
        let address = code.as_ptr() as usize;
        let mut library = mapped(&code);

        // Resolve pointers without executing these synthetic code bytes.
        assert!(unsafe { library.function(address, &signature) }.is_ok());

        code[63] = 0xc3;
        let error = unsafe { library.function(address, &signature) }.unwrap_err();
        assert!(error.to_string().contains("loaded test differs"));

        library.bytes[63] = code[63];
        let error = unsafe { library.function(address, &signature) }.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported Steam signature for test")
        );
        assert!(signature.check(&code[..63]).is_err());
    }

    #[test]
    fn code_must_fit_in_one_readable_executable_segment() {
        let code = [0x90; 64];
        let address = code.as_ptr() as usize;
        let mut library = mapped(&code);

        assert!(library.code(address, 64).is_ok());
        assert!(library.code(address + 1, 64).is_err());
        assert!(library.code(address - 1, 1).is_err());
        assert!(library.code(address, usize::MAX).is_err());

        for flags in [0, 1, 4, 6] {
            library.segments[0].flags = flags;
            assert!(library.code(address, 1).is_err());
        }
    }

    #[test]
    fn engine_slots_cannot_resolve_a_different_function() {
        let mut code = [0x90; 64];
        code[32] = 0xc3;
        let signature = Signature::<Method>::new(c"test", 32, Sha256::digest(&code[..32]).into());
        let address = code.as_ptr() as usize;
        let mut library = mapped(&code);
        let table = [address, address + 32, 0];
        map_table(&mut library, &table);
        let mut object = table.as_ptr();
        let object = (&mut object as *mut *const usize).cast();

        assert!(unsafe { library.engine_method(object, 0, &signature) }.is_ok());
        assert!(unsafe { library.engine_method(object, 1, &signature) }.is_err());
        assert!(unsafe { library.engine_method(object, 2, &signature) }.is_err());
        assert!(unsafe { library.engine_method(std::ptr::null_mut(), 0, &signature) }.is_err());

        let mut bad_table = std::ptr::null::<usize>();
        let bad_object = (&mut bad_table as *mut *const usize).cast();
        assert!(unsafe { library.engine_method(bad_object, 0, &signature) }.is_err());
    }

    #[test]
    fn moved_proxy_names_still_require_a_matching_signature() {
        let mut code = vec![0u8; 1024];
        code[..3].copy_from_slice(&[0x48, 0x8d, 0x0d]);
        code[3..7].copy_from_slice(&505i32.to_le_bytes());
        code[7..10].copy_from_slice(&[0x4c, 0x8d, 0x05]);
        code[10..14].copy_from_slice(&626i32.to_le_bytes());
        code[14] = 0xc3;
        code[512..531].copy_from_slice(b"IClientConfigStore\0");
        code[640..650].copy_from_slice(b"GetString\0");

        let signature =
            Signature::<Method>::new(c"GetString", 15, Sha256::digest(&code[..15]).into());
        let address = code.as_ptr() as usize;
        let mut library = mapped(&code);
        let table = [address, address + 256, 0];
        map_table(&mut library, &table);
        let mut object = table.as_ptr();
        let object = (&mut object as *mut *const usize).cast();

        assert!(unsafe { library.method(object, "IClientConfigStore", 1, &signature) }.is_ok());
        assert!(unsafe { library.method(object, "AnotherInterface", 1, &signature) }.is_err());

        code[14] = 0x90;
        library.bytes[14] = code[14];
        let error =
            unsafe { library.method(object, "IClientConfigStore", 1, &signature) }.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported Steam signature for GetString")
        );
    }

    #[test]
    fn exported_symbols_from_other_libraries_are_rejected() {
        let signature =
            Signature::<unsafe extern "C" fn(usize) -> Object>::new(c"malloc", 1, [0; 32]);
        let error = unsafe { Library::empty().symbol(&signature) }.unwrap_err();
        assert!(format!("{error:#}").contains("unmapped Steam code"));
    }

    #[test]
    fn malformed_libraries_fail_before_loading_native_code() {
        for bytes in [&b""[..], &b"not an ELF"[..], &b"\x7fELF\x02\x01"[..]] {
            assert!(elf_segments(bytes).is_err());
        }
        let mut elf = vec![0u8; 120];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[16] = 3; // ET_DYN
        elf[18] = 62;
        elf[32] = 64; // program header offset
        elf[54] = 56; // program header size
        elf[56] = 1; // one header
        elf[64] = 1; // PT_LOAD
        elf[72] = 120; // file offset
        elf[96] = 1; // one byte beyond EOF
        elf[104] = 1; // memory size
        assert!(elf_segments(&elf).is_err());
        elf.push(0);
        assert_eq!(
            elf_segments(&elf).unwrap(),
            vec![Segment {
                address: 0,
                offset: 120,
                size: 1,
                flags: 0,
            }]
        );

        elf[104] = 0; // file size exceeds memory size
        assert!(elf_segments(&elf).is_err());
        elf[104] = 1;
        elf[80..88].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(elf_segments(&elf).is_err());
    }
}
