//! Safe wrapper around the private Steam client interfaces we need.
//!
//! ABI reference: m4dEngi/open-steamworks, IClientEngine and
//! IClientRemoteClientManager. The scalar/string ABI and pairing callback were
//! also checked against the installed Linux steamclient.so. Private interfaces
//! can change: verify every function's code signature before use.

mod signatures;

use std::ffi::{CStr, c_char};
use std::path::Path;
use std::ptr;

use anyhow::{Context, Result, bail, ensure};

use super::library::{self, Library, Object};

type Count = unsafe extern "C" fn(Object) -> i32;
type ClientId = unsafe extern "C" fn(Object, u32) -> u64;
type ClientName = unsafe extern "C" fn(Object, u64) -> *const c_char;
type ClientFlag = unsafe extern "C" fn(Object, u64) -> bool;
type Pair = unsafe extern "C" fn(Object, u64) -> u64;
type GetString = unsafe extern "C" fn(Object, i32, *const c_char, *const c_char) -> *const c_char;
type GetCallback = unsafe extern "C" fn(i32, *mut Callback) -> bool;
type FreeCallback = unsafe extern "C" fn(i32);
type Factory = unsafe extern "C" fn(*const c_char, *mut i32) -> Object;
type CreatePipe = unsafe extern "C" fn(Object) -> i32;
type ReleasePipe = unsafe extern "C" fn(Object, i32) -> bool;
type ConnectUser = unsafe extern "C" fn(Object, i32) -> i32;
type ReleaseUser = unsafe extern "C" fn(Object, i32, i32);
type GetRemote = unsafe extern "C" fn(Object, i32) -> Object;
type GetConfig = unsafe extern "C" fn(Object, i32, i32) -> Object;

// RemoteClientPairWifiAP result. Its first field is the job handle returned
// by PairViaWifiAP, not a Remote Play client ID or a SteamAPICall_t.
const PAIR_CALLBACK: i32 = 1_100_056;
const CONFIG_LOCAL: i32 = 1;

#[repr(C)]
#[derive(Default)]
struct PairResult {
    job_id: u64,
    result: i32,
}

#[repr(C)]
struct Callback {
    user: i32,
    id: i32,
    data: *const u8,
    size: i32,
}

pub struct Device {
    pub id: u64,
    pub name: String,
    pub local: bool,
    pub can_pair: bool,
}

pub(super) struct Client {
    // Drop the connection before releasing the library it calls into.
    connection: Connection,
    _library: Library,
    remote: Object,
    config: Object,
    count: Count,
    client_id: ClientId,
    client_name: ClientName,
    local: ClientFlag,
    can_pair: ClientFlag,
    pair: Pair,
    get_string: GetString,
    get_callback: GetCallback,
    free_callback: FreeCallback,
}

impl Client {
    pub(super) fn connect(directory: Option<&Path>) -> Result<Self> {
        ensure!(
            cfg!(all(target_os = "linux", target_arch = "x86_64")),
            "Steam IPC currently supports x86_64 Linux"
        );

        let library = Library::open(&library::find(directory)?)?;

        // SAFETY: CreateInterface is Steam's exported C factory. The versioned
        // engine owns the returned object for the lifetime of the library.
        unsafe {
            let factory = library.symbol(&signatures::FACTORY)?;
            let get_callback = library.symbol(&signatures::GET_CALLBACK)?;
            let free_callback = library.symbol(&signatures::FREE_CALLBACK)?;

            let engine = factory(
                c"CLIENTENGINE_INTERFACE_VERSION005".as_ptr(),
                ptr::null_mut(),
            );

            ensure!(
                !engine.is_null(),
                "Steam has no CLIENTENGINE_INTERFACE_VERSION005"
            );

            // Validate cleanup before opening resources. Error paths and Drop
            // call these same checked pointers without resolving slots again.
            let release_pipe = library.engine_method(engine, 1, &signatures::RELEASE_PIPE)?;
            let release_user = library.engine_method(engine, 6, &signatures::RELEASE_USER)?;
            let create = library.engine_method(engine, 0, &signatures::CREATE_PIPE)?;
            let connect = library.engine_method(engine, 3, &signatures::CONNECT_USER)?;
            let remote_get = library.engine_method(engine, 56, &signatures::GET_REMOTE)?;
            let config_get = library.engine_method(engine, 44, &signatures::GET_CONFIG)?;

            let pipe = create(engine);

            ensure!(
                pipe != 0,
                "cannot open Steam IPC; start Steam as your normal desktop user"
            );

            // Release partial connections on every initialization error.
            let mut connection = Connection {
                engine,
                pipe,
                user: 0,
                release_pipe,
                release_user,
            };

            connection.user = connect(engine, pipe);

            ensure!(
                connection.user != 0,
                "Steam has no logged-in user; run this command as the user running Steam"
            );

            let remote = remote_get(engine, pipe);

            let config = config_get(engine, connection.user, pipe);

            ensure!(
                !remote.is_null() && !config.is_null(),
                "Steam Remote Play IPC is unavailable"
            );

            let iface = "IClientRemoteClientManager";

            let count = library.method(remote, iface, 17, &signatures::COUNT)?;
            let client_id = library.method(remote, iface, 18, &signatures::CLIENT_ID)?;
            let client_name = library.method(remote, iface, 36, &signatures::CLIENT_NAME)?;
            let local = library.method(remote, iface, 43, &signatures::LOCAL)?;
            let can_pair = library.method(remote, iface, 53, &signatures::CAN_PAIR)?;
            let pair = library.method(remote, iface, 55, &signatures::PAIR)?;
            let get_string =
                library.method(config, "IClientConfigStore", 5, &signatures::GET_STRING)?;

            Ok(Self {
                connection,
                _library: library,
                remote,
                config,
                count,
                client_id,
                client_name,
                local,
                can_pair,
                pair,
                get_string,
                get_callback,
                free_callback,
            })
        }
    }

    pub(super) fn devices(&self) -> Result<Vec<Device>> {
        // SAFETY: Methods are checked during initialization and the pipe is live.
        unsafe {
            let count = (self.count)(self.remote);

            ensure!(
                (0..=4096).contains(&count),
                "invalid Steam Remote Play client count"
            );

            let mut devices = Vec::new();

            for index in 0..count as u32 {
                let id = (self.client_id)(self.remote, index);

                // Remote Play client IDs are never 0 or all bits set; either
                // means the call did not return a uint64 client ID.
                ensure!(
                    id != 0 && id != u64::MAX,
                    "Steam returned an invalid Remote Play client ID"
                );

                let name = copy_string((self.client_name)(self.remote, id))?;

                devices.push(Device {
                    id,
                    name,
                    local: (self.local)(self.remote, id),
                    can_pair: (self.can_pair)(self.remote, id),
                });
            }
            Ok(devices)
        }
    }

    /// Requests Wi-Fi AP pairing with a Remote Play client and returns the job
    /// handle Steam reports its result with. Zero or `u64::MAX` mean refusal.
    pub(super) fn pair(&self, client: u64) -> u64 {
        // SAFETY: PairViaWifiAP takes a uint64 Remote Play client ID and returns
        // a job handle. This requests pairing, without starting a stream.
        unsafe { (self.pair)(self.remote, client) }
    }

    pub(super) fn config_string(&self, key: &CStr) -> Result<String> {
        // SAFETY: The verified GetString ABI returns a borrowed string, copied
        // immediately before any further IPC call can invalidate it.
        unsafe {
            copy_string((self.get_string)(
                self.config,
                CONFIG_LOCAL,
                key.as_ptr(),
                c"".as_ptr(),
            ))
        }
    }

    /// Empties Steam's callback queue and returns the pairing result for `job`,
    /// if it was among the drained callbacks.
    pub(super) fn drain_callbacks(&self, job: Option<u64>) -> Result<Option<i32>> {
        let mut status = None;

        for _ in 0..4096 {
            let mut callback = Callback {
                user: 0,
                id: 0,
                data: ptr::null(),
                size: 0,
            };

            // SAFETY: Steam owns each payload until FreeLastCallback. Copy the
            // result before freeing, including broadcasts for other devices.
            unsafe {
                if !(self.get_callback)(self.connection.pipe, &mut callback) {
                    return Ok(status);
                }

                if callback.id == PAIR_CALLBACK
                    && callback.size == size_of::<PairResult>() as i32
                    && !callback.data.is_null()
                {
                    let result = ptr::read_unaligned(callback.data.cast::<PairResult>());

                    if Some(result.job_id) == job {
                        status = Some(result.result);
                    }
                }
                (self.free_callback)(self.connection.pipe);
            }
        }

        bail!("Steam's callback queue did not drain")
    }
}

struct Connection {
    engine: Object,
    pipe: i32,
    user: i32,
    release_pipe: ReleasePipe,
    release_user: ReleaseUser,
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: Both functions were checked before creating the pipe and
        // remain mapped until after this connection is dropped.
        unsafe {
            if self.user != 0 {
                (self.release_user)(self.engine, self.pipe, self.user);
            }

            (self.release_pipe)(self.engine, self.pipe);
        }
    }
}

//TODO: we could also use CStr::from_ptr but we'd loose the 4096 bound in strlen
unsafe fn copy_string(value: *const c_char) -> Result<String> {
    if value.is_null() {
        return Ok(String::new());
    }

    // SAFETY: Steam returns a valid NUL-terminated string. Limit the copy to
    // catch unexpected ABI changes without copying unbounded client memory.
    let len = unsafe { libc::strnlen(value, 4096) };

    ensure!(len < 4096, "Steam returned an unexpectedly long string");

    let bytes = unsafe { std::slice::from_raw_parts(value.cast::<u8>(), len) };

    Ok(std::str::from_utf8(bytes)
        .context("Steam returned a non-UTF-8 string")?
        .to_owned())
}

/// A fake Steam client with one LAN headset. No library, IPC connection,
/// NetworkManager, or hardware is needed.
#[cfg(test)]
pub(super) mod fake {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::mem::ManuallyDrop;

    pub const CLIENT: u64 = 42;
    const JOB: u64 = 9_876;
    static OTHER: PairResult = PairResult {
        job_id: 123,
        result: 4,
    };
    static SUCCESS: PairResult = PairResult {
        job_id: JOB,
        result: 1,
    };
    static FAILURE: PairResult = PairResult {
        job_id: JOB,
        result: 4,
    };

    #[derive(Default)]
    struct Fake {
        reject: bool,
        complete: bool,
        reads: usize,
        queue: VecDeque<&'static PairResult>,
        releases: Vec<&'static str>,
    }
    thread_local! { static FAKE: RefCell<Fake> = RefCell::default(); }

    /// Credential reads so far. Each read asserts the pairing completed first.
    pub fn reads() -> usize {
        FAKE.with_borrow(|fake| fake.reads)
    }

    pub fn drained() -> bool {
        FAKE.with_borrow(|fake| fake.queue.is_empty())
    }

    unsafe extern "C" fn count(_: Object) -> i32 {
        1
    }
    unsafe extern "C" fn id(_: Object, _: u32) -> u64 {
        CLIENT
    }
    unsafe extern "C" fn name(_: Object, _: u64) -> *const c_char {
        c"test Frame".as_ptr()
    }
    unsafe extern "C" fn flag(_: Object, _: u64) -> bool {
        true
    }
    unsafe extern "C" fn pair(_: Object, client: u64) -> u64 {
        assert_eq!(client, CLIENT);
        FAKE.with_borrow_mut(|fake| {
            fake.queue.push_back(&OTHER);
            fake.queue
                .push_back(if fake.reject { &FAILURE } else { &SUCCESS });
        });
        JOB
    }
    unsafe extern "C" fn callback(_: i32, out: *mut Callback) -> bool {
        FAKE.with_borrow(|fake| {
            if let Some(result) = fake.queue.front() {
                unsafe {
                    *out = Callback {
                        user: 1,
                        id: PAIR_CALLBACK,
                        data: (*result as *const PairResult).cast(),
                        size: size_of::<PairResult>() as i32,
                    };
                }
                true
            } else {
                false
            }
        })
    }
    unsafe extern "C" fn free(_: i32) {
        FAKE.with_borrow_mut(|fake| {
            let result = fake.queue.pop_front().unwrap();
            if result.job_id == JOB {
                fake.complete = true;
            }
        });
    }
    unsafe extern "C" fn release_pipe(_: Object, _: i32) -> bool {
        FAKE.with_borrow_mut(|fake| fake.releases.push("pipe"));
        true
    }
    unsafe extern "C" fn release_user(_: Object, _: i32, _: i32) {
        FAKE.with_borrow_mut(|fake| fake.releases.push("user"));
    }
    unsafe extern "C" fn config(
        _: Object,
        store: i32,
        key: *const c_char,
        _: *const c_char,
    ) -> *const c_char {
        assert_eq!(store, CONFIG_LOCAL);
        FAKE.with_borrow_mut(|fake| {
            assert!(
                fake.complete,
                "credentials read before matching pairing response"
            );
            fake.reads += 1;
        });
        match unsafe { CStr::from_ptr(key) }.to_bytes() {
            b"streaming_v2\\WifiAPPairedSSID" => c"frame_TEST".as_ptr(),
            b"streaming_v2\\WifiAPPairedPassword" => c"test-password".as_ptr(),
            _ => panic!("unexpected configuration key"),
        }
    }

    /// Existing pairing tests keep the fake client alive with ManuallyDrop.
    pub fn client(reject: bool) -> ManuallyDrop<Client> {
        FAKE.with_borrow_mut(|fake| {
            *fake = Fake {
                reject,
                ..Fake::default()
            }
        });
        ManuallyDrop::new(Client {
            connection: Connection {
                engine: ptr::null_mut(),
                pipe: 1,
                user: 1,
                release_pipe,
                release_user,
            },
            _library: Library::empty(),
            remote: ptr::null_mut(),
            config: ptr::null_mut(),
            count,
            client_id: id,
            client_name: name,
            local: flag,
            can_pair: flag,
            pair,
            get_string: config,
            get_callback: callback,
            free_callback: free,
        })
    }

    #[test]
    fn cleanup_releases_only_acquired_resources_in_order() {
        for user in [0, 1] {
            let mut client = ManuallyDrop::into_inner(client(false));
            client.connection.user = user;
            drop(client);

            FAKE.with_borrow(|fake| {
                let expected = if user == 0 {
                    vec!["pipe"]
                } else {
                    vec!["user", "pipe"]
                };
                assert_eq!(fake.releases, expected);
            });
        }
    }
}
