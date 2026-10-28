use std::ffi::{CString, c_char, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use windows_sys::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;
const WINDIVERT_PARAM_VERSION_MAJOR: i32 = 3;
const WINDIVERT_PARAM_VERSION_MINOR: i32 = 4;
const WINDIVERT_SHUTDOWN_RECV: u32 = 0x1;
const OUTBOUND: u32 = 1 << 17;
const IPV6: u32 = 1 << 20;

type OpenFn = unsafe extern "system" fn(*const c_char, i32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn =
    unsafe extern "system" fn(HANDLE, *const c_void, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "system" fn(HANDLE, u32) -> i32;
type CloseFn = unsafe extern "system" fn(HANDLE) -> i32;
type GetParamFn = unsafe extern "system" fn(HANDLE, i32, *mut u64) -> i32;

struct Functions {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    get_param: GetParamFn,
}

struct Library {
    module: HMODULE,
    functions: Functions,
}

unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl Library {
    fn load() -> io::Result<Arc<Self>> {
        let path = library_path()?;
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let flags = LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32;
        let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), flags) };
        if module.is_null() {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!(
                    "failed to load {}: {}",
                    path.display(),
                    io::Error::last_os_error()
                ),
            ));
        }

        let functions = match unsafe { load_functions(module) } {
            Ok(functions) => functions,
            Err(error) => {
                unsafe {
                    FreeLibrary(module);
                }
                return Err(error);
            }
        };
        Ok(Arc::new(Self { module, functions }))
    }

    fn open(self: &Arc<Self>, filter: &str, flags: u64) -> io::Result<RawHandle> {
        let filter = CString::new(filter).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "WinDivert filter contains NUL")
        })?;
        let handle =
            unsafe { (self.functions.open)(filter.as_ptr(), WINDIVERT_LAYER_NETWORK, 0, flags) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(open_error());
        }
        check_version(&self.functions, handle)?;
        Ok(RawHandle {
            library: self.clone(),
            handle,
        })
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

struct RawHandle {
    library: Arc<Library>,
    handle: HANDLE,
}

unsafe impl Send for RawHandle {}
unsafe impl Sync for RawHandle {}

impl Drop for RawHandle {
    fn drop(&mut self) {
        unsafe {
            (self.library.functions.close)(self.handle);
        }
    }
}

struct RecvGuard {
    handle: Arc<RawHandle>,
    armed: bool,
}

impl RecvGuard {
    fn new(handle: Arc<RawHandle>) -> Self {
        Self {
            handle,
            armed: true,
        }
    }

    fn shutdown(&mut self) {
        if self.armed {
            self.armed = false;
            unsafe {
                (self.handle.library.functions.shutdown)(
                    self.handle.handle,
                    WINDIVERT_SHUTDOWN_RECV,
                );
            }
        }
    }
}

impl Drop for RecvGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) struct Capture {
    handle: Arc<RawHandle>,
}

pub(crate) struct Injector {
    handle: Arc<RawHandle>,
}

#[derive(Debug)]
pub(crate) struct Packet {
    pub(crate) data: Vec<u8>,
}

#[repr(C)]
struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}

impl Default for Address {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
}

impl Capture {
    pub(crate) fn open(filter: &str) -> io::Result<Self> {
        let library = Library::load()?;
        let handle = library.open(filter, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY)?;
        Ok(Self {
            handle: Arc::new(handle),
        })
    }

    pub(crate) async fn recv(&self, timeout: Duration) -> io::Result<Packet> {
        let handle = self.handle.clone();
        let mut guard = RecvGuard::new(handle.clone());
        let mut worker = tokio::task::spawn_blocking(move || recv_blocking(&handle));
        match tokio::time::timeout(timeout, &mut worker).await {
            Ok(Ok(result)) => {
                guard.armed = false;
                result
            }
            Ok(Err(error)) => {
                guard.armed = false;
                Err(io::Error::other(format!(
                    "WinDivert receive task failed: {error}"
                )))
            }
            Err(_) => {
                guard.shutdown();
                let _ = worker.await;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "WinDivert receive timed out",
                ))
            }
        }
    }
}

impl Injector {
    pub(crate) fn open() -> io::Result<Self> {
        let library = Library::load()?;
        let handle = library.open("false", WINDIVERT_FLAG_SEND_ONLY)?;
        Ok(Self {
            handle: Arc::new(handle),
        })
    }

    pub(crate) fn send(&self, packet: &[u8], ipv6: bool) -> io::Result<usize> {
        let length = u32::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "packet is too large"))?;
        let mut address = Address {
            flags: OUTBOUND | if ipv6 { IPV6 } else { 0 },
            ..Address::default()
        };
        let mut sent = 0;
        let ok = unsafe {
            (self.handle.library.functions.send)(
                self.handle.handle,
                packet.as_ptr().cast(),
                length,
                &mut sent,
                &mut address,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(sent as usize)
    }
}

fn recv_blocking(handle: &RawHandle) -> io::Result<Packet> {
    let mut data = vec![0u8; 65_535];
    let mut length = 0;
    let mut address = Address::default();
    let ok = unsafe {
        (handle.library.functions.recv)(
            handle.handle,
            data.as_mut_ptr().cast(),
            data.len() as u32,
            &mut length,
            &mut address,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    data.truncate(usize::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "WinDivert returned an invalid length",
        )
    })?);
    Ok(Packet { data })
}

fn check_version(functions: &Functions, handle: HANDLE) -> io::Result<()> {
    let mut major = 0;
    let mut minor = 0;
    let major_ok =
        unsafe { (functions.get_param)(handle, WINDIVERT_PARAM_VERSION_MAJOR, &mut major) };
    let minor_ok =
        unsafe { (functions.get_param)(handle, WINDIVERT_PARAM_VERSION_MINOR, &mut minor) };
    if major_ok == 0 || minor_ok == 0 {
        unsafe {
            (functions.close)(handle);
        }
        return Err(io::Error::other(format!(
            "failed to query WinDivert version: {}",
            io::Error::last_os_error()
        )));
    }
    if major != 2 || minor != 2 {
        unsafe {
            (functions.close)(handle);
        }
        return Err(io::Error::other(format!(
            "unsupported WinDivert version {major}.{minor}; pingx requires 2.2"
        )));
    }
    Ok(())
}

fn library_path() -> io::Result<PathBuf> {
    let path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::other("executable has no parent directory"))?
        .join("WinDivert.dll");
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} is missing; place WinDivert.dll and WinDivert64.sys next to pingx.exe",
                path.display()
            ),
        ));
    }
    Ok(path)
}

fn open_error() -> io::Error {
    let error = io::Error::last_os_error();
    let message = match error.raw_os_error() {
        Some(2) => "WinDivert driver is unavailable; install WinDivert64.sys next to WinDivert.dll",
        Some(5) => "WinDivert requires Administrator privileges",
        Some(577) => "WinDivert driver signature is invalid",
        Some(654) => "an incompatible WinDivert driver is already loaded",
        Some(1058) => "the WinDivert driver service is disabled",
        Some(1275) => "the WinDivert driver is blocked by Windows security policy",
        _ => return io::Error::new(error.kind(), format!("WinDivertOpen failed: {error}")),
    };
    io::Error::new(error.kind(), message)
}

unsafe fn load_symbol<T: Copy>(module: HMODULE, name: &'static [u8]) -> io::Result<T> {
    let symbol = unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "WinDivert.dll is missing {}",
                String::from_utf8_lossy(&name[..name.len() - 1])
            ),
        )
    })?;
    Ok(unsafe { std::mem::transmute_copy::<_, T>(&symbol) })
}

unsafe fn load_functions(module: HMODULE) -> io::Result<Functions> {
    Ok(Functions {
        open: unsafe { load_symbol(module, b"WinDivertOpen\0") }?,
        recv: unsafe { load_symbol(module, b"WinDivertRecv\0") }?,
        send: unsafe { load_symbol(module, b"WinDivertSend\0") }?,
        shutdown: unsafe { load_symbol(module, b"WinDivertShutdown\0") }?,
        close: unsafe { load_symbol(module, b"WinDivertClose\0") }?,
        get_param: unsafe { load_symbol(module, b"WinDivertGetParam\0") }?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_matches_the_x64_windivert_abi() {
        assert_eq!(std::mem::size_of::<Address>(), 80);
    }
}
