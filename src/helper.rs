use anyhow::Result;
use std::ffi::OsString;

pub const INTERNAL_DAEMON_ARG: &str = "--internal-helper-daemon";
pub const INTERNAL_INSTALL_ARG: &str = "--internal-helper-install";
pub const INTERNAL_UNINSTALL_ARG: &str = "--internal-helper-uninstall";

pub async fn run_internal(args: &[OsString]) -> Result<Option<i32>> {
    let Some(command) = args.first().and_then(|arg| arg.to_str()) else {
        return Ok(None);
    };
    match command {
        INTERNAL_DAEMON_ARG => {
            #[cfg(target_os = "macos")]
            {
                macos::run_daemon().await?;
                Ok(Some(0))
            }
            #[cfg(not(target_os = "macos"))]
            {
                anyhow::bail!("the privileged helper is only supported on macOS")
            }
        }
        INTERNAL_INSTALL_ARG => {
            #[cfg(target_os = "macos")]
            {
                macos::install_as_root(args)?;
                Ok(Some(0))
            }
            #[cfg(not(target_os = "macos"))]
            {
                anyhow::bail!("the privileged helper is only supported on macOS")
            }
        }
        INTERNAL_UNINSTALL_ARG => {
            #[cfg(target_os = "macos")]
            {
                macos::uninstall_as_root()?;
                Ok(Some(0))
            }
            #[cfg(not(target_os = "macos"))]
            {
                anyhow::bail!("the privileged helper is only supported on macOS")
            }
        }
        _ => Ok(None),
    }
}

pub async fn run_command(args: &[OsString]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        return macos::run_command(args).await;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        anyhow::bail!("the privileged helper is only supported on macOS")
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use anyhow::{Context, Result};
    use serde::{Deserialize, Serialize};
    use std::ffi::{CString, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, IsTerminal, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    const LABEL: &str = "com.seamile.pingx.helper";
    const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.seamile.pingx.helper";
    const PLIST_PATH: &str = "/Library/LaunchDaemons/com.seamile.pingx.helper.plist";
    const STATE_DIR: &str = "/Library/Application Support/PingX";
    const STATE_PATH: &str = "/Library/Application Support/PingX/helper.json";
    const SOCKET_PATH: &str = "/var/run/pingx-helper.sock";
    const PROTOCOL_VERSION: u16 = 1;
    const MAX_FRAME: usize = 64 * 1024;

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    struct HelperState {
        protocol_version: u16,
        allowed_uid: u32,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct Request {
        protocol_version: u16,
        action: Action,
    }

    #[derive(Debug, Deserialize, Serialize)]
    enum Action {
        Status,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        protocol_version: u16,
        result: ResponseResult,
    }

    #[derive(Debug, Deserialize, Serialize)]
    enum ResponseResult {
        Status { allowed_uid: u32 },
        Error(String),
    }

    pub(super) async fn run_command(args: &[OsString]) -> Result<()> {
        let command = args
            .first()
            .and_then(|arg| arg.to_str())
            .ok_or_else(|| anyhow::anyhow!("usage: pingx helper <install|status|uninstall>"))?;
        match command {
            "install" => install_as_user(),
            "status" => show_status().await,
            "uninstall" => uninstall_as_user(),
            _ => anyhow::bail!("usage: pingx helper <install|status|uninstall>"),
        }
    }

    fn install_as_user() -> Result<()> {
        confirm_install()?;
        run_sudo(&[super::INTERNAL_INSTALL_ARG])
    }

    fn uninstall_as_user() -> Result<()> {
        confirm_uninstall()?;
        run_sudo(&[super::INTERNAL_UNINSTALL_ARG])
    }

    fn run_sudo(args: &[&str]) -> Result<()> {
        let current_exe = std::env::current_exe().context("resolve current executable")?;
        let status = Command::new("sudo")
            .arg("--")
            .arg(current_exe)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("run sudo")?;
        anyhow::ensure!(status.success(), "administrator operation failed");
        Ok(())
    }

    fn confirm_install() -> Result<()> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            anyhow::bail!(
                "helper installation needs an interactive terminal; run `sudo -v` and then rerun `pingx helper install`"
            );
        }
        println!("PingX will install a root-owned macOS helper at {HELPER_PATH}.");
        print!("Install or update it now with administrator approval? [Y/n]: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        anyhow::ensure!(
            matches!(
                answer.trim().to_ascii_lowercase().as_str(),
                "" | "y" | "yes"
            ),
            "helper installation cancelled"
        );
        Ok(())
    }

    fn confirm_uninstall() -> Result<()> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            anyhow::bail!(
                "helper removal needs an interactive terminal; run `sudo -v` and then rerun `pingx helper uninstall`"
            );
        }
        print!("Remove the PingX privileged helper and its socket service? [y/N]: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        anyhow::ensure!(
            matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
            "helper removal cancelled"
        );
        Ok(())
    }

    pub(super) fn install_as_root(args: &[OsString]) -> Result<()> {
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "helper installation must run as root"
        );
        let allowed_uid = args
            .iter()
            .skip(1)
            .find_map(|arg| arg.to_str()?.strip_prefix("--uid="))
            .map(str::parse::<u32>)
            .transpose()?
            .or_else(|| std::env::var("SUDO_UID").ok()?.parse().ok())
            .ok_or_else(|| {
                anyhow::anyhow!("cannot determine the user requesting helper installation")
            })?;
        anyhow::ensure!(
            allowed_uid != 0,
            "the root account cannot be the helper caller"
        );

        let source = std::env::current_exe().context("resolve helper source")?;
        let source_metadata = fs::metadata(&source).context("inspect helper source")?;
        anyhow::ensure!(
            source_metadata.is_file(),
            "helper source is not a regular file"
        );

        let helper = Path::new(HELPER_PATH);
        ensure_root_directory(helper.parent().unwrap())?;
        let mut input = File::open(&source).context("open helper source")?;
        atomic_install(helper, 0o755, |output| {
            io::copy(&mut input, output).map(|_| ())
        })?;

        let plist = launchd_plist()?;
        ensure_root_directory(Path::new("/Library/LaunchDaemons"))?;
        atomic_install(Path::new(PLIST_PATH), 0o644, |output| {
            output.write_all(plist.as_bytes())
        })?;

        ensure_root_directory(Path::new(STATE_DIR))?;
        let state = serde_json::to_vec_pretty(&HelperState {
            protocol_version: PROTOCOL_VERSION,
            allowed_uid,
        })?;
        atomic_install(Path::new(STATE_PATH), 0o644, |output| {
            output.write_all(&state)
        })?;

        let _ = Command::new("launchctl")
            .args(["bootout", &format!("system/{LABEL}")])
            .status();
        let status = Command::new("launchctl")
            .args(["bootstrap", "system", PLIST_PATH])
            .status()
            .context("bootstrap helper service")?;
        anyhow::ensure!(status.success(), "launchctl could not load {LABEL}");
        println!("PingX helper installed for UID {allowed_uid}");
        Ok(())
    }

    pub(super) fn uninstall_as_root() -> Result<()> {
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "helper removal must run as root"
        );
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("system/{LABEL}")])
            .status();
        for path in [HELPER_PATH, PLIST_PATH, STATE_PATH] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).with_context(|| format!("remove {path}")),
            }
        }
        match fs::remove_dir(STATE_DIR) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("remove {STATE_DIR}")),
        }
        println!("PingX helper removed");
        Ok(())
    }

    async fn show_status() -> Result<()> {
        let metadata = fs::symlink_metadata(HELPER_PATH)
            .context("helper is not installed; run `pingx helper install`")?;
        anyhow::ensure!(
            metadata.file_type().is_file() && metadata.uid() == 0,
            "installed helper is not a root-owned regular file"
        );
        let state = read_state()?;
        anyhow::ensure!(
            state.protocol_version == PROTOCOL_VERSION,
            "helper protocol is {} but this client expects {PROTOCOL_VERSION}; run `pingx helper install`",
            state.protocol_version
        );
        let response = send_request(Request {
            protocol_version: PROTOCOL_VERSION,
            action: Action::Status,
        })
        .await?;
        match response.result {
            ResponseResult::Status { allowed_uid } => {
                println!("PingX helper: installed");
                println!("Protocol: {}", response.protocol_version);
                println!("Allowed UID: {allowed_uid}");
                println!("Socket: {SOCKET_PATH}");
                Ok(())
            }
            ResponseResult::Error(error) => Err(anyhow::anyhow!("helper error: {error}")),
        }
    }

    pub(super) async fn run_daemon() -> Result<()> {
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "helper daemon must run as root"
        );
        let state = read_state()?;
        anyhow::ensure!(
            state.protocol_version == PROTOCOL_VERSION,
            "unsupported helper protocol {}",
            state.protocol_version
        );
        let listener = activated_listener()?;
        loop {
            let accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
            match accepted {
                Ok(Ok((stream, _))) => {
                    if let Err(error) = handle_connection(stream, &state).await {
                        eprintln!("pingx-helper: {error:#}");
                    }
                }
                Ok(Err(error)) => return Err(error).context("accept helper connection"),
                Err(_) => return Ok(()),
            }
        }
    }

    async fn handle_connection(stream: UnixStream, state: &HelperState) -> Result<()> {
        let credentials = stream.peer_cred().context("read peer credentials")?;
        anyhow::ensure!(
            credentials.uid() == state.allowed_uid,
            "UID {} is not authorized to use the PingX helper",
            credentials.uid()
        );
        let (reader, mut writer) = stream.into_split();
        let request: Request = read_frame(reader).await?;
        anyhow::ensure!(
            request.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        let response = match request.action {
            Action::Status => Response {
                protocol_version: PROTOCOL_VERSION,
                result: ResponseResult::Status {
                    allowed_uid: state.allowed_uid,
                },
            },
        };
        write_frame(&mut writer, &response).await
    }

    async fn send_request(request: Request) -> Result<Response> {
        let stream = tokio::time::timeout(Duration::from_secs(3), UnixStream::connect(SOCKET_PATH))
            .await
            .map_err(|_| anyhow::anyhow!("PingX helper did not respond"))??
            .into_split();
        let (reader, mut writer) = stream;
        write_frame(&mut writer, &request).await?;
        read_frame(reader).await
    }

    async fn read_frame<T: for<'de> Deserialize<'de>>(
        reader: tokio::net::unix::OwnedReadHalf,
    ) -> Result<T> {
        let reader = BufReader::new(reader);
        let mut data = String::new();
        let size = reader
            .take((MAX_FRAME + 1) as u64)
            .read_line(&mut data)
            .await?;
        anyhow::ensure!(
            size > 0,
            "helper connection closed before a request was received"
        );
        anyhow::ensure!(size <= MAX_FRAME, "helper request is too large");
        Ok(serde_json::from_str(data.trim_end())?)
    }

    async fn write_frame<T: Serialize>(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        value: &T,
    ) -> Result<()> {
        let data = serde_json::to_vec(value)?;
        anyhow::ensure!(data.len() <= MAX_FRAME, "helper response is too large");
        writer.write_all(&data).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok(())
    }

    fn read_state() -> Result<HelperState> {
        let metadata = fs::symlink_metadata(STATE_PATH).context("helper state is missing")?;
        anyhow::ensure!(
            metadata.file_type().is_file() && metadata.uid() == 0,
            "helper state is not a root-owned regular file"
        );
        serde_json::from_reader(File::open(STATE_PATH)?).context("read helper state")
    }

    fn ensure_root_directory(path: &Path) -> Result<()> {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
        let metadata = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.uid() == 0 && !metadata.file_type().is_symlink(),
            "{} is not a root-owned directory",
            path.display()
        );
        Ok(())
    }

    fn atomic_install<F>(path: &Path, mode: u32, write: F) -> Result<()>
    where
        F: FnOnce(&mut File) -> io::Result<()>,
    {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid installation path {}", path.display()))?;
        let temporary = parent.join(format!(".{}.tmp.{}", LABEL, std::process::id()));
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("remove {}", temporary.display()));
            }
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        write(&mut output)?;
        output.sync_all()?;
        output.set_permissions(fs::Permissions::from_mode(mode))?;
        drop(output);
        fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn launchd_plist() -> Result<String> {
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{HELPER_PATH}</string><string>{}</string></array>
  <key>Sockets</key>
  <dict>
    <key>pingx</key>
    <dict>
      <key>SockPathName</key><string>{SOCKET_PATH}</string>
      <key>SockPathMode</key><integer>438</integer>
    </dict>
  </dict>
  <key>Umask</key><integer>18</integer>
  <key>ThrottleInterval</key><integer>1</integer>
</dict>
</plist>
"#,
            super::INTERNAL_DAEMON_ARG
        ))
    }

    fn activated_listener() -> Result<UnixListener> {
        #[link(name = "System")]
        unsafe extern "C" {
            fn launch_activate_socket(
                name: *const libc::c_char,
                fds: *mut *mut libc::c_int,
                count: *mut usize,
            ) -> libc::c_int;
        }

        let name = CString::new("pingx")?;
        let mut fds = std::ptr::null_mut();
        let mut count = 0usize;
        let status = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
        anyhow::ensure!(status == 0, "launch_activate_socket failed: {status}");
        anyhow::ensure!(
            count != 0 && !fds.is_null(),
            "launchd returned no helper socket"
        );
        let fd = unsafe { *fds };
        unsafe { libc::free(fds.cast()) };
        let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
        listener.set_nonblocking(true)?;
        UnixListener::from_std(listener).context("register launchd socket")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn launchd_plist_uses_the_activation_socket() {
            let plist = launchd_plist().unwrap();
            assert!(plist.contains(LABEL));
            assert!(plist.contains(SOCKET_PATH));
            assert!(plist.contains(super::super::INTERNAL_DAEMON_ARG));
            assert!(plist.contains("<key>SockPathMode</key><integer>438</integer>"));
        }

        #[test]
        fn helper_state_round_trips() {
            let state = HelperState {
                protocol_version: PROTOCOL_VERSION,
                allowed_uid: 501,
            };
            let data = serde_json::to_vec(&state).unwrap();
            assert_eq!(serde_json::from_slice::<HelperState>(&data).unwrap(), state);
        }
    }
}
