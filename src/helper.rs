use anyhow::Result;
use std::ffi::OsString;

pub const INTERNAL_DAEMON_ARG: &str = "--internal-helper-daemon";
pub const INTERNAL_INSTALL_ARG: &str = "--internal-helper-install";
pub const INTERNAL_UNINSTALL_ARG: &str = "--internal-helper-uninstall";
pub const INTERNAL_WORKER_ARG: &str = "--internal-helper-worker";

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
        INTERNAL_WORKER_ARG => {
            #[cfg(target_os = "macos")]
            {
                macos::run_worker().await?;
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

pub async fn run_if_needed(_cli: &crate::cli::Cli) -> Result<Option<i32>> {
    #[cfg(target_os = "macos")]
    {
        return macos::run_if_needed(_cli).await;
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use crate::cli::Cli;
    use anyhow::{Context, Result};
    use serde::{Deserialize, Serialize};
    use std::ffi::{CString, OsString};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, IsTerminal, Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};

    const LABEL: &str = "com.seamile.pingx.helper";
    const HELPER_PATH: &str = "/Library/PrivilegedHelperTools/com.seamile.pingx.helper";
    const PLIST_PATH: &str = "/Library/LaunchDaemons/com.seamile.pingx.helper.plist";
    const STATE_DIR: &str = "/Library/Application Support/PingX";
    const STATE_PATH: &str = "/Library/Application Support/PingX/helper.json";
    const SOCKET_PATH: &str = "/var/run/pingx-helper.sock";
    const PROTOCOL_VERSION: u16 = 4;
    const MAX_REQUEST: usize = 1024 * 1024;
    const MAX_RESPONSE: usize = 4 * 1024 * 1024;
    const MAX_CONTROL: usize = 4 * 1024;
    const MAX_JSON_OUTPUT: usize = 16 * 1024 * 1024;
    const ROOT_COPY_SCRIPT: &str = r#"set -eu
work=$(/usr/bin/mktemp -d /private/tmp/pingx-helper.XXXXXX)
trap '/bin/rm -rf "$work"' EXIT HUP INT TERM
/bin/cat > "$work/pingx"
/bin/chmod 700 "$work/pingx"
"$work/pingx" "$@"
"#;

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
        Run(Operation),
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct Response {
        protocol_version: u16,
        result: ResponseResult,
    }

    #[derive(Debug, Deserialize, Serialize)]
    enum ResponseResult {
        Status { allowed_uid: u32 },
        Output { stream: OutputStream, data: String },
        TraceData { data: String },
        Exit { code: i32 },
        Error(String),
    }

    #[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
    enum OutputStream {
        Stdout,
        Stderr,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    enum Operation {
        Ping(PingOperation),
        Trace(TraceOperation),
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct PingOperation {
        targets: Vec<String>,
        count: Option<u64>,
        interval_ns: u64,
        timeout_ns: u64,
        deadline_ns: Option<u64>,
        ttl: u32,
        size: usize,
        quiet: bool,
        interface: Option<String>,
        ipv4: bool,
        ipv6: bool,
        tcp: bool,
        udp: bool,
        json: bool,
        json_file: bool,
    }

    #[derive(Clone, Debug, Deserialize, Serialize)]
    struct TraceOperation {
        target: String,
        size: Option<usize>,
        timeout_ns: u64,
        interface: Option<String>,
        ipv4: bool,
        ipv6: bool,
        tcp: bool,
        udp: bool,
        max_hops: u8,
    }

    #[derive(Debug, Deserialize, Serialize)]
    enum ClientControl {
        Cancel,
    }

    pub(super) async fn run_if_needed(cli: &Cli) -> Result<Option<i32>> {
        if unsafe { libc::geteuid() } == 0 {
            return Ok(None);
        }
        let operation = operation_from_cli(cli)?;
        let Some(operation) = operation else {
            return Ok(None);
        };
        validate_operation(&operation)?;
        ensure_helper_ready().await?;
        let json_path = cli
            .json
            .as_ref()
            .and_then(|value| value.as_ref())
            .map(PathBuf::from);
        let code = run_client(operation, json_path).await?;
        Ok(Some(code))
    }

    fn operation_from_cli(cli: &Cli) -> Result<Option<Operation>> {
        if cli.fetch_geo || cli.geo {
            return Ok(None);
        }
        if cli.traceroute {
            let target = cli
                .targets
                .first()
                .ok_or_else(|| anyhow::anyhow!("traceroute requires a target"))?;
            return Ok(Some(Operation::Trace(TraceOperation {
                target: target.clone(),
                size: cli.size,
                timeout_ns: duration_ns(cli.timeout)?,
                interface: cli.interface.clone(),
                ipv4: cli.ipv4,
                ipv6: cli.ipv6,
                tcp: cli.tcp,
                udp: cli.udp,
                max_hops: cli.max_hops,
            })));
        }

        let unprivileged_icmp = can_use_unprivileged_icmp(cli);
        let mut needs_helper = false;
        let mut has_http = false;
        for target in &cli.targets {
            let protocol = cli.target_spec(target)?.protocol;
            if matches!(protocol, crate::cli::Protocol::Http(_)) {
                has_http = true;
            } else if protocol_needs_helper(&protocol, unprivileged_icmp) {
                needs_helper = true;
            }
        }
        if !needs_helper {
            return Ok(None);
        }
        anyhow::ensure!(
            !has_http,
            "HTTP and privileged probes cannot be combined in one helper request; run them separately"
        );
        Ok(Some(Operation::Ping(PingOperation {
            targets: cli.targets.clone(),
            count: cli.count,
            interval_ns: duration_ns(cli.interval)?,
            timeout_ns: duration_ns(cli.timeout)?,
            deadline_ns: cli.deadline.map(duration_ns).transpose()?,
            ttl: cli.ttl,
            size: cli.ping_size(),
            quiet: cli.quiet,
            interface: cli.interface.clone(),
            ipv4: cli.ipv4,
            ipv6: cli.ipv6,
            tcp: cli.tcp,
            udp: cli.udp,
            json: cli.json.is_some(),
            json_file: cli.json.as_ref().is_some_and(Option::is_some),
        })))
    }

    fn protocol_needs_helper(protocol: &crate::cli::Protocol, unprivileged_icmp: bool) -> bool {
        match protocol {
            crate::cli::Protocol::Icmp => !unprivileged_icmp,
            crate::cli::Protocol::Tcp(_) | crate::cli::Protocol::Udp(_) => true,
            crate::cli::Protocol::Http(_) => false,
        }
    }

    fn can_use_unprivileged_icmp(cli: &Cli) -> bool {
        use socket2::{Domain, Protocol, Socket, Type};

        let v4 = || Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok();
        let v6 = || Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).is_ok();
        if cli.ipv4 {
            v4()
        } else if cli.ipv6 {
            v6()
        } else {
            v4() && v6()
        }
    }

    fn duration_ns(duration: Duration) -> Result<u64> {
        u64::try_from(duration.as_nanos()).context("duration is too large for the helper protocol")
    }

    fn validate_operation(operation: &Operation) -> Result<()> {
        match operation {
            Operation::Ping(ping) => {
                anyhow::ensure!(
                    (1..=1024).contains(&ping.targets.len()),
                    "helper request must contain 1 to 1024 targets"
                );
                anyhow::ensure!(!ping.tcp || !ping.udp, "TCP and UDP modes conflict");
                anyhow::ensure!(!ping.ipv4 || !ping.ipv6, "IPv4 and IPv6 modes conflict");
                anyhow::ensure!(
                    !ping.json_file || ping.json,
                    "JSON file output requires JSON mode"
                );
                anyhow::ensure!((1..=255).contains(&ping.ttl), "TTL must be 1..=255");
                anyhow::ensure!(ping.size <= u16::MAX as usize, "packet size is too large");
                anyhow::ensure!(ping.interval_ns > 0, "interval must be positive");
                anyhow::ensure!(ping.timeout_ns > 0, "timeout must be positive");
                anyhow::ensure!(
                    ping.deadline_ns.is_none_or(|deadline| deadline > 0),
                    "deadline must be positive"
                );
                anyhow::ensure!(
                    ping.count
                        .is_none_or(|count| (1..=10_000_000).contains(&count)),
                    "count is outside the helper limit"
                );
                validate_interface(ping.interface.as_deref())?;
                let cli = ping.to_cli();
                for target in &ping.targets {
                    anyhow::ensure!(target.len() <= 1024, "target name is too long");
                    let protocol = cli.target_spec(target)?.protocol;
                    anyhow::ensure!(
                        !matches!(protocol, crate::cli::Protocol::Http(_)),
                        "HTTP targets do not use the privileged helper"
                    );
                    if matches!(protocol, crate::cli::Protocol::Udp(_)) {
                        crate::probe::udp_error::validate_payload_size(ping.size)
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    }
                }
            }
            Operation::Trace(trace) => {
                anyhow::ensure!(trace.target.len() <= 1024, "target name is too long");
                anyhow::ensure!(!trace.tcp || !trace.udp, "TCP and UDP modes conflict");
                anyhow::ensure!(!trace.ipv4 || !trace.ipv6, "IPv4 and IPv6 modes conflict");
                anyhow::ensure!(trace.timeout_ns > 0, "timeout must be positive");
                anyhow::ensure!(
                    (1..=255).contains(&trace.max_hops),
                    "max hops must be 1..=255"
                );
                anyhow::ensure!(
                    trace
                        .size
                        .is_none_or(|size| (1..=u16::MAX as usize).contains(&size)),
                    "invalid packet size"
                );
                validate_interface(trace.interface.as_deref())?;
                let cli = trace.to_cli();
                anyhow::ensure!(
                    !matches!(cli.trace_target()?.protocol, crate::cli::Protocol::Http(_)),
                    "HTTP traceroute is not supported"
                );
            }
        }
        Ok(())
    }

    fn validate_interface(interface: Option<&str>) -> Result<()> {
        if let Some(interface) = interface {
            anyhow::ensure!(
                !interface.is_empty()
                    && interface.len() <= 64
                    && interface
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte)),
                "invalid interface name"
            );
        }
        Ok(())
    }

    impl PingOperation {
        fn to_cli(&self) -> Cli {
            Cli {
                targets: self.targets.clone(),
                count: self.count,
                interval: Duration::from_nanos(self.interval_ns),
                timeout: Duration::from_nanos(self.timeout_ns),
                deadline: self.deadline_ns.map(Duration::from_nanos),
                ttl: self.ttl,
                size: Some(self.size),
                quiet: self.quiet,
                interface: self.interface.clone(),
                ipv4: self.ipv4,
                ipv6: self.ipv6,
                tcp: self.tcp,
                udp: self.udp,
                http: false,
                headers: Vec::new(),
                geo: false,
                fetch_geo: false,
                // The root worker must never write to a caller-selected path.
                json: self.json.then_some(None),
                traceroute: false,
                max_hops: crate::cli::DEFAULT_TRACEROUTE_MAX_HOPS,
            }
        }
    }

    impl TraceOperation {
        fn to_cli(&self) -> Cli {
            Cli {
                targets: vec![self.target.clone()],
                count: None,
                interval: Duration::from_secs(1),
                timeout: Duration::from_nanos(self.timeout_ns),
                deadline: None,
                ttl: 64,
                size: self.size,
                quiet: false,
                interface: self.interface.clone(),
                ipv4: self.ipv4,
                ipv6: self.ipv6,
                tcp: self.tcp,
                udp: self.udp,
                http: false,
                headers: Vec::new(),
                geo: false,
                fetch_geo: false,
                json: None,
                traceroute: true,
                max_hops: self.max_hops,
            }
        }
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

    async fn ensure_helper_ready() -> Result<()> {
        let uid = unsafe { libc::geteuid() } as u32;
        for attempt in 0..2 {
            let result = async {
                let state = read_state()?;
                anyhow::ensure!(
                    state.protocol_version == PROTOCOL_VERSION,
                    "helper protocol is {} but this client expects {PROTOCOL_VERSION}",
                    state.protocol_version
                );
                anyhow::ensure!(
                    state.allowed_uid == uid,
                    "helper is authorized for UID {} instead of {uid}",
                    state.allowed_uid
                );
                let response = send_request(Request {
                    protocol_version: PROTOCOL_VERSION,
                    action: Action::Status,
                })
                .await?;
                anyhow::ensure!(
                    response.protocol_version == PROTOCOL_VERSION,
                    "helper protocol changed while checking availability"
                );
                match response.result {
                    ResponseResult::Status { allowed_uid } if allowed_uid == uid => Ok(()),
                    ResponseResult::Status { allowed_uid } => Err(anyhow::anyhow!(
                        "helper authorized UID {allowed_uid} instead of {uid}"
                    )),
                    ResponseResult::Error(error) => Err(anyhow::anyhow!(error)),
                    _ => Err(anyhow::anyhow!("unexpected helper status response")),
                }
            }
            .await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) if attempt == 0 => {
                    offer_helper_install(&error)?;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(error) => return Err(error).context("PingX helper is unavailable"),
            }
        }
        unreachable!()
    }

    fn offer_helper_install(reason: &anyhow::Error) -> Result<()> {
        let command = "pingx helper install";
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            anyhow::bail!(
                "{reason:#}; privileged probes need the PingX helper. Run `{command}` from an interactive terminal"
            );
        }
        eprintln!("pingx: {reason:#}");
        eprintln!("Privileged probes need a root-owned PingX helper.");
        print!("Install or update it now with administrator approval? [Y/n]: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        anyhow::ensure!(
            matches!(
                answer.trim().to_ascii_lowercase().as_str(),
                "" | "y" | "yes"
            ),
            "PingX helper installation cancelled"
        );
        run_sudo(&[super::INTERNAL_INSTALL_ARG])
    }

    async fn run_client(operation: Operation, json_path: Option<PathBuf>) -> Result<i32> {
        validate_operation(&operation)?;
        let json_file_requested = matches!(
            &operation,
            Operation::Ping(PingOperation {
                json_file: true,
                ..
            })
        );
        anyhow::ensure!(
            !json_file_requested || json_path.is_some(),
            "helper JSON file path is missing"
        );
        let stream = UnixStream::connect(SOCKET_PATH)
            .await
            .context("connect to PingX helper")?;
        let (reader, mut writer) = stream.into_split();
        write_frame(
            &mut writer,
            &Request {
                protocol_version: PROTOCOL_VERSION,
                action: Action::Run(operation),
            },
        )
        .await?;
        let mut reader = BufReader::new(reader);
        let mut json_data = String::new();
        let mut json_line_count = 0usize;
        loop {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => {
                    signal?;
                    let _ = write_frame(&mut writer, &ClientControl::Cancel).await;
                    return Ok(130);
                }
                response = read_frame::<Response>(&mut reader, MAX_RESPONSE) => {
                    let Some(response) = response? else {
                        anyhow::bail!("PingX helper closed the connection before reporting completion");
                    };
                    anyhow::ensure!(
                        response.protocol_version == PROTOCOL_VERSION,
                        "helper protocol changed while the operation was running"
                    );
                    match response.result {
                        ResponseResult::Output { stream, data } => match stream {
                            OutputStream::Stdout => {
                                if json_file_requested {
                                    append_json_line(
                                        &mut json_data,
                                        &mut json_line_count,
                                        &data,
                                    )?;
                                } else {
                                    let mut output = io::stdout().lock();
                                    writeln!(output, "{data}")?;
                                    output.flush()?;
                                }
                            }
                            OutputStream::Stderr => {
                                let mut output = io::stderr().lock();
                                writeln!(output, "{data}")?;
                                output.flush()?;
                            }
                        },
                        ResponseResult::TraceData { data } => {
                            println!("{}", crate::traceroute::render_trace_data(&data).await?);
                        }
                        ResponseResult::Exit { code } => {
                            if code == 0 && json_file_requested
                                && let Some(path) = json_path.as_ref()
                            {
                                crate::session::write_json_file(
                                    path.to_str().context("JSON path is not valid UTF-8")?,
                                    json_data.as_bytes(),
                                )?;
                            }
                            return Ok(code);
                        }
                        ResponseResult::Error(error) => anyhow::bail!("{error}"),
                        ResponseResult::Status { .. } => {
                            anyhow::bail!("unexpected status response during probe operation");
                        }
                    }
                }
            }
        }
    }

    pub(super) async fn run_worker() -> Result<()> {
        let mut data = Vec::new();
        io::stdin()
            .lock()
            .take((MAX_REQUEST + 1) as u64)
            .read_to_end(&mut data)?;
        anyhow::ensure!(data.len() <= MAX_REQUEST, "helper request is too large");
        let operation: Operation = serde_json::from_slice(&data)?;
        validate_operation(&operation)?;
        let json_only = matches!(
            &operation,
            Operation::Ping(PingOperation {
                json_file: true,
                ..
            })
        );
        let CliWithMode {
            cli: mut parsed,
            traceroute,
        } = match operation {
            Operation::Ping(ping) => CliWithMode {
                cli: ping.to_cli(),
                traceroute: false,
            },
            Operation::Trace(trace) => CliWithMode {
                cli: trace.to_cli(),
                traceroute: true,
            },
        };
        if json_only {
            parsed.quiet = true;
        }
        crate::utils::set_bind_interface(parsed.interface.clone());
        if traceroute {
            crate::traceroute::TraceSession::new(parsed)
                .run_helper_data()
                .await
        } else if json_only {
            crate::session::Session::new(parsed).run_json_only().await
        } else {
            crate::session::Session::new(parsed).run().await
        }
    }

    struct CliWithMode {
        cli: Cli,
        traceroute: bool,
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
        let source = open_current_executable()?;
        let status = Command::new("/usr/bin/sudo")
            .arg("--")
            .arg("/bin/sh")
            .arg("-c")
            .arg(ROOT_COPY_SCRIPT)
            .arg("pingx-helper")
            .args(args)
            .stdin(Stdio::from(source))
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

        let mut input = open_current_executable()?;

        let helper = Path::new(HELPER_PATH);
        let helper_dir = helper.parent().unwrap();
        ensure_root_directory(helper_dir)?;
        ensure_root_directory(Path::new("/Library/LaunchDaemons"))?;
        ensure_root_directory(Path::new(STATE_DIR))?;

        let plist = launchd_plist(allowed_uid)?;
        let state = serde_json::to_vec_pretty(&HelperState {
            protocol_version: PROTOCOL_VERSION,
            allowed_uid,
        })?;
        let mut staged = Vec::new();
        stage_install(&mut staged, helper, 0o755, |output| {
            io::copy(&mut input, output).map(|_| ())
        })?;
        stage_install(&mut staged, Path::new(PLIST_PATH), 0o644, |output| {
            output.write_all(plist.as_bytes())
        })?;
        stage_install(&mut staged, Path::new(STATE_PATH), 0o644, |output| {
            output.write_all(&state)
        })?;
        let service_was_loaded = stop_helper_service()?;
        activate_install(
            &mut staged,
            || restore_helper_service(service_was_loaded),
            start_helper_service,
        )?;
        println!("PingX helper installed for UID {allowed_uid}");
        Ok(())
    }

    fn activate_install<F, G>(
        staged: &mut [StagedInstall],
        restore_service: G,
        mut start_service: F,
    ) -> Result<()>
    where
        F: FnMut() -> Result<()>,
        G: FnOnce() -> Result<()>,
    {
        if let Err(error) = commit_install(staged) {
            rollback_install(staged);
            restore_service()?;
            return Err(error);
        }
        if let Err(error) = start_service() {
            rollback_install(staged);
            restore_service().context("restore the previous helper service")?;
            return Err(error);
        }
        finalize_install(staged)
    }

    fn stop_helper_service() -> Result<bool> {
        let loaded = Command::new("launchctl")
            .args(["print", &format!("system/{LABEL}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("query helper service")?
            .success();
        if loaded {
            let status = Command::new("launchctl")
                .args(["bootout", &format!("system/{LABEL}")])
                .status()
                .context("stop helper service")?;
            anyhow::ensure!(status.success(), "launchctl could not stop {LABEL}");
        }
        Ok(loaded)
    }

    fn start_helper_service() -> Result<()> {
        let status = Command::new("launchctl")
            .args(["bootstrap", "system", PLIST_PATH])
            .status()
            .context("bootstrap helper service")?;
        anyhow::ensure!(status.success(), "launchctl could not load {LABEL}");
        Ok(())
    }

    fn restore_helper_service(was_loaded: bool) -> Result<()> {
        if was_loaded {
            start_helper_service()?;
        }
        Ok(())
    }

    pub(super) fn uninstall_as_root() -> Result<()> {
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "helper removal must run as root"
        );
        stop_helper_service()?;
        for path in [HELPER_PATH, PLIST_PATH, STATE_PATH, SOCKET_PATH] {
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
        anyhow::ensure!(
            response.protocol_version == PROTOCOL_VERSION,
            "helper protocol changed while checking status"
        );
        match response.result {
            ResponseResult::Status { allowed_uid } => {
                println!("PingX helper: installed");
                println!("Protocol: {}", response.protocol_version);
                println!("Allowed UID: {allowed_uid}");
                println!("Socket: {SOCKET_PATH}");
                Ok(())
            }
            ResponseResult::Error(error) => Err(anyhow::anyhow!("helper error: {error}")),
            _ => Err(anyhow::anyhow!("unexpected helper status response")),
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
        serve(listener, state).await
    }

    async fn serve(listener: UnixListener, state: HelperState) -> Result<()> {
        let mut sessions = tokio::task::JoinSet::new();
        loop {
            reap_sessions(&mut sessions);
            let accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
            match accepted {
                Ok(Ok((stream, _))) => {
                    let state = state.clone();
                    sessions.spawn(async move { handle_connection(stream, &state).await });
                }
                Ok(Err(error)) => return Err(error).context("accept helper connection"),
                Err(_) => {
                    reap_sessions(&mut sessions);
                    if sessions.is_empty() {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn reap_sessions(sessions: &mut tokio::task::JoinSet<Result<()>>) {
        while let Some(result) = sessions.try_join_next() {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("pingx-helper: {error:#}"),
                Err(error) => eprintln!("pingx-helper: session task failed: {error}"),
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
        let mut reader = BufReader::new(reader);
        let request: Request = read_request(&mut reader, Duration::from_secs(3))
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("helper connection closed before a request was received")
            })?;
        anyhow::ensure!(
            request.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        match request.action {
            Action::Status => {
                write_response(
                    &mut writer,
                    &Response {
                        protocol_version: PROTOCOL_VERSION,
                        result: ResponseResult::Status {
                            allowed_uid: state.allowed_uid,
                        },
                    },
                )
                .await
            }
            Action::Run(operation) => {
                let response = match run_operation(operation, &mut reader, &mut writer).await {
                    Ok(Some(code)) => Response {
                        protocol_version: PROTOCOL_VERSION,
                        result: ResponseResult::Exit { code },
                    },
                    Ok(None) => return Ok(()),
                    Err(error) => Response {
                        protocol_version: PROTOCOL_VERSION,
                        result: ResponseResult::Error(format!("{error:#}")),
                    },
                };
                write_response(&mut writer, &response).await
            }
        }
    }

    async fn run_operation(
        operation: Operation,
        client_reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
    ) -> Result<Option<i32>> {
        validate_operation(&operation)?;
        let current_exe = std::env::current_exe().context("resolve helper executable")?;
        let child = tokio::process::Command::new(current_exe)
            .arg(super::INTERNAL_WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("start probe worker")?;
        run_operation_with_child(operation, client_reader, writer, child).await
    }

    async fn run_operation_with_child(
        operation: Operation,
        client_reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        mut child: tokio::process::Child,
    ) -> Result<Option<i32>> {
        let traceroute = matches!(&operation, Operation::Trace(_));
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("probe worker stdin is unavailable"))?;
        input
            .write_all(&serde_json::to_vec(&operation)?)
            .await
            .context("write probe request")?;
        input.shutdown().await.context("close probe request")?;
        drop(input);

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("probe worker stdout is unavailable"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("probe worker stderr is unavailable"))?;
        let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(64);
        let stdout_task = tokio::spawn(forward_output(
            stdout,
            OutputStream::Stdout,
            output_tx.clone(),
        ));
        let stderr_task = tokio::spawn(forward_output(stderr, OutputStream::Stderr, output_tx));

        let mut status = None;
        let mut output_closed = false;
        loop {
            tokio::select! {
                control = read_frame::<ClientControl>(client_reader, MAX_CONTROL), if status.is_none() => {
                    match control? {
                        Some(ClientControl::Cancel) => {
                            terminate_child(&mut child).await;
                            stdout_task.abort();
                            stderr_task.abort();
                            return Ok(Some(130));
                        }
                        None => {
                            terminate_child(&mut child).await;
                            stdout_task.abort();
                            stderr_task.abort();
                            return Ok(None);
                        }
                    }
                }
                output = output_rx.recv(), if !output_closed => {
                    match output {
                        Some(output) => {
                            let (stream, data) = output?;
                            write_response(
                                writer,
                                &Response {
                                    protocol_version: PROTOCOL_VERSION,
                                    result: if stream == OutputStream::Stdout && traceroute {
                                        ResponseResult::TraceData { data }
                                    } else {
                                        ResponseResult::Output { stream, data }
                                    },
                                },
                            )
                            .await?;
                        }
                        None => output_closed = true,
                    }
                }
                child_status = child.wait(), if status.is_none() => {
                    status = Some(child_status.context("wait for probe worker")?);
                }
            }
            if output_closed && status.is_some() {
                break;
            }
        }
        let _ = stdout_task.await;
        let _ = stderr_task.await;
        Ok(Some(status.and_then(|status| status.code()).unwrap_or(1)))
    }

    async fn forward_output<R>(
        reader: R,
        stream: OutputStream,
        output: tokio::sync::mpsc::Sender<Result<(OutputStream, String)>>,
    ) where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut lines = BufReader::new(reader).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if output.send(Ok((stream, line))).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = output.send(Err(error.into())).await;
                    return;
                }
            }
        }
    }

    async fn terminate_child(child: &mut tokio::process::Child) {
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.start_kill();
        }
        let _ = child.wait().await;
    }

    async fn send_request(request: Request) -> Result<Response> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let stream = UnixStream::connect(SOCKET_PATH)
                .await
                .context("connect to PingX helper")?;
            let (reader, mut writer) = stream.into_split();
            write_frame(&mut writer, &request).await?;
            let mut reader = BufReader::new(reader);
            read_frame(&mut reader, MAX_RESPONSE)
                .await?
                .ok_or_else(|| anyhow::anyhow!("PingX helper closed the connection"))
        })
        .await
        .map_err(|_| anyhow::anyhow!("PingX helper did not respond"))?
    }

    async fn read_frame<T: for<'de> Deserialize<'de>>(
        reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
        max: usize,
    ) -> Result<Option<T>> {
        let mut data = Vec::new();
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if data.is_empty() {
                    return Ok(None);
                }
                break;
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let content_len = newline.unwrap_or(available.len());
            anyhow::ensure!(data.len() + content_len <= max, "helper frame is too large");
            data.extend_from_slice(&available[..content_len]);
            let consumed = content_len + usize::from(newline.is_some());
            reader.consume(consumed);
            if newline.is_some() {
                break;
            }
        }
        Ok(Some(serde_json::from_slice(&data)?))
    }

    fn append_json_line(data: &mut String, line_count: &mut usize, line: &str) -> Result<()> {
        let separator = usize::from(*line_count != 0);
        anyhow::ensure!(
            data.len()
                .checked_add(separator)
                .and_then(|size| size.checked_add(line.len()))
                .is_some_and(|size| size <= MAX_JSON_OUTPUT),
            "JSON output exceeds {MAX_JSON_OUTPUT} bytes"
        );
        if separator != 0 {
            data.push('\n');
        }
        data.push_str(line);
        *line_count += 1;
        Ok(())
    }

    async fn read_request(
        reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
        timeout: Duration,
    ) -> Result<Option<Request>> {
        tokio::time::timeout(timeout, read_frame(reader, MAX_REQUEST))
            .await
            .map_err(|_| anyhow::anyhow!("helper request timed out"))?
    }

    async fn write_frame<T: Serialize>(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        value: &T,
    ) -> Result<()> {
        write_frame_with_limit(writer, value, MAX_REQUEST).await
    }

    async fn write_response<T: Serialize>(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        value: &T,
    ) -> Result<()> {
        write_frame_with_limit(writer, value, MAX_RESPONSE).await
    }

    async fn write_frame_with_limit<T: Serialize>(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        value: &T,
        max: usize,
    ) -> Result<()> {
        let data = serde_json::to_vec(value)?;
        anyhow::ensure!(data.len() <= max, "helper frame is too large");
        writer.write_all(&data).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        Ok(())
    }

    fn read_state() -> Result<HelperState> {
        let file = open_state(Path::new(STATE_PATH))?;
        serde_json::from_reader(file).context("read helper state")
    }

    fn open_state(path: &Path) -> Result<File> {
        let file = open_regular_file(path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.uid() == 0,
            "helper state is not a root-owned regular file"
        );
        Ok(file)
    }

    fn ensure_root_directory(path: &Path) -> Result<()> {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
        let metadata = fs::symlink_metadata(path)?;
        validate_install_directory(path, &metadata, 0)
    }

    fn open_current_executable() -> Result<File> {
        let path = std::env::current_exe().context("resolve current executable")?;
        open_executable(&path)
    }

    fn open_executable(path: &Path) -> Result<File> {
        open_regular_file(path).with_context(|| "current executable is not a regular file")
    }

    fn open_regular_file(path: &Path) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        anyhow::ensure!(file.metadata()?.is_file(), "not a regular file");
        Ok(file)
    }

    fn validate_install_directory(path: &Path, metadata: &fs::Metadata, owner: u32) -> Result<()> {
        anyhow::ensure!(
            metadata.is_dir()
                && metadata.uid() == owner
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o022 == 0,
            "{} is not a secure root-owned directory",
            path.display()
        );
        Ok(())
    }

    struct StagedInstall {
        target: PathBuf,
        temporary: PathBuf,
        backup_path: PathBuf,
        backup: Option<PathBuf>,
        installed: bool,
    }

    impl StagedInstall {
        fn restore(&mut self) {
            if !self.installed {
                return;
            }
            if let Some(backup) = self.backup.take() {
                let _ = fs::rename(backup, &self.target);
            } else {
                let _ = fs::remove_file(&self.target);
            }
            self.installed = false;
        }
    }

    impl Drop for StagedInstall {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.temporary);
            self.restore();
        }
    }

    fn stage_install<F>(
        staged: &mut Vec<StagedInstall>,
        path: &Path,
        mode: u32,
        write: F,
    ) -> Result<()>
    where
        F: FnOnce(&mut File) -> io::Result<()>,
    {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid installation path {}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("invalid installation filename {}", path.display()))?;
        let temporary = parent.join(format!(".{LABEL}.{name}.tmp.{}", std::process::id()));
        let backup = parent.join(format!(".{LABEL}.{name}.old.{}", std::process::id()));
        for path in [&temporary, &backup] {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("remove {}", path.display()));
                }
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
        staged.push(StagedInstall {
            target: path.to_path_buf(),
            temporary,
            backup_path: backup,
            backup: None,
            installed: false,
        });
        Ok(())
    }

    fn commit_install(staged: &mut [StagedInstall]) -> Result<()> {
        for (replaced, item) in staged.iter_mut().enumerate() {
            let backup = item.backup_path.clone();
            let target = item.target.clone();
            item.backup = match fs::rename(&target, &backup) {
                Ok(()) => Some(backup),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| format!("back up {}", target.display()));
                }
            };
            if let Err(error) = fs::rename(&item.temporary, &target) {
                if let Some(backup) = &item.backup {
                    let _ = fs::rename(backup, &target);
                }
                item.installed = false;
                let _ = fs::remove_file(&item.temporary);
                rollback_install(&mut staged[..replaced]);
                return Err(error).with_context(|| format!("replace {}", target.display()));
            }
            item.installed = true;
            if let Err(error) =
                File::open(target.parent().unwrap()).and_then(|file| file.sync_all())
            {
                item.installed = false;
                if let Some(backup) = &item.backup {
                    let _ = fs::rename(backup, &target);
                } else {
                    let _ = fs::remove_file(&target);
                }
                let _ = fs::remove_file(&item.temporary);
                rollback_install(&mut staged[..replaced]);
                return Err(error).with_context(|| format!("sync {}", target.display()));
            }
        }
        Ok(())
    }

    fn finalize_install(staged: &mut [StagedInstall]) -> Result<()> {
        for item in staged.iter_mut() {
            item.installed = false;
        }
        for item in staged {
            if let Some(backup) = item.backup.take() {
                match fs::remove_file(backup) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(error).context("remove previous helper file");
                    }
                }
            }
            let _ = fs::remove_file(&item.temporary);
        }
        Ok(())
    }

    fn rollback_install(staged: &mut [StagedInstall]) {
        for item in staged.iter_mut().rev() {
            item.restore();
            let _ = fs::remove_file(&item.temporary);
        }
    }

    fn launchd_plist(allowed_uid: u32) -> Result<String> {
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
      <key>SockPathOwner</key><integer>{allowed_uid}</integer>
      <key>SockPathMode</key><integer>384</integer>
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

        fn ping_operation() -> PingOperation {
            PingOperation {
                targets: vec!["127.0.0.1".to_string()],
                count: Some(1),
                interval_ns: 1,
                timeout_ns: 1,
                deadline_ns: None,
                ttl: 64,
                size: 56,
                quiet: false,
                interface: None,
                ipv4: false,
                ipv6: false,
                tcp: true,
                udp: false,
                json: true,
                json_file: true,
            }
        }

        fn cli_with_targets(targets: &[&str]) -> Cli {
            Cli {
                targets: targets.iter().map(|target| (*target).to_string()).collect(),
                count: Some(1),
                interval: Duration::from_secs(1),
                timeout: Duration::from_secs(1),
                deadline: None,
                ttl: 64,
                size: Some(56),
                quiet: false,
                interface: None,
                ipv4: false,
                ipv6: false,
                tcp: false,
                udp: false,
                http: false,
                headers: Vec::new(),
                geo: false,
                fetch_geo: false,
                json: None,
                traceroute: false,
                max_hops: crate::cli::DEFAULT_TRACEROUTE_MAX_HOPS,
            }
        }

        #[test]
        fn launchd_plist_uses_the_activation_socket() {
            let plist = launchd_plist(501).unwrap();
            assert!(plist.contains(LABEL));
            assert!(plist.contains(SOCKET_PATH));
            assert!(plist.contains(super::super::INTERNAL_DAEMON_ARG));
            assert!(plist.contains("<key>SockPathOwner</key><integer>501</integer>"));
            assert!(plist.contains("<key>SockPathMode</key><integer>384</integer>"));
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

        #[test]
        fn root_copy_runs_the_opened_executable_after_its_path_changes() {
            let root = std::env::temp_dir().join(format!(
                "pingx-helper-open-executable-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let path = root.join("pingx");
            fs::write(&path, "#!/bin/sh\nprintf 'opened-file\\n'").unwrap();
            let input = open_executable(&path).unwrap();
            let replacement = root.join("replacement");
            fs::write(&replacement, "#!/bin/sh\nprintf 'replaced-file\\n'").unwrap();
            fs::rename(replacement, &path).unwrap();
            let output = Command::new("/bin/sh")
                .args(["-c", ROOT_COPY_SCRIPT, "pingx-helper"])
                .stdin(Stdio::from(input))
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, b"opened-file\n");
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn helper_source_must_not_be_a_symlink() {
            let root = std::env::temp_dir().join(format!(
                "pingx-helper-source-symlink-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let file = root.join("pingx");
            let link = root.join("link");
            fs::write(&file, "binary").unwrap();
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(open_executable(&link).is_err());
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn state_uses_the_opened_file_after_its_path_changes() {
            let root = std::env::temp_dir()
                .join(format!("pingx-helper-state-replace-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let path = root.join("helper.json");
            fs::write(&path, br#"{"protocol_version":3,"allowed_uid":501}"#).unwrap();
            let file = open_regular_file(&path).unwrap();
            let replacement = root.join("replacement.json");
            fs::write(&replacement, br#"{"protocol_version":3,"allowed_uid":123}"#).unwrap();
            fs::rename(replacement, &path).unwrap();
            let state = serde_json::from_reader::<_, HelperState>(file).unwrap();
            assert_eq!(state.allowed_uid, 501);
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn install_directories_must_be_private_and_regular() {
            let root =
                std::env::temp_dir().join(format!("pingx-helper-directory-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            let owner = fs::symlink_metadata(&root).unwrap().uid();
            assert!(
                validate_install_directory(&root, &fs::symlink_metadata(&root).unwrap(), owner)
                    .is_ok()
            );

            fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(
                validate_install_directory(&root, &fs::symlink_metadata(&root).unwrap(), owner)
                    .is_err()
            );

            let link = root.join("link");
            std::os::unix::fs::symlink(&root, &link).unwrap();
            assert!(
                validate_install_directory(&link, &fs::symlink_metadata(&link).unwrap(), owner)
                    .is_err()
            );
            let _ = fs::remove_dir_all(&root);
        }

        fn temporary_files(paths: &[&Path]) -> Vec<PathBuf> {
            paths
                .iter()
                .flat_map(|path| {
                    let parent = path.parent().unwrap();
                    let name = path.file_name().unwrap().to_str().unwrap();
                    ["tmp", "old"].map(|suffix| {
                        parent.join(format!(".{LABEL}.{name}.{}.{}", suffix, std::process::id()))
                    })
                })
                .collect()
        }

        #[test]
        fn staged_install_replaces_all_files() {
            let root =
                std::env::temp_dir().join(format!("pingx-helper-install-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let paths = [root.join("helper"), root.join("plist"), root.join("state")];
            for (index, path) in paths.iter().enumerate() {
                fs::write(path, format!("old {index}")).unwrap();
            }
            let mut staged = Vec::new();
            for (index, path) in paths.iter().enumerate() {
                stage_install(&mut staged, path, 0o644, |output| {
                    output.write_all(format!("new {index}").as_bytes())
                })
                .unwrap();
            }
            commit_install(&mut staged).unwrap();
            assert!(
                temporary_files(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>())
                    .iter()
                    .filter(|path| path.extension().is_some_and(|extension| extension == "old"))
                    .all(|path| path.exists())
            );
            finalize_install(&mut staged).unwrap();
            for (index, path) in paths.iter().enumerate() {
                assert_eq!(fs::read_to_string(path).unwrap(), format!("new {index}"));
            }
            assert!(
                temporary_files(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>())
                    .iter()
                    .all(|path| !path.exists())
            );
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn staged_install_rolls_back_a_failed_commit() {
            let root =
                std::env::temp_dir().join(format!("pingx-helper-rollback-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let paths = [root.join("first"), root.join("second")];
            fs::write(&paths[0], "old first").unwrap();
            fs::write(&paths[1], "old second").unwrap();
            let mut staged = Vec::new();
            stage_install(&mut staged, &paths[0], 0o644, |output| {
                output.write_all(b"new first")
            })
            .unwrap();
            stage_install(&mut staged, &paths[1], 0o644, |output| {
                output.write_all(b"new second")
            })
            .unwrap();
            fs::remove_file(&paths[1]).unwrap();
            staged[1].temporary = root.join("missing");
            assert!(commit_install(&mut staged).is_err());
            assert_eq!(fs::read_to_string(&paths[0]).unwrap(), "old first");
            assert!(!paths[1].exists());
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn staged_install_removes_a_new_file_after_a_later_failure() {
            let root = std::env::temp_dir().join(format!(
                "pingx-helper-new-file-rollback-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let paths = [root.join("first"), root.join("second")];
            let mut staged = Vec::new();
            stage_install(&mut staged, &paths[0], 0o644, |output| {
                output.write_all(b"new first")
            })
            .unwrap();
            stage_install(&mut staged, &paths[1], 0o644, |output| {
                output.write_all(b"new second")
            })
            .unwrap();
            staged[1].target = root.join("missing/target");
            assert!(commit_install(&mut staged).is_err());
            assert!(!paths[0].exists());
            assert!(
                temporary_files(&paths.iter().map(PathBuf::as_path).collect::<Vec<_>>())
                    .iter()
                    .all(|path| !path.exists())
            );
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn failed_service_start_restores_files_and_the_previous_service() {
            let root = std::env::temp_dir().join(format!(
                "pingx-helper-service-rollback-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let path = root.join("helper");
            fs::write(&path, "old helper").unwrap();
            let mut staged = Vec::new();
            stage_install(&mut staged, &path, 0o644, |output| {
                output.write_all(b"new helper")
            })
            .unwrap();

            let mut restored_service = false;
            assert!(
                activate_install(
                    &mut staged,
                    || Ok(()),
                    || {
                        restored_service = true;
                        anyhow::bail!("service did not start")
                    }
                )
                .is_err()
            );
            assert!(restored_service);
            assert_eq!(fs::read_to_string(&path).unwrap(), "old helper");
            assert!(
                temporary_files(&[path.as_path()])
                    .iter()
                    .all(|path| !path.exists())
            );
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn failed_commit_restores_files_before_the_previous_service() {
            let root = std::env::temp_dir()
                .join(format!("pingx-helper-commit-order-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir(&root).unwrap();
            let paths = [root.join("first"), root.join("second")];
            fs::write(&paths[0], "old first").unwrap();
            fs::write(&paths[1], "old second").unwrap();
            let mut staged = Vec::new();
            for (index, path) in paths.iter().enumerate() {
                stage_install(&mut staged, path, 0o644, |output| {
                    output.write_all(format!("new {index}").as_bytes())
                })
                .unwrap();
            }
            staged[1].backup_path = root.join("blocked");
            fs::create_dir(&staged[1].backup_path).unwrap();

            let mut service_restored = false;
            assert!(
                activate_install(
                    &mut staged,
                    || {
                        service_restored = true;
                        assert_eq!(fs::read_to_string(&paths[0]).unwrap(), "old first");
                        assert_eq!(fs::read_to_string(&paths[1]).unwrap(), "old second");
                        Ok(())
                    },
                    || Ok(()),
                )
                .is_err()
            );
            assert!(service_restored);
            let _ = fs::remove_dir_all(&root);
        }

        #[test]
        fn worker_json_output_cannot_choose_a_file_path() {
            let cli = ping_operation().to_cli();
            assert_eq!(cli.json, Some(None));
        }

        fn sleeping_worker() -> tokio::process::Child {
            tokio::process::Command::new("/bin/sleep")
                .arg("60")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap()
        }

        #[tokio::test]
        async fn client_disconnect_terminates_the_worker() {
            let (client, server) = UnixStream::pair().unwrap();
            let (reader, mut writer) = server.into_split();
            let mut client_reader = BufReader::new(reader);
            drop(client);
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                run_operation_with_child(
                    Operation::Ping(ping_operation()),
                    &mut client_reader,
                    &mut writer,
                    sleeping_worker(),
                ),
            )
            .await
            .expect("disconnect should stop the worker promptly")
            .unwrap();
            assert_eq!(result, None);
        }

        #[tokio::test]
        async fn client_cancel_terminates_the_worker() {
            let (client, server) = UnixStream::pair().unwrap();
            let (reader, mut writer) = server.into_split();
            let (_, mut client_writer) = client.into_split();
            write_frame(&mut client_writer, &ClientControl::Cancel)
                .await
                .unwrap();
            let mut client_reader = BufReader::new(reader);
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                run_operation_with_child(
                    Operation::Ping(ping_operation()),
                    &mut client_reader,
                    &mut writer,
                    sleeping_worker(),
                ),
            )
            .await
            .expect("cancel should stop the worker promptly")
            .unwrap();
            assert_eq!(result, Some(130));
        }

        #[test]
        fn invalid_operations_are_rejected() {
            let mut operation = Operation::Ping(ping_operation());
            validate_operation(&operation).unwrap();

            {
                let Operation::Ping(ping) = &mut operation else {
                    unreachable!()
                };
                ping.interval_ns = 0;
            }
            assert!(validate_operation(&operation).is_err());

            {
                let Operation::Ping(ping) = &mut operation else {
                    unreachable!()
                };
                ping.interval_ns = 1;
                ping.targets = vec!["https://example.com".to_string()];
            }
            assert!(validate_operation(&operation).is_err());

            {
                let Operation::Ping(ping) = &mut operation else {
                    unreachable!()
                };
                ping.targets = vec!["127.0.0.1".to_string()];
                ping.ipv4 = true;
                ping.ipv6 = true;
            }
            assert!(validate_operation(&operation).is_err());

            {
                let Operation::Ping(ping) = &mut operation else {
                    unreachable!()
                };
                ping.ipv6 = false;
                ping.json = false;
            }
            assert!(validate_operation(&operation).is_err());

            {
                let Operation::Ping(ping) = &mut operation else {
                    unreachable!()
                };
                ping.json = true;
                ping.tcp = false;
                ping.udp = true;
                ping.size = crate::probe::udp_error::MAX_UDP_PAYLOAD + 1;
            }
            assert!(validate_operation(&operation).is_err());
        }

        #[test]
        fn helper_routes_only_privileged_ping_modes() {
            use crate::cli::Protocol;

            assert!(!protocol_needs_helper(&Protocol::Icmp, true));
            assert!(protocol_needs_helper(&Protocol::Icmp, false));
            assert!(protocol_needs_helper(&Protocol::Tcp(443), true));
            assert!(protocol_needs_helper(&Protocol::Udp(33434), true));
            assert!(!protocol_needs_helper(
                &Protocol::Http("https://example.com".to_string()),
                false
            ));
        }

        #[test]
        fn helper_request_keeps_mixed_non_http_targets_together() {
            let cli = cli_with_targets(&["127.0.0.1", "127.0.0.1:1"]);
            let operation = operation_from_cli(&cli).unwrap().unwrap();
            let Operation::Ping(ping) = operation else {
                panic!("expected ping operation")
            };
            assert_eq!(ping.targets, cli.targets);

            let cli = cli_with_targets(&["127.0.0.1:1", "https://example.com"]);
            assert!(operation_from_cli(&cli).is_err());
        }

        #[tokio::test]
        async fn helper_frames_reject_oversized_input() {
            let (mut client, server) = UnixStream::pair().unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut client, b"12345\n")
                .await
                .unwrap();
            let (reader, _) = server.into_split();
            let mut reader = BufReader::new(reader);
            assert!(read_frame::<ClientControl>(&mut reader, 4).await.is_err());
        }

        #[tokio::test]
        async fn helper_requests_have_a_deadline() {
            let (_client, server) = UnixStream::pair().unwrap();
            let (reader, _) = server.into_split();
            let mut reader = BufReader::new(reader);
            let error = read_request(&mut reader, Duration::from_millis(10))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("timed out"));
        }

        #[tokio::test]
        async fn helper_responses_use_the_response_frame_limit() {
            let (mut client, server) = UnixStream::pair().unwrap();
            let response = Response {
                protocol_version: PROTOCOL_VERSION,
                result: ResponseResult::Output {
                    stream: OutputStream::Stdout,
                    data: "x".repeat(MAX_REQUEST),
                },
            };
            let task = tokio::spawn(async move {
                let mut writer = server.into_split().1;
                write_response(&mut writer, &response).await
            });
            let mut line = String::new();
            BufReader::new(&mut client)
                .read_line(&mut line)
                .await
                .unwrap();
            assert!(line.len() > MAX_REQUEST);
            task.await.unwrap().unwrap();
        }

        #[test]
        fn json_lines_preserve_empty_output_and_bound_accumulation() {
            let mut data = String::new();
            let mut lines = 0;
            append_json_line(&mut data, &mut lines, "").unwrap();
            assert!(data.is_empty());
            assert_eq!(lines, 1);

            append_json_line(&mut data, &mut lines, "{}").unwrap();
            assert_eq!(data, "\n{}");
            assert_eq!(lines, 2);

            data = "x".repeat(MAX_JSON_OUTPUT);
            assert!(append_json_line(&mut data, &mut lines, "x").is_err());
        }

        #[test]
        fn traceroute_stdout_is_returned_as_data() {
            let response = ResponseResult::TraceData {
                data: "{\"rows\":[]}".to_string(),
            };
            let encoded = serde_json::to_string(&response).unwrap();
            assert!(encoded.contains("TraceData"));
            assert!(matches!(
                serde_json::from_str::<ResponseResult>(&encoded).unwrap(),
                ResponseResult::TraceData { data } if data == "{\"rows\":[]}"
            ));
        }

        #[tokio::test]
        async fn helper_status_is_scoped_to_the_peer_uid() {
            let (client, server) = UnixStream::pair().unwrap();
            let allowed_uid = unsafe { libc::geteuid() } as u32;
            let task = tokio::spawn(async move {
                handle_connection(
                    server,
                    &HelperState {
                        protocol_version: PROTOCOL_VERSION,
                        allowed_uid,
                    },
                )
                .await
            });
            let (reader, mut writer) = client.into_split();
            write_frame(
                &mut writer,
                &Request {
                    protocol_version: PROTOCOL_VERSION,
                    action: Action::Status,
                },
            )
            .await
            .unwrap();
            drop(writer);
            let mut reader = BufReader::new(reader);
            let response = read_frame::<Response>(&mut reader, MAX_RESPONSE)
                .await
                .unwrap()
                .unwrap();
            match response.result {
                ResponseResult::Status {
                    allowed_uid: reported,
                } => {
                    assert_eq!(reported, allowed_uid);
                }
                other => panic!("unexpected helper response: {other:?}"),
            }
            task.await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn helper_rejects_an_unauthorized_peer_uid() {
            let (_client, server) = UnixStream::pair().unwrap();
            let allowed_uid = (unsafe { libc::geteuid() } as u32).wrapping_add(1);
            let error = handle_connection(
                server,
                &HelperState {
                    protocol_version: PROTOCOL_VERSION,
                    allowed_uid,
                },
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("not authorized"));
        }

        #[tokio::test]
        async fn helper_rejects_a_protocol_version_mismatch() {
            let (client, server) = UnixStream::pair().unwrap();
            let task = tokio::spawn(async move {
                handle_connection(
                    server,
                    &HelperState {
                        protocol_version: PROTOCOL_VERSION,
                        allowed_uid: unsafe { libc::geteuid() } as u32,
                    },
                )
                .await
            });
            let (_reader, mut writer) = client.into_split();
            write_frame(
                &mut writer,
                &Request {
                    protocol_version: PROTOCOL_VERSION.wrapping_add(1),
                    action: Action::Status,
                },
            )
            .await
            .unwrap();
            drop(writer);
            let error = task.await.unwrap().unwrap_err();
            assert!(
                error.to_string().contains("protocol version mismatch"),
                "{error:#}"
            );
        }

        #[tokio::test]
        async fn daemon_exits_after_its_last_session() {
            let path =
                std::env::temp_dir().join(format!("pingx-helper-daemon-{}", std::process::id()));
            let _ = fs::remove_file(&path);
            let listener = UnixListener::bind(&path).unwrap();
            let allowed_uid = unsafe { libc::geteuid() } as u32;
            let state = HelperState {
                protocol_version: PROTOCOL_VERSION,
                allowed_uid,
            };
            let daemon = tokio::spawn(serve(listener, state));
            let stream = UnixStream::connect(&path).await.unwrap();
            let (reader, mut writer) = stream.into_split();
            write_frame(
                &mut writer,
                &Request {
                    protocol_version: PROTOCOL_VERSION,
                    action: Action::Status,
                },
            )
            .await
            .unwrap();
            drop(writer);
            let mut reader = BufReader::new(reader);
            let response = read_frame::<Response>(&mut reader, MAX_RESPONSE)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                response.result,
                ResponseResult::Status { allowed_uid: reported } if reported == allowed_uid
            ));
            tokio::time::timeout(Duration::from_secs(4), daemon)
                .await
                .expect("daemon should exit after its last session")
                .unwrap()
                .unwrap();
            let _ = fs::remove_file(&path);
        }
    }
}
