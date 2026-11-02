use serde_json::Value;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Output, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::oneshot;

const CHILD_TIMEOUT: Duration = Duration::from_secs(5);

fn ping_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pingx"));
    command
        .args(["-H", "--json", "-c", "10", "-i", "0.01", "-W", "2"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn parse_ping_json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "pingx failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON output: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

async fn silent_http_server() -> (SocketAddr, oneshot::Receiver<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    tokio::spawn(async move {
        let mut accepted_tx = Some(accepted_tx);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            if let Some(tx) = accepted_tx.take() {
                let _ = tx.send(());
            }
            tokio::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            });
        }
    });
    (addr, accepted_rx)
}

async fn responding_http_server(status: u16) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

async fn run_command(command: &mut Command) -> Output {
    tokio::time::timeout(CHILD_TIMEOUT, command.output())
        .await
        .expect("pingx command timed out")
        .unwrap()
}

#[tokio::test]
async fn deadline_counts_an_inflight_probe_as_sent() {
    let (addr, _accepted) = silent_http_server().await;
    let url = format!("http://{addr}/");
    let mut command = ping_command();
    command.args(["-w", "0.1", url.as_str()]);

    let output = run_command(&mut command).await;
    let json = parse_ping_json(&output);

    assert!(json["sent"].as_u64().unwrap() >= 1);
    assert_eq!(json["received"].as_u64(), Some(0));
    assert_eq!(json["loss"].as_f64(), Some(100.0));
}

#[cfg(unix)]
#[tokio::test]
async fn ctrl_c_counts_an_inflight_probe_as_sent() {
    let (addr, accepted) = silent_http_server().await;
    let url = format!("http://{addr}/");
    let mut command = ping_command();
    command.arg(url.as_str());
    let child = command.spawn().unwrap();
    let pid = child.id().unwrap();

    tokio::time::timeout(Duration::from_secs(2), accepted)
        .await
        .expect("pingx did not start its first HTTP probe")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) }, 0);

    let output = match tokio::time::timeout(CHILD_TIMEOUT, child.wait_with_output()).await {
        Ok(output) => output.unwrap(),
        Err(_) => {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            panic!("pingx did not exit after SIGINT");
        }
    };
    let json = parse_ping_json(&output);

    assert!(json["sent"].as_u64().unwrap() >= 1);
    assert_eq!(json["received"].as_u64(), Some(0));
}

#[tokio::test]
async fn duplicate_targets_produce_one_json_result() {
    let addr = responding_http_server(200).await;
    let url = format!("http://{addr}/");
    let mut command = ping_command();
    command.args(["-c", "1", url.as_str(), url.as_str()]);

    let output = run_command(&mut command).await;
    let json = parse_ping_json(&output);

    assert!(json.is_object());
    assert_eq!(json["target"].as_str(), Some(url.as_str()));
    assert_eq!(json["sent"].as_u64(), Some(1));
    assert_eq!(json["received"].as_u64(), Some(1));
}
