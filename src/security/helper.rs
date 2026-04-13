use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use nix::{
    libc,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::security::audit::{append_event, now_ts, AuditEvent};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Capability {
    KillProcess,
    ReniceProcess,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelperRequest {
    pub action: String,
    pub pid: u32,
    pub nice: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
}

pub struct HelperServer {
    pub socket_path: PathBuf,
    _thread: JoinHandle<()>,
}

pub struct HelperRuntime {
    pub socket_path: PathBuf,
    pub audit_path: PathBuf,
    _embedded: Option<HelperServer>,
    child: Option<Child>,
}

impl HelperServer {
    pub fn spawn(socket_path: PathBuf, audit_path: PathBuf, capabilities: Vec<Capability>) -> anyhow::Result<Self> {
        if socket_path.exists() {
            let _ = fs::remove_file(&socket_path);
        }
        let listener = UnixListener::bind(&socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));
        }

        let audit_path_for_thread = audit_path.clone();
        let thread = thread::spawn(move || serve(listener, audit_path_for_thread, capabilities));

        Ok(Self {
            socket_path,
            _thread: thread,
        })
    }
}

impl Drop for HelperServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
    }
}

impl HelperRuntime {
    pub fn start_embedded(socket_path: PathBuf, audit_path: PathBuf, capabilities: Vec<Capability>) -> anyhow::Result<Self> {
        let server = HelperServer::spawn(socket_path.clone(), audit_path.clone(), capabilities)?;
        Ok(Self {
            socket_path,
            audit_path,
            _embedded: Some(server),
            child: None,
        })
    }

    pub fn start_subprocess(socket_path: PathBuf, audit_path: PathBuf, capabilities: Vec<Capability>) -> anyhow::Result<Self> {
        if socket_path.exists() {
            let _ = fs::remove_file(&socket_path);
        }
        let caps = serialize_capabilities(&capabilities);
        let exe = std::env::current_exe()?;
        let child = Command::new(exe)
            .arg("--helper-daemon")
            .env("MANTICORE_HELPER_SOCKET", &socket_path)
            .env("MANTICORE_HELPER_AUDIT", &audit_path)
            .env("MANTICORE_HELPER_CAPS", caps)
            .spawn()?;
        info!(socket = %socket_path.display(), "helper subprocess spawned");

        wait_for_startup(&socket_path)?;
        let health = send_request(
            &socket_path,
            &HelperRequest {
                action: "healthcheck".to_string(),
                pid: 0,
                nice: None,
            },
        )?;
        if !health.ok {
            error!(message = %health.message, "helper healthcheck failed");
            return Err(anyhow::anyhow!("helper healthcheck failed: {}", health.message));
        }
        info!("helper subprocess healthcheck passed");

        Ok(Self {
            socket_path,
            audit_path,
            _embedded: None,
            child: Some(child),
        })
    }
}

impl Drop for HelperRuntime {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

pub fn send_request(socket_path: &Path, req: &HelperRequest) -> anyhow::Result<HelperResponse> {
    let mut stream = UnixStream::connect(socket_path)?;
    let payload = serde_json::to_string(req)?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim_end())?)
}

fn read_request(stream: &mut UnixStream) -> anyhow::Result<HelperRequest> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim_end())?)
}

fn write_response(stream: &mut UnixStream, response: &HelperResponse) -> anyhow::Result<()> {
    let payload = serde_json::to_string(response)?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn serve(listener: UnixListener, audit_path: PathBuf, capabilities: Vec<Capability>) {
    info!(socket = ?listener.local_addr().ok(), "helper service loop started");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let request = read_request(&mut stream);
        let response = match request {
            Ok(req) => {
                debug!(action = %req.action, pid = req.pid, "helper request received");
                let resp = handle_request(&req, &capabilities);
                let _ = append_event(
                    &audit_path,
                    &AuditEvent {
                        ts: now_ts(),
                        action: req.action.clone(),
                        target: format!("pid:{}", req.pid),
                        result: if resp.ok {
                            format!("ok: {}", resp.message)
                        } else {
                            format!("denied: {}", resp.message)
                        },
                        actor: "operator".to_string(),
                        sig: None,
                    },
                );
                resp
            }
            Err(err) => HelperResponse {
                ok: false,
                message: format!("invalid request: {err}"),
            },
        };
        if !response.ok {
            warn!(message = %response.message, "helper request denied");
        }
        let _ = write_response(&mut stream, &response);
    }
}

fn handle_request(req: &HelperRequest, caps: &[Capability]) -> HelperResponse {
    match req.action.as_str() {
        "healthcheck" => allow("ready".to_string()),
        "kill_process" => {
            if !caps.contains(&Capability::KillProcess) {
                return deny("missing capability KillProcess");
            }
            if req.pid <= 1 {
                return deny("refusing to signal protected pid");
            }
            let pid = Pid::from_raw(req.pid as i32);
            match kill(pid, Signal::SIGTERM) {
                Ok(_) => allow(format!("sent SIGTERM to pid {}", req.pid)),
                Err(err) => deny(format!("kill failed: {err}").as_str()),
            }
        }
        "renice_process" => {
            if !caps.contains(&Capability::ReniceProcess) {
                return deny("missing capability ReniceProcess");
            }
            let nice = match req.nice {
                Some(v) if (-20..=19).contains(&v) => v,
                _ => return deny("invalid nice value"),
            };
            match set_priority(req.pid, nice) {
                Ok(_) => allow(format!("set pid {} nice {}", req.pid, nice)),
                Err(err) => deny(format!("renice failed: {err}").as_str()),
            }
        }
        _ => deny("unknown action"),
    }
}

fn allow(message: String) -> HelperResponse {
    HelperResponse { ok: true, message }
}

fn deny(message: &str) -> HelperResponse {
    HelperResponse {
        ok: false,
        message: message.to_string(),
    }
}

fn set_priority(pid: u32, nice: i32) -> anyhow::Result<()> {
    if pid <= 1 {
        return Err(anyhow::anyhow!("refusing to renice protected pid"));
    }
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid, nice) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

pub fn run_helper_daemon_from_env() -> anyhow::Result<()> {
    let socket_path = std::env::var("MANTICORE_HELPER_SOCKET")
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!("MANTICORE_HELPER_SOCKET missing"))?;
    let audit_path = std::env::var("MANTICORE_HELPER_AUDIT")
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!("MANTICORE_HELPER_AUDIT missing"))?;
    let caps_raw = std::env::var("MANTICORE_HELPER_CAPS").unwrap_or_default();
    let capabilities = parse_capabilities(&caps_raw);

    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }
    let listener = UnixListener::bind(&socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));
    }

    serve(listener, audit_path, capabilities);
    Ok(())
}

fn parse_capabilities(raw: &str) -> Vec<Capability> {
    raw.split(',')
        .filter_map(|item| match item.trim() {
            "kill" => Some(Capability::KillProcess),
            "renice" => Some(Capability::ReniceProcess),
            _ => None,
        })
        .collect()
}

fn serialize_capabilities(capabilities: &[Capability]) -> String {
    let mut parts = Vec::new();
    for cap in capabilities {
        match cap {
            Capability::KillProcess => parts.push("kill"),
            Capability::ReniceProcess => parts.push("renice"),
        }
    }
    parts.join(",")
}

fn wait_for_startup(socket_path: &Path) -> anyhow::Result<()> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if socket_path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(anyhow::anyhow!("helper socket startup timeout"))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, process::Command, thread, time::Duration};

    use super::{send_request, Capability, HelperRequest, HelperServer};

    fn unique_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "manticore-helper-test-{}-{}-{}",
            std::process::id(),
            suffix,
            super::now_ts()
        ));
        p
    }

    fn wait_for_socket(path: &PathBuf) {
        for _ in 0..30 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("socket not ready: {}", path.display());
    }

    #[test]
    fn uds_denies_when_capability_missing() {
        let socket = unique_path("deny.sock");
        let audit = unique_path("deny.jsonl");
        let server = HelperServer::spawn(socket.clone(), audit.clone(), vec![]).expect("spawn helper");
        wait_for_socket(&socket);

        let response = send_request(
            &socket,
            &HelperRequest {
                action: "kill_process".to_string(),
                pid: 999999,
                nice: None,
            },
        )
        .expect("send request");

        assert!(!response.ok);
        assert!(response.message.contains("missing capability"));

        drop(server);
        let _ = fs::remove_file(audit);
    }

    #[test]
    fn uds_rejects_protected_pid() {
        let socket = unique_path("protected.sock");
        let audit = unique_path("protected.jsonl");
        let server = HelperServer::spawn(
            socket.clone(),
            audit.clone(),
            vec![Capability::KillProcess, Capability::ReniceProcess],
        )
        .expect("spawn helper");
        wait_for_socket(&socket);

        let kill_response = send_request(
            &socket,
            &HelperRequest {
                action: "kill_process".to_string(),
                pid: 1,
                nice: None,
            },
        )
        .expect("send kill request");
        assert!(!kill_response.ok);
        assert!(kill_response.message.contains("protected pid"));

        let renice_response = send_request(
            &socket,
            &HelperRequest {
                action: "renice_process".to_string(),
                pid: 1,
                nice: Some(5),
            },
        )
        .expect("send renice request");
        assert!(!renice_response.ok);
        assert!(renice_response.message.contains("protected pid"));

        drop(server);
        let _ = fs::remove_file(audit);
    }

    #[test]
    fn uds_kill_success_path() {
        let socket = unique_path("success.sock");
        let audit = unique_path("success.jsonl");
        let server = HelperServer::spawn(socket.clone(), audit.clone(), vec![Capability::KillProcess])
            .expect("spawn helper");
        wait_for_socket(&socket);

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep process");

        let response = send_request(
            &socket,
            &HelperRequest {
                action: "kill_process".to_string(),
                pid: child.id(),
                nice: None,
            },
        )
        .expect("send request");

        assert!(response.ok, "expected success response, got: {}", response.message);
        let _ = child.wait();

        drop(server);
        let _ = fs::remove_file(audit);
    }
}
