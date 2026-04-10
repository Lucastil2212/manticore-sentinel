use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    thread::{self, JoinHandle},
};

use nix::{
    libc,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use serde::{Deserialize, Serialize};

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
    pub audit_path: PathBuf,
    _thread: JoinHandle<()>,
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
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let request = read_request(&mut stream);
                let response = match request {
                    Ok(req) => {
                        let resp = handle_request(&req, &capabilities);
                        let _ = append_event(
                            &audit_path_for_thread,
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
                            },
                        );
                        resp
                    }
                    Err(err) => HelperResponse {
                        ok: false,
                        message: format!("invalid request: {err}"),
                    },
                };
                let _ = write_response(&mut stream, &response);
            }
        });

        Ok(Self {
            socket_path,
            audit_path,
            _thread: thread,
        })
    }
}

impl Drop for HelperServer {
    fn drop(&mut self) {
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

fn handle_request(req: &HelperRequest, caps: &[Capability]) -> HelperResponse {
    match req.action.as_str() {
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
