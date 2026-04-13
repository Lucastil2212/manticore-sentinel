use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use serde_json::Value;

use crate::security::auth::AuthMode;

#[derive(Clone)]
pub struct EventStreamOutput {
    sender: Sender<String>,
}

impl EventStreamOutput {
    pub fn start(
        port: u16,
        auth_mode: AuthMode,
        token_secret: Option<String>,
        evrus_jwt: Option<String>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        listener.set_nonblocking(true)?;
        let (tx, rx) = mpsc::channel::<String>();
        thread::spawn(move || serve(listener, rx, auth_mode, token_secret, evrus_jwt));
        Ok(Self { sender: tx })
    }

    pub fn emit_json(&self, event_type: &str, payload: &Value) {
        let body = serde_json::json!({
            "type": event_type,
            "payload": payload,
        });
        let _ = self.sender.send(body.to_string());
    }
}

fn serve(
    listener: TcpListener,
    rx: Receiver<String>,
    auth_mode: AuthMode,
    token_secret: Option<String>,
    evrus_jwt: Option<String>,
) {
    let mut clients: Vec<TcpStream> = Vec::new();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if authorize_client(&mut stream, auth_mode, token_secret.as_deref(), evrus_jwt.as_deref()).is_ok()
                {
                    let _ = stream.set_nonblocking(true);
                    clients.push(stream);
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => {
                let frame = format!("event: telemetry\ndata: {event}\n\n");
                clients.retain_mut(|c| c.write_all(frame.as_bytes()).is_ok());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn authorize_client(
    stream: &mut TcpStream,
    auth_mode: AuthMode,
    token_secret: Option<&str>,
    evrus_jwt: Option<&str>,
) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let mut auth_header: Option<String> = None;
    reader.read_line(&mut line)?;
    loop {
        line.clear();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("authorization") {
                auth_header = Some(v.trim().to_string());
            }
        }
    }

    match auth_mode {
        AuthMode::Local => {}
        AuthMode::Token => {
            let expected = token_secret.unwrap_or_default();
            let provided = auth_header
                .as_deref()
                .and_then(|h| h.strip_prefix("Bearer "))
                .unwrap_or_default();
            if provided != expected {
                anyhow::bail!("token auth failed");
            }
        }
        AuthMode::Evrus => {
            let expected = evrus_jwt.unwrap_or_default();
            let provided = auth_header
                .as_deref()
                .and_then(|h| h.strip_prefix("Bearer "))
                .unwrap_or_default();
            if provided != expected {
                anyhow::bail!("evrus auth failed");
            }
        }
    }

    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
    )?;
    Ok(())
}
