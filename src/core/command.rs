#[derive(Debug, Clone)]
pub enum CommandAction {
    ShowCpu,
    ShowMemory,
    ShowDisk,
    ShowNetwork,
    ShowProcesses {
        sort: Option<String>,
        limit: Option<usize>,
    },
    ShowAlerts,
    ShowConfig,
    ShowConnectors,
    ShowAudit {
        last: usize,
    },
    ShowStorage,
    Help {
        topic: Option<String>,
    },
    KillProcess {
        pid: u32,
    },
    ReniceProcess {
        pid: u32,
        nice: i32,
    },
}

fn is_valid_process_sort(sort: &str) -> bool {
    matches!(sort, "cpu" | "rss" | "pid" | "threads")
}

pub fn parse_command(input: &str) -> Result<CommandAction, String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("empty command".to_string());
    }
    if raw.len() > 256 {
        return Err("command too long".to_string());
    }
    if raw.contains('|')
        || raw.contains(';')
        || raw.contains('&')
        || raw.contains('>')
        || raw.contains('<')
    {
        return Err("shell operators are not allowed".to_string());
    }

    let tokens: Vec<&str> = raw.split_whitespace().collect();
    match tokens.as_slice() {
        ["show", "cpu"] => Ok(CommandAction::ShowCpu),
        ["show", "memory"] | ["show", "mem"] => Ok(CommandAction::ShowMemory),
        ["show", "disk"] | ["show", "disks"] => Ok(CommandAction::ShowDisk),
        ["show", "network"] | ["show", "net"] => Ok(CommandAction::ShowNetwork),
        ["show", "processes", rest @ ..] | ["show", "procs", rest @ ..] => {
            let mut sort = None;
            let mut limit = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i] {
                    "--sort" if i + 1 < rest.len() => {
                        let v = rest[i + 1].to_ascii_lowercase();
                        if !is_valid_process_sort(&v) {
                            return Err(
                                "invalid --sort value (expected cpu|rss|pid|threads)".to_string()
                            );
                        }
                        sort = Some(v);
                        i += 2;
                    }
                    "--limit" if i + 1 < rest.len() => {
                        let parsed = rest[i + 1]
                            .parse::<usize>()
                            .map_err(|_| "invalid --limit value".to_string())?;
                        if parsed == 0 {
                            return Err("--limit must be >= 1".to_string());
                        }
                        limit = Some(parsed);
                        i += 2;
                    }
                    _ => return Err(format!("unknown flag: {}", rest[i])),
                }
            }
            Ok(CommandAction::ShowProcesses { sort, limit })
        }
        ["show", "alerts"] => Ok(CommandAction::ShowAlerts),
        ["show", "config"] => Ok(CommandAction::ShowConfig),
        ["show", "connectors"] => Ok(CommandAction::ShowConnectors),
        ["show", "audit"] => Ok(CommandAction::ShowAudit { last: 10 }),
        ["show", "audit", "--last", n] => {
            let last = n
                .parse::<usize>()
                .map_err(|_| "invalid --last value".to_string())?;
            if last == 0 {
                return Err("--last must be >= 1".to_string());
            }
            Ok(CommandAction::ShowAudit {
                last: last.min(200),
            })
        }
        ["show", "storage"] => Ok(CommandAction::ShowStorage),
        ["help"] => Ok(CommandAction::Help { topic: None }),
        ["help", topic] => Ok(CommandAction::Help {
            topic: Some(topic.to_string()),
        }),
        ["kill", pid] => {
            let pid = pid.parse::<u32>().map_err(|_| "invalid pid".to_string())?;
            if pid == 0 {
                return Err("pid must be > 0".to_string());
            }
            Ok(CommandAction::KillProcess { pid })
        }
        ["renice", nice, pid] => {
            let nice = nice
                .parse::<i32>()
                .map_err(|_| "invalid nice value".to_string())?;
            let pid = pid.parse::<u32>().map_err(|_| "invalid pid".to_string())?;
            if pid == 0 {
                return Err("pid must be > 0".to_string());
            }
            if !(-20..=19).contains(&nice) {
                return Err("nice must be between -20 and 19".to_string());
            }
            Ok(CommandAction::ReniceProcess { pid, nice })
        }
        _ => Err("unknown command. Type 'help' for available commands.".to_string()),
    }
}

pub const COMMAND_COMPLETIONS: &[&str] = &[
    "show cpu",
    "show memory",
    "show disk",
    "show network",
    "show processes",
    "show processes --sort cpu",
    "show processes --sort rss",
    "show alerts",
    "show config",
    "show connectors",
    "show audit",
    "show audit --last 50",
    "show storage",
    "help",
    "help commands",
    "help config",
    "help connectors",
    "help auth",
    "help alerts",
    "help audit",
    "help sse",
    "help profiles",
    "kill ",
    "renice ",
];

pub fn help_text(topic: Option<&str>) -> String {
    match topic {
        None => HELP_OVERVIEW.to_string(),
        Some("commands") | Some("command") => HELP_COMMANDS.to_string(),
        Some("config") | Some("configuration") => HELP_CONFIG.to_string(),
        Some("connectors") | Some("connector") => HELP_CONNECTORS.to_string(),
        Some("peerweave") | Some("pw") => HELP_PEERWEAVE.to_string(),
        Some("evrus") => HELP_EVRUS.to_string(),
        Some("auth") | Some("authentication") => HELP_AUTH.to_string(),
        Some("alerts") | Some("alert") => HELP_ALERTS.to_string(),
        Some("audit") => HELP_AUDIT.to_string(),
        Some("sse") | Some("stream") => HELP_SSE.to_string(),
        Some("profiles") | Some("profile") => HELP_PROFILES.to_string(),
        Some(other) => format!(
            "Unknown topic: '{other}'. Available: commands, config, connectors, peerweave, evrus, auth, alerts, audit, sse, profiles"
        ),
    }
}

const HELP_OVERVIEW: &str = "\
Manticore Sentinel — Command Palette

COMMANDS:
  show cpu          CPU metrics (usage, load, per-core)
  show memory       Memory usage (total, used, available)
  show disk         Disk throughput per device
  show network      Network throughput per interface
  show processes    Process table (--sort cpu|rss|pid|threads, --limit N)
  show alerts       Active alert policy matches
  show config       Current effective configuration
  show connectors   Ecosystem connector status
  show audit        Recent audit events (--last N, default 10)
  show storage      File sizes and retention status
  help [topic]      In-app documentation (topics: commands, config, connectors,
                    peerweave, evrus, auth, alerts, audit, sse, profiles)
  kill <pid>        Kill a process (requires confirmation + privilege)
  renice <n> <pid>  Change process priority (-20..19)

Press F1 for Help Center. Press Tab for autocomplete.";

const HELP_COMMANDS: &str = "\
COMMANDS — detailed reference

show cpu
  Displays aggregate CPU usage percent, 1/5/15-minute load averages,
  and per-core utilization.

show memory | show mem
  Displays total, used, and available memory in human-readable units.

show disk | show disks
  Lists all disk devices sorted by combined R+W throughput.

show network | show net
  Lists all network interfaces sorted by combined RX+TX throughput.

show processes [--sort cpu|rss|pid|threads] [--limit N]
  Full process table. Default sort: cpu descending. Limit default: all.

show alerts
  Lists currently firing alert rules with severity and message.

show config
  Displays all effective configuration values including profile,
  auth mode, connectors, retention settings, and feature flags.

show connectors
  Shows health status for PeerWeave and EVRUS connectors.

show audit [--last N]
  Shows the N most recent audit events (default 10, max 200).

show storage
  Displays file sizes, entry counts, and retention config for
  audit events, snapshots, and archive files.

help [topic]
  Shows documentation. Topics: commands, config, connectors,
  peerweave, evrus, auth, alerts, audit, sse, profiles.

kill <pid>
  Sends SIGKILL to the specified process. Requires operator/admin role,
  confirmation prompt, and is audit-logged.

renice <nice> <pid>
  Changes the scheduling priority of a process. Nice range: -20..19.
  Lower = higher priority. Requires operator/admin role.";

const HELP_CONFIG: &str = "\
CONFIGURATION — environment variables

Core:
  MANTICORE_PROFILE             default|dev|secure|ecosystem (default: default)
  MANTICORE_PRIVILEGED          true|false — enable kill/renice (default: false)
  MANTICORE_HELPER_MODE         embedded|subprocess (default: embedded)
  MANTICORE_REFRESH_MS          Poll interval 100-5000ms (default: 500)

Auth:
  MANTICORE_AUTH_MODE            local|token|evrus (default: local)
  MANTICORE_ROLE                 viewer|operator|admin (auto from privileged)
  MANTICORE_AUTH_TOKEN           Required if auth_mode=token (min 12 chars)
  MANTICORE_AUTH_TOKEN_ISSUED_AT Unix timestamp for token lifecycle
  MANTICORE_AUTH_TOKEN_TTL_SECS  60-604800 seconds
  MANTICORE_AUTH_TOKEN_GRACE_SECS 0-600 (default: 30)

Retention:
  MANTICORE_AUDIT_MAX_ENTRIES      500-500000 (default: 10000)
  MANTICORE_AUDIT_ARCHIVE_ENABLED  true|false (default: true)
  MANTICORE_SNAPSHOT_HISTORY_ENABLED  true|false (default: false)
  MANTICORE_SNAPSHOT_HISTORY_MAX_ENTRIES 100-200000 (default: 1000)
  MANTICORE_SNAPSHOT_HISTORY_MAX_AGE_SECS seconds; 0/empty disables
  MANTICORE_SNAPSHOT_HISTORY_MAX_BYTES bytes; 0/empty disables
  MANTICORE_SNAPSHOT_HISTORY_SLIM_RECORDS true|false (default: false)
  MANTICORE_SNAPSHOT_HISTORY_RESET_ON_START true|false (default: false)

SSE:
  MANTICORE_EVENT_STREAM_ENABLED   true|false (default: false)
  MANTICORE_EVENT_STREAM_PORT      port number (default: 9462)

PeerWeave:
  MANTICORE_PEERWEAVE_ENABLED      true|false
  MANTICORE_PEERWEAVE_GRAPHQL_URL  (default: http://localhost:3200/graphql)
  MANTICORE_PEERWEAVE_CAP_TOKEN    CapToken for graph.read
  MANTICORE_PEERWEAVE_POLL_MS      1000-30000 (default: 5000)
  MANTICORE_PEERWEAVE_PUBLISH_ENABLED  true|false
  MANTICORE_PEERWEAVE_PUBLISH_SPACE_ID Space ID for publish
  MANTICORE_PEERWEAVE_PUBLISH_MS   1000-30000 (default: 5000)

EVRUS:
  MANTICORE_EVRUS_ENABLED          true|false
  MANTICORE_EVRUS_OIDC_URL         (default: http://localhost:8790)
  MANTICORE_EVRUS_JWT              EVRUS-issued JWT
  MANTICORE_EVRUS_ANCHOR_ENABLED   true|false
  MANTICORE_EVRUS_ANCHOR_INTERVAL_SECS 30-86400 (default: 300)
  MANTICORE_EVRUS_RPC_URL / _USER / _PASS  Evrmore RPC credentials

Alerts:
  MANTICORE_ALERT_POLICY_JSON      Inline JSON alert policy
  MANTICORE_ALERT_POLICY_PATH      Path to alert policy JSON file";

const HELP_CONNECTORS: &str = "\
CONNECTORS — ecosystem integration

Sentinel optionally connects to PeerWeave and EVRUS to provide a
unified operations console. Connectors are disabled by default.

To enable:
  export MANTICORE_PEERWEAVE_ENABLED=true
  export MANTICORE_EVRUS_ENABLED=true

See 'help peerweave' and 'help evrus' for connector-specific details.

Connector status is shown in the Connectors tab. Use 'show connectors'
from the command palette for a quick check.

All connector communication is outbound HTTP only. Sentinel never
listens for inbound connections from connectors.";

const HELP_PEERWEAVE: &str = "\
PEERWEAVE — graph-based distributed knowledge

PeerWeave provides a GraphQL API for querying node, space, and graph
context. Sentinel reads from PeerWeave to display ecosystem topology.

Required env vars:
  MANTICORE_PEERWEAVE_ENABLED=true
  MANTICORE_PEERWEAVE_GRAPHQL_URL=<url>
  MANTICORE_PEERWEAVE_CAP_TOKEN=<token>

Optional graph publish (write host telemetry as triples):
  MANTICORE_PEERWEAVE_PUBLISH_ENABLED=true
  MANTICORE_PEERWEAVE_PUBLISH_SPACE_ID=<space-id>

Authentication uses CapTokens (capability-based tokens) passed
as Bearer tokens in the Authorization header.";

const HELP_EVRUS: &str = "\
EVRUS — identity, vault, and chain integration

EVRUS provides OIDC-based operator identity and optional Evrmore
blockchain audit anchoring.

Required env vars:
  MANTICORE_EVRUS_ENABLED=true
  MANTICORE_EVRUS_OIDC_URL=<url>
  MANTICORE_EVRUS_JWT=<jwt>

For audit anchoring (writes Merkle root to Evrmore blockchain):
  MANTICORE_EVRUS_ANCHOR_ENABLED=true
  MANTICORE_EVRUS_ANCHOR_INTERVAL_SECS=300
  MANTICORE_EVRUS_RPC_URL=<url>
  MANTICORE_EVRUS_RPC_USER=<user>
  MANTICORE_EVRUS_RPC_PASS=<pass>

When auth_mode=evrus, the JWT is used for operator identity
attribution in audit events (DID from JWT claims).";

const HELP_AUTH: &str = "\
AUTHENTICATION — trust modes and RBAC

Sentinel supports three authentication modes:

local  — No token required. Role set by MANTICORE_ROLE.
         Suitable for single-user desktop use.

token  — Bearer token required for destructive actions.
         Set MANTICORE_AUTH_TOKEN (min 12 chars),
         MANTICORE_AUTH_TOKEN_ISSUED_AT, MANTICORE_AUTH_TOKEN_TTL_SECS.
         Lockout after 3 failed attempts.

evrus  — JWT-based identity via EVRUS OIDC.
         Requires MANTICORE_EVRUS_JWT. Operator identity
         (DID) extracted from JWT claims for audit attribution.

Roles:
  viewer   — Read-only. Cannot kill/renice.
  operator — Can renice. Cannot kill.
  admin    — Full access including kill.

Role is set by MANTICORE_ROLE or auto-detected from MANTICORE_PRIVILEGED.";

const HELP_ALERTS: &str = "\
ALERTS — configurable threshold monitoring

Alert policies define rules that fire when metrics exceed thresholds.
Alerts are evaluated on each collection cycle.

Configure via env vars:
  MANTICORE_ALERT_POLICY_JSON='{\"rules\": [...]}'
  MANTICORE_ALERT_POLICY_PATH=/path/to/alerts.json

Rule format:
  {
    \"id\": \"high-cpu\",
    \"metric\": \"cpu.usage_percent\",
    \"op\": \">\",
    \"threshold\": 90.0,
    \"for_cycles\": 3,
    \"severity\": \"warning\",
    \"message\": \"CPU above 90%\"
  }

Available metrics:
  cpu.usage_percent, memory.used_percent, process.count,
  disk.total_bytes_per_sec, network.total_bytes_per_sec

Severities: info, warning, critical
The for_cycles field requires the condition to persist for N consecutive
cycles before firing (debounce).";

const HELP_AUDIT: &str = "\
AUDIT — append-only event trail

Every command execution, auth failure, and policy denial is recorded
in .beads/audit/events.jsonl with Ed25519 digital signatures.

Retention:
  MANTICORE_AUDIT_MAX_ENTRIES (default: 10000)
  MANTICORE_AUDIT_ARCHIVE_ENABLED (default: true)

When max entries is exceeded, old events are archived to
.beads/audit/archive/events-<timestamp>.jsonl.

A Merkle tree root is computed over all events. When EVRUS anchoring
is enabled, this root is written to the Evrmore blockchain via
OP_RETURN for tamper-evidence.

Use 'show audit --last 50' to view recent events.
Use 'show storage' to check file sizes and retention status.";

const HELP_SSE: &str = "\
SSE — Server-Sent Events stream

Sentinel can expose a local SSE endpoint for streaming telemetry
to external consumers (dashboards, scripts, monitoring tools).

Enable:
  MANTICORE_EVENT_STREAM_ENABLED=true
  MANTICORE_EVENT_STREAM_PORT=9462

Test with curl:
  curl -N http://localhost:9462/

Events are streamed as 'event: telemetry' frames with JSON payloads
containing the current SystemSnapshot. Auth is inherited from the
configured MANTICORE_AUTH_MODE.";

const HELP_PROFILES: &str = "\
PROFILES — runtime configuration presets

Profiles load environment variables from config/profiles/<name>.env.
Use --profile <name> or MANTICORE_PROFILE=<name>.

Available profiles:

default  — Minimal standalone. Local auth, no connectors.
           Good for personal desktop monitoring.

dev      — Development mode. Verbose logging, fast refresh.

secure   — Token auth, restricted capabilities.
           Suitable for shared workstations.

ecosystem — Full integration. EVRUS auth, PeerWeave + EVRUS connectors,
            audit anchoring, snapshot history. For production fleet use.

Profile files are in config/profiles/. Create custom profiles by
adding new .env files to that directory.";

#[cfg(test)]
mod tests {
    use super::{parse_command, CommandAction};

    #[test]
    fn parses_show_cpu() {
        let action = parse_command("show cpu").expect("should parse");
        assert!(matches!(action, CommandAction::ShowCpu));
    }

    #[test]
    fn rejects_shell_operators() {
        let err = parse_command("show cpu | cat").expect_err("should reject");
        assert!(err.contains("shell operators"));
    }

    #[test]
    fn rejects_zero_pid_kill() {
        let err = parse_command("kill 0").expect_err("should reject");
        assert!(err.contains("pid must be > 0"));
    }

    #[test]
    fn parses_renice_command() {
        let action = parse_command("renice 10 123").expect("should parse");
        match action {
            CommandAction::ReniceProcess { pid, nice } => {
                assert_eq!(pid, 123);
                assert_eq!(nice, 10);
            }
            _ => panic!("unexpected action"),
        }
    }

    #[test]
    fn rejects_too_long_command() {
        let input = "x".repeat(300);
        let err = parse_command(&input).expect_err("should reject");
        assert!(err.contains("too long"));
    }

    #[test]
    fn parses_show_memory() {
        let action = parse_command("show memory").expect("should parse");
        assert!(matches!(action, CommandAction::ShowMemory));
        let action = parse_command("show mem").expect("should parse");
        assert!(matches!(action, CommandAction::ShowMemory));
    }

    #[test]
    fn parses_show_processes_with_flags() {
        let action = parse_command("show processes --sort rss --limit 10").expect("should parse");
        match action {
            CommandAction::ShowProcesses { sort, limit } => {
                assert_eq!(sort, Some("rss".to_string()));
                assert_eq!(limit, Some(10));
            }
            _ => panic!("unexpected action"),
        }
    }

    #[test]
    fn rejects_invalid_show_processes_sort() {
        let err = parse_command("show processes --sort bogus").expect_err("should reject");
        assert!(err.contains("invalid --sort"));
    }

    #[test]
    fn rejects_zero_show_processes_limit() {
        let err = parse_command("show processes --limit 0").expect_err("should reject");
        assert!(err.contains("--limit"));
    }

    #[test]
    fn parses_help_with_topic() {
        let action = parse_command("help config").expect("should parse");
        match action {
            CommandAction::Help { topic } => assert_eq!(topic, Some("config".to_string())),
            _ => panic!("unexpected action"),
        }
    }

    #[test]
    fn parses_show_audit_with_last() {
        let action = parse_command("show audit --last 50").expect("should parse");
        match action {
            CommandAction::ShowAudit { last } => assert_eq!(last, 50),
            _ => panic!("unexpected action"),
        }
    }

    #[test]
    fn rejects_zero_show_audit_last() {
        let err = parse_command("show audit --last 0").expect_err("should reject");
        assert!(err.contains("--last"));
    }

    #[test]
    fn unknown_command_suggests_help() {
        let err = parse_command("foo bar").expect_err("should reject");
        assert!(err.contains("help"));
    }
}
