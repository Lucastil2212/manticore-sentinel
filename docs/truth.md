Below is a **comprehensive, implementation-grade design document** intended to serve as the **single source of truth** for building the product we’ve discussed.

---

# 🦂 Product Design Document

## **Manticore Sentinel**

*A Zero-Trust, Kernel-Proximate Linux Observability Interface*

---

# 1. Vision & Philosophy

## 1.1 Product Definition

**Manticore Sentinel** is a **lightweight, Linux-native, real-time system observability platform** that:

* Operates **as close to the kernel as possible**
* Provides a **dual-interface (GUI + command layer)**
* Implements a **zero-trust, capability-based architecture**
* Bridges **novice usability** with **expert-level control**

---

## 1.2 Core Principles

1. **Kernel Proximity First**

   * Direct reads from `/proc`, `/sys`, netlink
   * No shell command dependency

2. **Zero Trust by Default**

   * All inputs validated
   * Privileges isolated
   * Explicit capability model

3. **Performance as a Feature**

   * <2% CPU usage
   * <50MB memory
   * <100ms startup

4. **Transparency**

   * Every UI action maps to real system behavior
   * CLI equivalence always visible

5. **Dual Persona UX**

   * Beginner clarity
   * Expert control

---

# 2. High-Level Architecture

## 2.1 System Overview

```text
+---------------------+
|        UI           |
| (egui / GTK layer)  |
+----------+----------+
           |
           v
+---------------------+
|  Unprivileged Core  |
|  (Sentinel Engine)  |
+----------+----------+
           |
   Secure IPC (UDS)
           |
           v
+---------------------+
| Privileged Helper   |
| (Minimal Surface)   |
+----------+----------+
           |
           v
+---------------------+
|   Linux Kernel      |
| /proc /sys netlink  |
+---------------------+
```

---

## 2.2 Component Responsibilities

### UI Layer

* Rendering
* Input capture
* Command palette
* No system access

### Core Engine

* Data collection
* Metric computation
* State management
* Validation layer

### Privileged Helper

* Minimal, audited operations:

  * kill
  * renice
  * eBPF (future)
* No business logic

---

# 3. Technology Stack

## 3.1 Language

**Rust (mandatory)**

Rationale:

* Memory safety
* Low-level access
* Concurrency primitives
* Zero-cost abstractions

---

## 3.2 GUI Framework

### Preferred:

* `egui` (lightweight, immediate mode)

### Alternative:

* GTK (if native desktop fidelity required)

---

## 3.3 Core Libraries

| Purpose       | Library            |
| ------------- | ------------------ |
| /proc parsing | `procfs` (initial) |
| syscalls      | `nix`              |
| IPC           | `tokio` + UDS      |
| serialization | `serde`            |
| async runtime | `tokio`            |

---

# 4. Kernel Interface Strategy

## 4.1 Data Sources

| Domain    | Source                         |
| --------- | ------------------------------ |
| CPU       | `/proc/stat`                   |
| Memory    | `/proc/meminfo`                |
| Processes | `/proc/[pid]/`                 |
| Disk      | `/proc/diskstats`              |
| Network   | `/sys/class/net/*/statistics/` |
| Temps     | `/sys/class/thermal/`          |

---

## 4.2 Data Collection Model

### Polling Strategy

* Interval: **250–500ms**
* Snapshot-based
* Delta computation required

---

## 4.3 Metric Computation Example

### CPU Usage

```text
delta_total = total_t2 - total_t1
delta_idle  = idle_t2 - idle_t1

cpu_usage = 1 - (delta_idle / delta_total)
```

---

# 5. Core Data Model

## 5.1 System Snapshot

```rust
struct SystemSnapshot {
    timestamp: u64,
    cpu: CpuMetrics,
    memory: MemoryMetrics,
    disks: Vec<DiskMetrics>,
    network: Vec<NetMetrics>,
    processes: Vec<ProcessMetrics>,
}
```

---

## 5.2 CPU Metrics

```rust
struct CpuMetrics {
    usage_percent: f32,
    per_core: Vec<f32>,
    load_avg: (f32, f32, f32),
}
```

---

## 5.3 Process Model

```rust
struct ProcessMetrics {
    pid: u32,
    name: String,
    cpu_percent: f32,
    memory_bytes: u64,
    threads: u32,
    cmdline: String,
}
```

---

# 6. Security Architecture (Zero Trust)

## 6.1 Process Separation

| Component   | Privilege            |
| ----------- | -------------------- |
| UI          | Unprivileged         |
| Core Engine | Unprivileged         |
| Helper      | Privileged (minimal) |

---

## 6.2 IPC Design

### Transport

* Unix Domain Socket

### Message Schema

```json
{
  "action": "kill_process",
  "pid": 1234
}
```

---

## 6.3 Validation Rules

* No free-form commands
* All actions enumerated
* All inputs validated before execution

---

## 6.4 Capability Model

```rust
enum Capability {
    ReadMetrics,
    KillProcess,
    ReniceProcess,
    TraceSystem,
}
```

---

## 6.5 Privileged Helper Constraints

* No dynamic memory allocation if possible
* No parsing logic
* No string-based command execution
* Only syscall wrappers

---

# 7. Command System (Warp-Inspired)

## 7.1 Command Palette

### Examples

```
kill 1234
show cpu
trace pid 456
```

---

## 7.2 Internal Mapping

| Command  | Internal Action |
| -------- | --------------- |
| kill     | KillProcess     |
| show cpu | ReadMetrics     |
| renice   | ReniceProcess   |

---

## 7.3 Parsing Strategy

* Token-based parser
* No shell interpretation
* No piping/redirection

---

# 8. UX Design

## 8.1 Layout

### Main Dashboard

* CPU Graph (top)
* Memory Bar
* Disk I/O Graph
* Network Graph
* Process Table

---

## 8.2 Dual Mode

### Beginner Mode

* Simplified metrics
* Plain language
* Alerts

### Advanced Mode

* Raw values
* Full process data
* Command palette enabled

---

## 8.3 “Reveal Command” Feature

Every UI action exposes:

```text
Equivalent:
kill 1234
```

---

# 9. Performance Requirements

| Metric       | Target    |
| ------------ | --------- |
| CPU overhead | <2%       |
| Memory       | <50MB     |
| Startup      | <100ms    |
| Refresh      | 250–500ms |

---

# 10. Sandboxing

## 10.1 seccomp Profile

Restrict:

* file writes
* network syscalls (optional)
* process spawning

---

## 10.2 Filesystem Access

Allowed:

* `/proc`
* `/sys`

Denied:

* `/etc`
* `/home` (write)

---

# 11. Observability & Logging

## 11.1 Audit Log

```text
[time] action=kill_process pid=1234 result=success
```

---

## 11.2 Internal Metrics

* self CPU usage
* polling latency
* IPC latency

---

# 12. Extensibility (Future)

## 12.1 Plugin System

### Requirement:

* WASM sandbox

### Capabilities:

* Read-only metrics
* Custom visualizations

---

## 12.2 eBPF Integration

Phase 2:

* syscall tracing
* performance hotspots

---

# 13. Build & Packaging

## 13.1 Distribution

* Static binary preferred
* Optional:

  * Flatpak
  * AppImage

---

## 13.2 Permissions

* Default: user-level
* Elevation via:

  * polkit (preferred)
  * NOT setuid (unless audited)

---

# 14. Development Phases

## Phase 1 (MVP)

* CPU, memory, network, disk
* Process viewer
* Basic UI

## Phase 2

* Command palette
* Privileged helper
* Process control

## Phase 3

* eBPF
* plugins
* historical data

---

# 15. Engineering Constraints

## MUST NOT

* Use shell commands internally
* Run everything as root
* Trust UI input
* Over-abstract kernel interfaces

---

## MUST

* Validate all inputs
* Keep helper minimal
* Prefer direct kernel reads
* Maintain strict module boundaries

---

# 16. Strategic Positioning

Manticore Sentinel is:

* Not a system monitor
* Not a dashboard

It is:

> **A real-time, zero-trust interface to the Linux kernel’s operational state**

---

# 17. Final Directive

If implemented correctly, this system will:

* Outperform existing tools
* Be safer than traditional monitors
* Educate users implicitly
* Scale into a full observability platform

---

# Next Step

To move into execution with precision, the next artifact should be:

👉 **Rust project scaffolding + module layout + first collector implementation**

I can generate that next if you want to move directly into building.

