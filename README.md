```markdown
# tcp_killer

**Author:** Jason Geffner (Google)
**Modifications:** v2.0 (Python 3 Port, UDP Support, Persistence, Process Forensics)
**License:** Apache License, Version 2.0

`tcp_killer` shuts down TCP and UDP connections on Linux or macOS. It finds the process and socket file descriptor associated with a given connection and injects code to shut it down.

This repository now includes `proc_scanner.py`, a sister script designed for deep process forensics to aid in identifying targets for `tcp_killer`.

## 1. tcp_killer.py

The functionality offered by *tcp_killer* is intended to mimic [TCPView](https://technet.microsoft.com/en-us/sysinternals/tcpview.aspx)'s "Close Connection" functionality and [tcpdrop](http://man.openbsd.org/tcpdrop.8)'s functionality on Linux and macOS.

### Modifications in v2.0
* **Python 3:** Codebase fully modernized for Python 3.
* **UDP & QUIC Support:** Added `--udp` flag to target UDP sockets (essential for killing HTTP/3 and QUIC connections).
* **Persistence Monitoring:** Added `--watch` mode to continuously kill connections that attempt to auto-restart.
* **Process Termination:** Added `--kill-process` flag to terminate the entire process if the socket cannot be closed gracefully.

### Usage

**Note:** This script usually requires `sudo` (root privileges) to inspect and inject into processes owned by other users.

`sudo python3 tcp_killer.py [options] <local endpoint> [remote endpoint]`

#### Arguments

| Argument | Description |
| :--- | :--- |
| `<local endpoint>` | The local IP address and port (e.g., `127.0.0.1:8080` or `:8080`). |
| `<remote endpoint>` | (Optional) The remote IP address and port. If omitted, it targets *any* connection on the local port. |
| `-v`, `--verbose` | Show verbose output (PID, FD details). |
| `--udp` | Target UDP sockets (includes QUIC/HTTP3). |
| `--tcp` | Target TCP sockets (Default if unspecified). |
| `-w`, `--watch SECONDS` | Run in a loop, checking for the connection every X seconds. |
| `--kill-process` | **Aggressive:** If the connection is found, kill the entire process (SIGKILL) instead of just closing the socket. |

#### Examples

**Basic TCP Kill**
Shut down a specific TCP connection between local port 50246 and remote port 443.
```bash
sudo python3 tcp_killer.py 10.31.33.7:50246 93.184.216.34:443

```

**Kill UDP / QUIC Connections**
Shut down any UDP connection on port 443.

```bash
sudo python3 tcp_killer.py :443 --udp

```

**Persistence Mode (Anti-Auto-Restart)**
Continuously monitor for a connection on port 8080 and kill it every 0.5 seconds.

```bash
sudo python3 tcp_killer.py :8080 --watch 0.5

```

---

## 2. proc_scanner.py (Auxiliary)

A forensic utility designed to identify hidden, malicious, or anomalous processes that may need to be targeted by `tcp_killer`. It bypasses standard tools like `ps` to inspect `/proc` directly.

### Features

* **W^X Violation Detection:** Scans memory maps for segments that are both Writable and Executable (RWX), indicating potential code injection.
* **Rootkit Hook Detection:** Scans process environments for `LD_PRELOAD` hooks.
* **Ghost Process Detection:** Flags binaries that have been deleted from disk but are still running.
* **Swap Inspection:** Identifies processes hiding in Swap (high disk usage, low RAM).
* **Baselining:** Saves a "known good" state to detect new processes over time.

### Usage

`sudo python3 proc_scanner.py [options]`

#### Arguments

| Argument | Description |
| --- | --- |
| `--scan` | View current anomalies (Deleted binaries, RWX memory, Swap hiding). |
| `--all` | Show all processes with forensic details. |
| `--baseline` | Establish the "Normal" warning baseline (saves to `process_baseline.json`). |
| `--diff` | Compare current active processes to the Baseline. |

#### Workflow Example

1. **Identify:** Run scan to find a suspicious PID.
```bash
sudo python3 proc_scanner.py --scan
# Output: PID 1337 [RWX_ANONYMOUS] /tmp/miner

```


2. **Terminate:** Use `tcp_killer` to kill the process.
```bash
sudo python3 tcp_killer.py --kill-process (target port or use kill -9 1337)

```



---

## Dependencies

### Python 3 & Lsof

Ensure you have Python 3 and `lsof` installed.

```bash
# Ubuntu/Debian
sudo apt-get install python3 lsof

# macOS
brew install lsof

```

### Frida

`tcp_killer.py` uses [frida](https://www.frida.re/) for dynamic binary instrumentation (socket injection).

```bash
pip3 install frida-tools frida

```

## Disclaimer

This is not an official Google product. Use responsibly and only on systems you own or have permission to manage.

```

```
