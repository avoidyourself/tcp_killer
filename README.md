```markdown
tcp_killer (v2.0)

**Advanced Forensic Intelligence & Connection Termination for Linux/macOS**

This suite consists of two "sister scripts" designed to work in tandem:
1.  **`process_reveal.py` (The Hunter):** A deep-forensic scanner that identifies hidden, malicious, or anomalous processes (including those hiding in Swap or using code injection).
2.  **`connection_killer.py` (The Killer):** A kinetic tool to sever TCP/UDP connections or terminate the processes identified by the Hunter.

## Part 1: The Hunter (`process_reveal.py`)

This script bypasses standard tools like `top` or `ps` to inspect raw kernel data structures (`/proc`). It is designed to expose threats that attempt to hide from the user.

### Key Capabilities
* **W^X Violation Detection:** Scans memory maps for segments that are both Writable and Executable (RWX)—a primary indicator of shellcode injection or process hollowing.
* **Rootkit Hook Detection:** Scans process environments for `LD_PRELOAD` hooks used by user-land rootkits to hijack system tools.
* **Ghost Process Detection:** Flags binaries that have been deleted from the disk (`unlinked`) but are still running in RAM.
* **Swap Inspection:** Identifies processes hiding in Swap (high disk usage, low RAM) to evade standard memory scanners.
* **Baselining:** Establishes a "known good" state to detect new anomalies over time.

### Usage

**Note:** Must be run as root (`sudo`) to inspect memory maps and other users' processes.

```bash
# 1. Establish a Baseline (Record "Normal" State)
sudo python3 process_reveal.py --baseline

# 2. Forensic Scan (Show only anomalies/threats)
sudo python3 process_reveal.py --scan

# 3. Diff Scan (Compare current state to Baseline)
sudo python3 process_reveal.py --diff

# 4. Full Dump (Show all processes with forensic data)
sudo python3 process_reveal.py --scan --all

```

---

## Part 2: The Killer (`connection_killer.py`)

Once a target is identified, this script terminates its network access or its existence entirely.

### Key Capabilities

* **Protocol Agnostic:** Targets TCP and UDP (essential for killing QUIC/HTTP3).
* **Persistence Countermeasure:** The `--watch` mode creates a loop to instantly kill connections that attempt to auto-restart (DoS the malware).
* **The Nuclear Option:** The `--kill-process` flag bypasses socket shutdown and sends a `SIGKILL` to the process itself.

### Usage

```bash
# 1. Kill a specific connection (TCP default)
sudo python3 connection_killer.py 192.168.1.50:443

# 2. Kill a UDP/QUIC connection on port 443
sudo python3 connection_killer.py :443 --udp

# 3. Persistence Mode (Stop auto-restarting connections)
sudo python3 connection_killer.py :8080 --watch 0.5

# 4. The Nuclear Option (Kill the process found by process_reveal.py)
# If process_reveal showed a threat on port 4444:
sudo python3 connection_killer.py :4444 --kill-process

```

---

## The Hunter-Killer Workflow

**Step 1: Intelligence**
Run `process_reveal.py` to find the threat.

```text
PID     USER      ALERTS                         PROCESS
1337    www-data  [RWX_ANONYMOUS] | [SWAP_HIDER] /usr/bin/python3 (deleted)

```

**Step 2: Verification**
Check if PID 1337 has an active connection.

```bash
sudo lsof -p 1337
# Output shows connection to 93.184.216.34:443

```

**Step 3: Termination**
Use `connection_killer.py` to end it.

```bash
sudo python3 connection_killer.py :443 --kill-process

```

---

## Installation & Dependencies

Both scripts require **Python 3**.

1. **System Tools:**
```bash
# Ubuntu/Debian
sudo apt-get install python3 lsof

# macOS
brew install lsof

```


2. **Python Libraries:**
The Killer script utilizes Frida for socket injection (optional if only using `--kill-process`).
```bash
pip3 install frida-tools frida

```



## Disclaimer

These tools are powerful. `process_reveal.py` exposes raw system internals, and `connection_killer.py` can disrupt system stability if used on critical daemon processes. Use responsibly and only on systems you own or are authorized to secure.

```

```
