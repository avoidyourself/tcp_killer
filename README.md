# Google - TCP Killer succesor
## Complete Detection & Termination Capabilities

### Overview

This project is a comprehensive security tool that combines deep system forensics with surgical network connection termination. It goes beyond traditional tools like `ps`, `netstat`, and `lsof` to detect sophisticated threats.

---

## Detection Capabilities

### 1. Process Analysis

#### Basic Detection
- **Process metadata**: PID, PPID, UID, state, threads, file descriptors
- **Memory usage**: RSS (RAM), Swap usage
- **CPU utilization**: Cumulative CPU time tracking
- **Binary path resolution**: Full executable path tracking

#### Advanced Detection

**Memory Anomalies**:
- W^X violations (Read-Write-Execute segments)
- Anonymous executable memory (process injection signature)
- RWX on stack/heap (shellcode indicators)
- Excessive RWX segments
- High anonymous memory percentage
- Large shared memory segments

**Process Behavior**:
- High thread counts (> 100 threads)
- Excessive file descriptors (> 500 FDs)
- Swap hiding (high swap, low RSS)
- CPU usage spikes
- Process name spoofing (name vs exe mismatch)
- Orphaned processes (PPID = 1, non-init)

**Binary Location**:
- Deleted binaries (running from RAM only)
- Suspicious paths (/tmp, /dev/shm, /var/tmp)
- Hidden directories (dot-prefixed)
- Root processes in suspicious locations

**Permissions & Capabilities**:
- Dangerous Linux capabilities:
  - CAP_SYS_ADMIN (full system control)
  - CAP_SYS_PTRACE (process debugging)
  - CAP_NET_RAW (packet crafting)
  - CAP_NET_ADMIN (network config)
  - CAP_DAC_OVERRIDE (file permission bypass)
  - CAP_DAC_READ_SEARCH (file read bypass)

---

### 2. Network Analysis

#### Connection State Tracking
Monitors all TCP/UDP connection states:
- ESTABLISHED (active connections)
- LISTEN (listening services)
- SYN_SENT (outbound connection attempts)
- SYN_RECV (inbound connection attempts)
- FIN_WAIT1/FIN_WAIT2 (graceful close)
- TIME_WAIT (connection cooldown)
- CLOSE_WAIT (zombie connections)
- CLOSE (closed connections)
- LAST_ACK (final acknowledgment)
- CLOSING (simultaneous close)

#### Behavioral Analysis

**Port Binding Detection**:
- LISTEN on 0.0.0.0 (all interfaces) for non-standard ports
- High port listeners (> 50000)
- Unusual system port usage

**Connection Patterns**:
- Beaconing detection (periodic C2 communications)
  - Analyzes connection timing intervals
  - Detects regular patterns (5s - 2min intervals)
  - < 20% timing deviation = probable C2
- Connection state anomalies
- Excessive SYN_SENT (port scanning)
- CLOSE_WAIT zombies (resource leaks)

**Baseline Comparison**:
- Tracks normal network destinations per process
- Identifies new/unusual connections
- Flags deviation from established patterns

**Protocol Coverage**:
- TCP (IPv4 and IPv6)
- UDP (IPv4 and IPv6)
- All connection states

---

### 3. Memory Forensics

#### Memory Mapping Analysis
Parses `/proc/[pid]/maps` for:
- Permission violations (RWX segments)
- Anonymous memory regions
- Executable anonymous memory
- Memory-mapped files from suspicious paths
- Stack/heap execution

#### Shared Memory Analysis
Analyzes `/proc/[pid]/smaps` for:
- Large shared memory segments (> 100MB)
- Shared_Clean and Shared_Dirty tracking
- Inter-process communication patterns

#### Memory Growth Tracking
- Monitors memory allocation over time
- Detects rapid memory expansion
- Identifies memory leaks or data staging

---

### 4. Persistence Detection

#### Startup Mechanisms

**Systemd Units**:
- Scans all systemd services
- Identifies suspicious service names
- Keywords: miner, bot, trojan, backdoor, hidden

**Cron Jobs**:
- System crontabs (/etc/cron.*)
- User crontabs
- Detects jobs with suspicious paths

**Shell Profiles**:
- ~/.bashrc, ~/.bash_profile, ~/.profile
- ~/.zshrc
- /etc/profile, /etc/bash.bashrc
- Detects LD_PRELOAD hooks
- Identifies suspicious path references

**XDG Autostart**:
- ~/.config/autostart
- /etc/xdg/autostart
- Scans .desktop files for suspicious executables

---

## Killing Capabilities

### 1. Native Kernel Kill (ss -K)

**Method**: Uses kernel socket destruction via `ss -K`

**Advantages**:
- Fastest method (kernel-level operation)
- No process memory access required
- Stealthy (no ptrace attachment)
- No risk of process corruption

**Limitations**:
- Linux-only
- Cannot kill LISTEN sockets
- Requires `ss` utility

**Usage**:
```bash
sudo python3 net_sentinel.py --kill :8080 --method native
```

---

### 2. Frida Injection Kill

**Method**: Injects `shutdown()` syscall into target process

**Advantages**:
- Surgical precision (specific socket only)
- Works on LISTEN sockets
- Cross-platform (Linux/macOS)
- Graceful connection termination

**Limitations**:
- Requires Frida library
- Process memory access required
- May trigger security software
- Slower than native method

**Usage**:
```bash
sudo python3 net_sentinel.py --kill :8080 --method injection
```

**Technical Details**:
- Resolves `shutdown()` function in libc/libsystem
- Creates NativeFunction wrapper
- Calls `shutdown(fd, SHUT_RDWR)`
- Detaches cleanly

---

### 3. Process Termination

**Method**: SIGKILL entire process and children

**Advantages**:
- Guaranteed kill
- Removes all connections at once
- Kills entire process tree
- No recovery possible

**Limitations**:
- Most disruptive
- May affect legitimate functionality
- No graceful shutdown

**Usage**:
```bash
sudo python3 net_sentinel.py --kill :8080 --method process
```

**Process Tree Handling**:
1. Identifies all child processes via PPID
2. Kills children first (depth-first)
3. Kills parent process last
4. Uses SIGKILL (cannot be caught)

---

### 4. Firewall Blocking

**Method**: IPTables/IP6Tables rules

**Advantages**:
- Persistent blocking (survives reconnect attempts)
- Network-level enforcement
- Blocks all future connections to target
- Dual-stack support (IPv4/IPv6)

**Limitations**:
- Rules persist until manually removed
- Affects all processes
- Requires iptables utilities

**Usage**:
```bash
sudo python3 net_sentinel.py --kill 192.168.1.100:8080 --method block
```

**Firewall Logic**:
1. Checks existing rules to avoid duplicates
2. Inserts OUTPUT chain rule: `-j DROP`
3. Separate handling for IPv4 (iptables) and IPv6 (ip6tables)
4. Refuses to block localhost/wildcard IPs

**Rule Removal**:
```bash
# View rules
sudo iptables -L OUTPUT -n --line-numbers

# Remove rule
sudo iptables -D OUTPUT <line_number>
```

---

### 5. Kill Verification

All kill methods support verification:
1. Re-scans network connections
2. Checks if target still exists
3. Reports success/failure
4. Automatic verification in "auto" mode

---

### 6. Watch Mode (Persistence Counter)

Continuous monitoring to handle auto-reconnecting processes:

```bash
sudo python3 net_sentinel.py --kill :8080 --watch 0.5
```

**Features**:
- Loops indefinitely (Ctrl+C to stop)
- Configurable interval (seconds)
- Kills connections as they appear
- Tracks kill statistics

**Use Cases**:
- Malware that auto-reconnects
- Persistent C2 channels
- Auto-restarting backdoors
- Testing connection resilience

---

## Usage Examples

### Forensic Scanning

**Basic Scan** (suspicious processes only):
```bash
sudo python3 net_sentinel.py --scan
```

**Full Scan** (all processes):
```bash
sudo python3 net_sentinel.py --scan --all
```

**Establish Baseline**:
```bash
# Process baseline
sudo python3 net_sentinel.py --baseline

# Network baseline
sudo python3 net_sentinel.py --network-baseline
```

**Compare to Baseline** (diff mode):
After establishing baseline, run normal scan to see deviations.

---

### Connection Termination

**Kill Local Port** (all connections):
```bash
sudo python3 net_sentinel.py --kill :8080
```

**Kill Specific Connection**:
```bash
sudo python3 net_sentinel.py --kill :8080 --remote 192.168.1.100:443
```

**Kill UDP Connections**:
```bash
sudo python3 net_sentinel.py --kill :53 --protocol UDP
```

**Persistent Kill Loop**:
```bash
sudo python3 net_sentinel.py --kill :8080 --watch 0.5
```

**Nuclear Option** (kill process):
```bash
sudo python3 net_sentinel.py --kill :22 --method process
```

**Block with Firewall**:
```bash
sudo python3 net_sentinel.py --kill :443 --remote 93.184.216.34:443 --method block
```

---

### Real-World Scenarios

#### Scenario 1: Cryptocurrency Miner Detection

```bash
# 1. Full scan
sudo python3 net_sentinel.py --scan

# Output shows:
# PID 1337 | HIGH_THREADS:150 | HIGH_CPU | SUSPICIOUS_PATH:/tmp/xmrig

# 2. Check network connections
# Shows beaconing to mining pool every 30 seconds

# 3. Kill the miner
sudo python3 net_sentinel.py --kill :3333 --method process

# 4. Block mining pool
sudo python3 net_sentinel.py --kill :3333 --remote pool.minexmr.com:3333 --method block
```

---

#### Scenario 2: Backdoor Detection

```bash
# 1. Scan for listeners
sudo python3 net_sentinel.py --scan

# Output shows:
# PID 666 | LISTEN_ALL_INTERFACES:31337 | DELETED_BINARY | RWX_ANONYMOUS

# 2. Establish baseline for future detection
sudo python3 net_sentinel.py --baseline

# 3. Kill the backdoor
sudo python3 net_sentinel.py --kill :31337 --method process

# 4. Monitor for reconnection
sudo python3 net_sentinel.py --kill :31337 --watch 1.0
```

---

#### Scenario 3: C2 Beaconing Detection

```bash
# 1. Run scan to detect beaconing
sudo python3 net_sentinel.py --scan

# Output shows:
# BEACONING DETECTED: 203.0.113.5:443 - Interval: 15.2s (PID: 2468)

# 2. Kill connection
sudo python3 net_sentinel.py --kill :443 --remote 203.0.113.5:443

# 3. Block C2 server permanently
sudo python3 net_sentinel.py --kill :443 --remote 203.0.113.5:443 --method block
```

---

#### Scenario 4: Process Injection Detection

```bash
# 1. Scan memory for injection
sudo python3 net_sentinel.py --scan

# Output shows:
# PID 1234 | RWX_ANONYMOUS | HIGH_ANON_MEM:85%

# 2. Examine the process
ls -la /proc/1234/exe
cat /proc/1234/cmdline

# 3. If malicious, kill entire process tree
sudo python3 net_sentinel.py --kill :8080 --method process
```

---

## Technical Architecture

### Data Sources

```
/proc/[pid]/stat       - CPU, state, threads
/proc/[pid]/status     - Memory, capabilities, UIDs
/proc/[pid]/fd/        - Open file descriptors
/proc/[pid]/maps       - Memory mappings
/proc/[pid]/smaps      - Detailed memory info
/proc/[pid]/exe        - Binary path (symlink)
/proc/[pid]/cmdline    - Command line arguments
/proc/[pid]/environ    - Environment variables
/proc/[pid]/cwd        - Working directory

/proc/net/tcp          - TCP connections (IPv4)
/proc/net/tcp6         - TCP connections (IPv6)
/proc/net/udp          - UDP sockets (IPv4)
/proc/net/udp6         - UDP sockets (IPv6)
```

### External Utilities

```bash
ss          - Socket statistics (native kill)
lsof        - List open files (connection tracking)
iptables    - Firewall rules (IPv4 blocking)
ip6tables   - Firewall rules (IPv6 blocking)
systemctl   - Systemd unit management
crontab     - Cron job listing
```

### Python Modules

```python
frida       - Dynamic instrumentation (optional)
os, sys     - System interaction
pwd         - User database
json        - Baseline storage
threading   - Async injection
socket      - Address parsing
subprocess  - External command execution
signal      - Process signaling
```

---

## Safety Features

### Process Whitelist

Automatically protects critical system processes:
- systemd, init
- sshd (don't lock yourself out)
- dhclient, NetworkManager
- dbus-daemon
- systemd-resolved, systemd-networkd

**Bypass whitelist**:
```python
# Edit PROCESS_WHITELIST in source code
PROCESS_WHITELIST = {}  # Empty set = no protection
```

### Localhost Protection

Refuses to block localhost IPs in firewall:
- 127.0.0.1 (IPv4 loopback)
- ::1 (IPv6 loopback)
- 0.0.0.0 (wildcard)
- :: (IPv6 wildcard)

### Graceful Degradation

Works even if tools are missing:
- No `ss`: Falls back to Frida injection
- No Frida: Falls back to process kill
- No iptables: Skips firewall blocking
- Continues operation with warnings

---

## Performance Considerations

### Scan Performance

- **Process scan**: ~0.1ms per process
- **Memory scan**: ~1ms per process
- **Network scan**: ~50ms (all connections)
- **Full scan (1000 processes)**: ~2-3 seconds

### Optimization Tips

1. Use `--all` sparingly (shows everything)
2. Establish baselines offline (lower runtime overhead)
3. Watch mode intervals: 0.5s minimum recommended
4. Network baseline: Re-generate weekly

---

## Limitations & Known Issues

### Platform Support

- **Linux**: Full support (all features)
- **macOS**: Partial support:
  - No native kill (ss -K)
  - No iptables (use pfctl manually)
  - Frida injection works
  - Process forensics works

### Root Requirements

Most features require root:
- Reading other users' /proc data
- Socket termination
- Firewall rule modification
- Process killing

### Container/Namespace Limitations

- Cannot see processes in other namespaces
- Container networking may be isolated
- Docker processes may not be visible

### Kernel Rootkits

This tool operates in userland only:
- Cannot detect kernel-level rootkits
- Cannot verify syscall table integrity
- Cannot scan kernel memory

---

## Troubleshooting

### "Frida not available"

```bash
pip3 install frida-tools frida
```

### "Permission denied" errors

```bash
sudo python3 net_sentinel.py ...
```

### "ss: command not found"

```bash
# Ubuntu/Debian
sudo apt install iproute2

# Or use --method injection
```

### Kill verification fails

Some processes immediately reconnect. Use watch mode:
```bash
sudo python3 net_sentinel.py --kill :8080 --watch 0.5
```

### IPTables rules persist

```bash
# List rules
sudo iptables -L OUTPUT -n --line-numbers

# Delete rule
sudo iptables -D OUTPUT <line_number>

# Flush all rules (dangerous!)
sudo iptables -F OUTPUT
```

---

## Contributing

Contributions welcome. Please focus on:
- Additional detection heuristics
- New persistence mechanisms
- Platform-specific optimizations
- Performance improvements

---

## License

Apache License, Version 2.0

Original tcp_killer by Jason Geffner (Google)
Enhanced by NET SENTINEL v5.0 development team

---

## Disclaimer

This tool is for authorized security testing and system administration only. Unauthorized use may violate computer fraud and abuse laws. Use responsibly and only on systems you own or have explicit permission to manage.
