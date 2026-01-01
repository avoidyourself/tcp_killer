# NET SENTINEL v5.0 - Quick Start Guide

## Installation (5 minutes)

### 1. Install System Dependencies

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install python3 python3-pip lsof iproute2 iptables
```

**RHEL/CentOS**:
```bash
sudo yum install python3 python3-pip lsof iproute iptables
```

**macOS**:
```bash
brew install python3 lsof
```

### 2. Install Python Dependencies

```bash
# Recommended: Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip3 install -r requirements.txt

# Or install manually:
pip3 install frida frida-tools
```

### 3. Verify Installation

```bash
sudo python3 net_sentinel.py --scan
```

If you see a system scan output, you're ready to go.

---

## Your First Scan (2 minutes)

### Basic Security Audit

```bash
# Run full security scan
sudo python3 net_sentinel.py --scan
```

**What to look for**:
- RED alerts: Critical issues (RWX memory, dangerous capabilities, deleted binaries)
- YELLOW alerts: Suspicious activity (high threads, unusual paths)
- Beaconing: Regular interval connections (possible C2 communication)

### Example Output

```
================================================================================
PROCESS FORENSICS
================================================================================
PID     USER       STATE  THR   FDS   ALERTS                                  PROCESS
--------------------------------------------------------------------------------
1337    root       S      150   45    HIGH_THREADS:150 | SUSPICIOUS_PATH:/tmp /tmp/xmrig
2468    www-data   S      8     512   HIGH_FDS:512 | RWX_ANONYMOUS            /usr/bin/apache2
```

---

## Common Tasks (1 minute each)

### Task 1: Establish Security Baseline

```bash
# Create process baseline (run on clean system)
sudo python3 net_sentinel.py --baseline

# Create network baseline
sudo python3 net_sentinel.py --network-baseline
```

**Purpose**: Future scans will show NEW processes and connections.

---

### Task 2: Kill a Suspicious Connection

**Scenario**: Found process listening on port 31337

```bash
# Kill all connections on port 31337
sudo python3 net_sentinel.py --kill :31337

# Or kill specific remote connection
sudo python3 net_sentinel.py --kill :31337 --remote 192.168.1.100:443
```

---

### Task 3: Block Malicious IP

**Scenario**: Process keeps reconnecting to C2 server

```bash
# Block with firewall (persistent)
sudo python3 net_sentinel.py --kill :443 --remote 203.0.113.5:443 --method block

# Verify blocked
sudo iptables -L OUTPUT -n | grep 203.0.113.5
```

**Remove block later**:
```bash
sudo iptables -D OUTPUT -d 203.0.113.5 -j DROP
```

---

### Task 4: Monitor for Auto-Reconnecting Malware

**Scenario**: Malware reconnects every few seconds

```bash
# Watch mode (kills every 0.5 seconds)
sudo python3 net_sentinel.py --kill :8080 --watch 0.5

# Press Ctrl+C to stop
```

---

## Understanding Output

### Process Alerts

| Alert | Meaning | Severity |
|-------|---------|----------|
| `DELETED_BINARY` | Running from RAM only (file deleted) | HIGH |
| `RWX_ANONYMOUS` | Writable+executable memory (injection) | HIGH |
| `DANGEROUS_CAP:cap_sys_ptrace` | Can debug other processes | HIGH |
| `SUSPICIOUS_PATH:/tmp` | Binary in temporary directory | MEDIUM |
| `HIGH_THREADS:150` | Excessive threads (> 100) | MEDIUM |
| `HIGH_FDS:512` | Many open files | MEDIUM |
| `ORPHANED` | Parent process died | LOW |

---

### Network Alerts

| Alert | Meaning | Severity |
|-------|---------|----------|
| `BEACONING` | Regular interval connections (C2) | HIGH |
| `LISTEN_ALL_INTERFACES:8080` | Listening on 0.0.0.0 | MEDIUM |
| `HIGH_PORT_LISTENER:51234` | Listening on port > 50000 | MEDIUM |
| `ZOMBIE_CONN` | CLOSE_WAIT state | LOW |
| `SYN_SENT_SCANNING` | Many outbound attempts | MEDIUM |

---

## Decision Tree

```
Found suspicious process?
├─ Has network connection?
│  ├─ YES → Kill connection:
│  │       sudo python3 net_sentinel.py --kill :PORT
│  │       
│  │       Still reconnecting?
│  │       └─ YES → Use watch mode or block:
│  │              sudo python3 net_sentinel.py --kill :PORT --watch 0.5
│  │              sudo python3 net_sentinel.py --kill :PORT --remote IP:PORT --method block
│  │
│  └─ NO → Kill process directly:
│          sudo python3 net_sentinel.py --kill :PORT --method process
│          (Or use: sudo kill -9 PID)
│
└─ Not sure? → Run full scan and compare to baseline
              sudo python3 net_sentinel.py --scan
```

---

## Pro Tips

### Tip 1: Automate Daily Scans

```bash
# Add to cron (run daily at 2 AM)
sudo crontab -e

# Add this line:
0 2 * * * /usr/bin/python3 /path/to/net_sentinel.py --scan > /var/log/sentinel_scan.log 2>&1
```

---

### Tip 2: Custom Whitelist

Edit `config.yaml`:
```yaml
process_whitelist:
  - systemd
  - sshd
  - your_app_name  # Add your protected processes
```

---

### Tip 3: Quick Incident Response

```bash
# 1. Snapshot system state
sudo python3 net_sentinel.py --scan > incident_$(date +%Y%m%d_%H%M%S).txt
sudo python3 net_sentinel.py --baseline  # Save for comparison

# 2. Kill threat
sudo python3 net_sentinel.py --kill :THREAT_PORT --method process

# 3. Block C2
sudo python3 net_sentinel.py --kill :443 --remote C2_IP:443 --method block

# 4. Monitor for persistence
sudo python3 net_sentinel.py --kill :THREAT_PORT --watch 1.0
```

---

### Tip 4: When NOT to Use NET SENTINEL

- **Production databases**: Don't kill database connections without planning
- **Active SSH sessions**: You'll lock yourself out
- **Critical services**: Check whitelist first
- **Containers**: May not see processes inside containers

---

## Troubleshooting

### "Permission denied"
```bash
# Always run with sudo
sudo python3 net_sentinel.py --scan
```

### "Frida not available"
```bash
# Install Frida
pip3 install frida frida-tools

# Or use native/process methods:
sudo python3 net_sentinel.py --kill :8080 --method native
```

### "No connections found"
```bash
# Check if process is actually listening
sudo lsof -i :8080
sudo netstat -tlnp | grep 8080

# Try different protocol
sudo python3 net_sentinel.py --kill :8080 --protocol UDP
```

### Kill doesn't work
```bash
# Try process kill (nuclear option)
sudo python3 net_sentinel.py --kill :8080 --method process

# Or manual kill
sudo lsof -i :8080  # Get PID
sudo kill -9 PID
```

---

## Next Steps

1. Read full documentation: `README_ADVANCED.md`
2. Customize configuration: `config.yaml`
3. Set up automated monitoring
4. Integrate with your incident response workflow

---

## Quick Reference Card

```bash
# SCANNING
sudo python3 net_sentinel.py --scan              # Scan anomalies
sudo python3 net_sentinel.py --scan --all        # Scan everything
sudo python3 net_sentinel.py --baseline          # Save baseline

# KILLING
sudo python3 net_sentinel.py --kill :PORT        # Kill local port
sudo python3 net_sentinel.py --kill :PORT --protocol UDP  # Kill UDP
sudo python3 net_sentinel.py --kill :PORT --method process  # Kill process
sudo python3 net_sentinel.py --kill :PORT --watch 0.5  # Monitor mode
sudo python3 net_sentinel.py --kill :PORT --remote IP:PORT --method block  # Firewall block

# METHODS
--method native     # Fast kernel kill (default for TCP)
--method injection  # Frida injection (surgical)
--method process    # Kill entire process (nuclear)
--method block      # Firewall block (persistent)
--method auto       # Try all methods (default)
```

---

## Support

- Report bugs: GitHub Issues
- Documentation: `README_ADVANCED.md`
- Configuration: `config.yaml`

---

**Remember**: Always test in a safe environment first. NET SENTINEL is a powerful tool - use responsibly.
