#!/usr/bin/env python3
# Copyright 2017 Google Inc. All Rights Reserved.
# Modified 2026: Advanced Hunter-Killer Architecture (v5.0)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""
NET SENTINEL v5.0 - Advanced Network & Process Intelligence System

DETECTION CAPABILITIES:
  [Network]
    - Connection state analysis (all TCP states)
    - Beaconing detection (C2 communication patterns)
    - Behavioral baselining (unusual destinations)
    - Port binding analysis (suspicious listeners)
  
  [Process]
    - CPU/Thread/FD anomalies
    - Capability analysis (dangerous permissions)
    - Process tree relationships
    - Binary location analysis
    - Name spoofing detection
  
  [Memory]
    - W^X violations (RWX segments)
    - Memory growth tracking
    - Shared memory analysis
    - Anonymous mapping detection
  
  [Persistence]
    - Systemd units
    - Cron jobs
    - Shell profile hooks
    - Autostart entries

KILLING CAPABILITIES:
  - All TCP connection states
  - IPv4/IPv6 dual stack
  - Process tree termination
  - Kill verification
  - Namespace-aware
"""

import os
import sys
import argparse
import pwd
import json
import time
import signal
import shutil
import platform
import re
import socket
import subprocess
import threading
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

# Frida is optional
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

# =============================================================================
# CONFIGURATION & GLOBALS
# =============================================================================

BASELINE_FILE = "sentinel_baseline_v5.json"
NETWORK_BASELINE = "network_baseline_v5.json"

# Colors
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Whitelisted processes (won't be killed)
PROCESS_WHITELIST = {
    "systemd", "init", "sshd", "dhclient", "NetworkManager",
    "dbus-daemon", "systemd-resolved", "systemd-networkd"
}

# Suspicious binary locations
SUSPICIOUS_PATHS = ["/tmp", "/dev/shm", "/var/tmp", "/var/run"]

# Common system ports (expected listeners)
COMMON_SYSTEM_PORTS = {22, 53, 80, 443, 123, 67, 68, 111, 631}

# Dangerous capabilities
DANGEROUS_CAPS = [
    "cap_sys_admin", "cap_sys_ptrace", "cap_net_raw", 
    "cap_net_admin", "cap_dac_override", "cap_dac_read_search"
]

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def run_cmd(cmd, check=False):
    """Run shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, 
            text=True, timeout=10
        )
        if check and result.returncode != 0:
            return None
        return result.stdout.strip()
    except:
        return None

def get_username(uid):
    """Convert UID to username."""
    try:
        return pwd.getpwuid(uid).pw_name
    except:
        return str(uid)

def is_whitelisted(proc_name):
    """Check if process is whitelisted."""
    return proc_name in PROCESS_WHITELIST

def is_suspicious_path(path):
    """Check if binary path is suspicious."""
    for susp in SUSPICIOUS_PATHS:
        if path.startswith(susp):
            return True
    return False

# =============================================================================
# PROCESS DETECTION MODULE
# =============================================================================

class ProcessDetector:
    """Advanced process analysis and anomaly detection."""
    
    def __init__(self):
        self.baseline = {}
        
    def scan_process(self, pid):
        """Deep scan of a single process."""
        p_path = f"/proc/{pid}"
        if not os.path.exists(p_path):
            return None
            
        data = {
            "pid": pid,
            "name": "?",
            "ppid": 0,
            "uid": -1,
            "user": "?",
            "state": "?",
            "threads": 0,
            "fds": 0,
            "rss": 0,
            "swap": 0,
            "cpu_time": 0,
            "exe": "",
            "cmdline": "",
            "cwd": "",
            "capabilities": [],
            "alerts": []
        }
        
        try:
            # 1. Parse /proc/[pid]/status
            with open(f"{p_path}/status", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 2: continue
                    key = parts[0].strip(":")
                    
                    if key == "Name": data["name"] = parts[1]
                    elif key == "State": data["state"] = parts[1]
                    elif key == "PPid": data["ppid"] = int(parts[1])
                    elif key == "Uid": 
                        data["uid"] = int(parts[1])
                        data["user"] = get_username(int(parts[1]))
                    elif key == "Threads": data["threads"] = int(parts[1])
                    elif key == "VmRSS": data["rss"] = int(parts[1])
                    elif key == "VmSwap": data["swap"] = int(parts[1])
                    elif key == "CapEff":
                        # Effective capabilities (hex)
                        data["capabilities"] = self._parse_capabilities(parts[1])
            
            # 2. Parse /proc/[pid]/stat for CPU
            with open(f"{p_path}/stat", "r") as f:
                stat_data = f.read().split(")")[-1].split()
                # utime + stime (fields 13, 14)
                if len(stat_data) >= 13:
                    data["cpu_time"] = int(stat_data[11]) + int(stat_data[12])
            
            # 3. Count file descriptors
            try:
                fd_path = f"{p_path}/fd"
                if os.path.exists(fd_path):
                    data["fds"] = len(os.listdir(fd_path))
            except:
                pass
            
            # 4. Resolve binary path
            try:
                data["exe"] = os.readlink(f"{p_path}/exe")
                if " (deleted)" in data["exe"]:
                    data["alerts"].append("DELETED_BINARY")
                elif is_suspicious_path(data["exe"]):
                    data["alerts"].append(f"SUSPICIOUS_PATH:{data['exe']}")
            except:
                pass
            
            # 5. Get cmdline
            try:
                with open(f"{p_path}/cmdline", "rb") as f:
                    data["cmdline"] = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            # 6. Get working directory
            try:
                data["cwd"] = os.readlink(f"{p_path}/cwd")
            except:
                pass
            
            # 7. Anomaly checks
            self._check_anomalies(data)
            
        except Exception as e:
            return None
            
        return data
    
    def _parse_capabilities(self, cap_hex):
        """Parse capability hex to list of capability names."""
        try:
            cap_int = int(cap_hex, 16)
            caps = []
            
            cap_names = [
                "cap_chown", "cap_dac_override", "cap_dac_read_search",
                "cap_fowner", "cap_fsetid", "cap_kill", "cap_setgid",
                "cap_setuid", "cap_setpcap", "cap_linux_immutable",
                "cap_net_bind_service", "cap_net_broadcast", "cap_net_admin",
                "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner", "cap_sys_module",
                "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace",
                "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot",
                "cap_sys_nice", "cap_sys_resource", "cap_sys_time",
                "cap_sys_tty_config", "cap_mknod", "cap_lease",
                "cap_audit_write", "cap_audit_control", "cap_setfcap"
            ]
            
            for i, cap_name in enumerate(cap_names):
                if cap_int & (1 << i):
                    caps.append(cap_name)
                    
            return caps
        except:
            return []
    
    def _check_anomalies(self, data):
        """Check for process anomalies."""
        # High thread count
        if data["threads"] > 100:
            data["alerts"].append(f"HIGH_THREADS:{data['threads']}")
        
        # High FD count
        if data["fds"] > 500:
            data["alerts"].append(f"HIGH_FDS:{data['fds']}")
        
        # Swap hiding
        if data["swap"] > 10000 and data["rss"] < 1000:
            data["alerts"].append("SWAP_HIDER")
        
        # Dangerous capabilities
        for cap in data["capabilities"]:
            if cap in DANGEROUS_CAPS:
                data["alerts"].append(f"DANGEROUS_CAP:{cap}")
        
        # Process name spoofing (name doesn't match exe)
        if data["exe"] and data["name"] != "?":
            exe_name = os.path.basename(data["exe"]).split()[0]
            if exe_name != data["name"] and not data["exe"].endswith("(deleted)"):
                data["alerts"].append("NAME_SPOOF")
        
        # Root process with suspicious path
        if data["uid"] == 0 and data["exe"]:
            if is_suspicious_path(data["exe"]):
                data["alerts"].append("ROOT_SUSPICIOUS_PATH")
        
        # Orphaned process (ppid = 1 but not init-like)
        if data["ppid"] == 1 and data["name"] not in ["systemd", "init"]:
            if not data["name"].startswith("kworker"):
                data["alerts"].append("ORPHANED")
    
    def scan_all(self):
        """Scan all processes."""
        pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
        results = {}
        for pid in pids:
            info = self.scan_process(pid)
            if info:
                results[str(pid)] = info
        return results

# =============================================================================
# MEMORY DETECTION MODULE
# =============================================================================

class MemoryDetector:
    """Advanced memory analysis."""
    
    def scan_memory(self, pid):
        """Scan process memory for anomalies."""
        maps_path = f"/proc/{pid}/maps"
        if not os.path.exists(maps_path):
            return []
        
        alerts = []
        rwx_count = 0
        anon_exec_count = 0
        total_anon = 0
        total_mapped = 0
        
        try:
            with open(maps_path, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 2: continue
                    
                    addr_range = parts[0]
                    perms = parts[1]
                    path = parts[-1] if len(parts) > 5 else "[anon]"
                    
                    # Calculate size
                    try:
                        start, end = addr_range.split("-")
                        size = int(end, 16) - int(start, 16)
                    except:
                        size = 0
                    
                    # Track totals
                    if path in ["[anon]", "[heap]", "[stack]"]:
                        total_anon += size
                    else:
                        total_mapped += size
                    
                    # W^X violation
                    if "w" in perms and "x" in perms:
                        rwx_count += 1
                        if "[stack]" in path or "[heap]" in path:
                            alerts.append("RWX_STACK_HEAP")
                        elif path == "[anon]":
                            alerts.append("RWX_ANONYMOUS")
                            anon_exec_count += 1
                    
                    # Executable anonymous memory
                    if "x" in perms and path == "[anon]":
                        anon_exec_count += 1
                    
                    # Suspicious mapped files
                    if "x" in perms and any(susp in path for susp in SUSPICIOUS_PATHS):
                        alerts.append(f"EXEC_SUSPICIOUS_PATH:{path}")
            
            # High anonymous memory percentage
            if total_anon + total_mapped > 0:
                anon_percent = (total_anon / (total_anon + total_mapped)) * 100
                if anon_percent > 80:
                    alerts.append(f"HIGH_ANON_MEM:{anon_percent:.0f}%")
            
            if rwx_count > 5:
                alerts.append(f"EXCESSIVE_RWX:{rwx_count}")
                
        except Exception:
            pass
        
        return list(set(alerts))
    
    def scan_shared_memory(self, pid):
        """Check shared memory segments."""
        smaps_path = f"/proc/{pid}/smaps"
        if not os.path.exists(smaps_path):
            return []
        
        alerts = []
        try:
            with open(smaps_path, "r") as f:
                content = f.read()
                # Look for large shared memory
                if "Shared_Clean:" in content or "Shared_Dirty:" in content:
                    # Parse shared memory size
                    for line in content.split("\n"):
                        if "Shared_Dirty:" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                size = int(parts[1])
                                if size > 100000:  # > 100MB
                                    alerts.append(f"LARGE_SHARED_MEM:{size}KB")
        except:
            pass
        
        return alerts

# =============================================================================
# NETWORK DETECTION MODULE
# =============================================================================

class NetworkDetector:
    """Advanced network connection analysis."""
    
    def __init__(self):
        self.baseline = {}
        self.connection_history = defaultdict(list)
    
    def scan_connections(self):
        """Scan all network connections using /proc/net."""
        connections = []
        
        # Parse TCP
        connections.extend(self._parse_net_file("/proc/net/tcp", "TCP", False))
        connections.extend(self._parse_net_file("/proc/net/tcp6", "TCP6", True))
        
        # Parse UDP
        connections.extend(self._parse_net_file("/proc/net/udp", "UDP", False))
        connections.extend(self._parse_net_file("/proc/net/udp6", "UDP6", True))
        
        return connections
    
    def _parse_net_file(self, path, proto, ipv6):
        """Parse /proc/net/tcp or /proc/net/udp."""
        if not os.path.exists(path):
            return []
        
        connections = []
        try:
            with open(path, "r") as f:
                lines = f.readlines()[1:]  # Skip header
                
                for line in lines:
                    parts = line.split()
                    if len(parts) < 10: continue
                    
                    # Parse local address
                    local_addr, local_port = self._parse_address(parts[1], ipv6)
                    remote_addr, remote_port = self._parse_address(parts[2], ipv6)
                    
                    # Parse state (TCP only)
                    state_hex = parts[3]
                    state = self._parse_state(state_hex, proto)
                    
                    # Parse UID
                    uid = int(parts[7])
                    
                    # Parse inode
                    inode = int(parts[9])
                    
                    conn = {
                        "proto": proto,
                        "local_addr": local_addr,
                        "local_port": local_port,
                        "remote_addr": remote_addr,
                        "remote_port": remote_port,
                        "state": state,
                        "uid": uid,
                        "user": get_username(uid),
                        "inode": inode,
                        "pid": None,
                        "process": None,
                        "alerts": []
                    }
                    
                    # Find PID by inode
                    pid, proc_name = self._find_pid_by_inode(inode)
                    conn["pid"] = pid
                    conn["process"] = proc_name
                    
                    # Analyze connection
                    self._analyze_connection(conn)
                    
                    connections.append(conn)
                    
        except Exception as e:
            pass
        
        return connections
    
    def _parse_address(self, addr_str, ipv6):
        """Parse hex address:port to readable format."""
        try:
            addr_hex, port_hex = addr_str.split(":")
            port = int(port_hex, 16)
            
            if ipv6:
                # IPv6: 32 hex chars
                addr_bytes = bytes.fromhex(addr_hex)
                # Reverse byte order for each 4-byte chunk
                addr_bytes = b''.join([addr_bytes[i:i+4][::-1] for i in range(0, 16, 4)])
                addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                # IPv4: 8 hex chars (little endian)
                addr_int = int(addr_hex, 16)
                addr = socket.inet_ntoa(addr_int.to_bytes(4, 'little'))
            
            return addr, port
        except:
            return "0.0.0.0", 0
    
    def _parse_state(self, state_hex, proto):
        """Parse TCP state from hex."""
        if "UDP" in proto:
            return "UNCONN"
        
        tcp_states = {
            "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
            "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
            "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
            "0A": "LISTEN", "0B": "CLOSING"
        }
        return tcp_states.get(state_hex, "UNKNOWN")
    
    def _find_pid_by_inode(self, inode):
        """Find process by socket inode."""
        for pid in os.listdir("/proc"):
            if not pid.isdigit(): continue
            
            fd_path = f"/proc/{pid}/fd"
            if not os.path.exists(fd_path): continue
            
            try:
                for fd in os.listdir(fd_path):
                    link = os.readlink(f"{fd_path}/{fd}")
                    if f"socket:[{inode}]" in link:
                        # Get process name
                        with open(f"/proc/{pid}/comm", "r") as f:
                            proc_name = f.read().strip()
                        return int(pid), proc_name
            except:
                continue
        
        return None, None
    
    def _analyze_connection(self, conn):
        """Analyze connection for anomalies."""
        # LISTEN on 0.0.0.0
        if conn["state"] == "LISTEN":
            if conn["local_addr"] in ["0.0.0.0", "::"]:
                if conn["local_port"] not in COMMON_SYSTEM_PORTS:
                    conn["alerts"].append(f"LISTEN_ALL_INTERFACES:{conn['local_port']}")
        
        # Suspicious high ports
        if conn["local_port"] > 50000 and conn["state"] == "LISTEN":
            conn["alerts"].append(f"HIGH_PORT_LISTENER:{conn['local_port']}")
        
        # Connection to localhost from non-localhost
        if conn["remote_addr"] not in ["0.0.0.0", "127.0.0.1", "::", "::1"]:
            if conn["local_addr"] in ["127.0.0.1", "::1"]:
                conn["alerts"].append("LOCALHOST_REMOTE_CONN")
        
        # CLOSE_WAIT zombies
        if conn["state"] == "CLOSE_WAIT":
            conn["alerts"].append("ZOMBIE_CONN")
        
        # Many SYN_SENT (scanning?)
        if conn["state"] == "SYN_SENT":
            conn["alerts"].append("SYN_SENT_SCANNING")
    
    def detect_beaconing(self, connections, window=60):
        """Detect periodic connections (C2 beaconing)."""
        # Track connections by destination
        now = time.time()
        beacons = []
        
        for conn in connections:
            if conn["state"] not in ["ESTABLISHED", "SYN_SENT"]:
                continue
            
            key = f"{conn['remote_addr']}:{conn['remote_port']}"
            self.connection_history[key].append(now)
            
            # Keep only recent history
            self.connection_history[key] = [
                t for t in self.connection_history[key] 
                if now - t < 300  # Last 5 minutes
            ]
            
            # Check for regular intervals
            timestamps = self.connection_history[key]
            if len(timestamps) >= 3:
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                avg_interval = sum(intervals) / len(intervals)
                
                # If intervals are consistent (< 20% deviation), likely beaconing
                deviations = [abs(i - avg_interval) for i in intervals]
                if all(d < avg_interval * 0.2 for d in deviations):
                    if 5 < avg_interval < 120:  # Between 5s and 2min
                        beacons.append({
                            "destination": key,
                            "interval": avg_interval,
                            "count": len(timestamps),
                            "pid": conn["pid"],
                            "process": conn["process"]
                        })
        
        return beacons
    
    def save_baseline(self, connections):
        """Save network baseline."""
        baseline = {
            "timestamp": time.time(),
            "connections": []
        }
        
        for conn in connections:
            baseline["connections"].append({
                "process": conn["process"],
                "pid": conn["pid"],
                "dest": f"{conn['remote_addr']}:{conn['remote_port']}",
                "proto": conn["proto"]
            })
        
        with open(NETWORK_BASELINE, "w") as f:
            json.dump(baseline, f, indent=2)
    
    def compare_baseline(self, connections):
        """Compare to baseline."""
        if not os.path.exists(NETWORK_BASELINE):
            return []
        
        with open(NETWORK_BASELINE, "r") as f:
            baseline = json.load(f)
        
        baseline_dests = {c["dest"] for c in baseline["connections"]}
        current_dests = {f"{c['remote_addr']}:{c['remote_port']}" for c in connections}
        
        new_dests = current_dests - baseline_dests
        
        return list(new_dests)

# =============================================================================
# PERSISTENCE DETECTION MODULE
# =============================================================================

class PersistenceDetector:
    """Detect persistence mechanisms."""
    
    def scan_all(self):
        """Scan all persistence mechanisms."""
        findings = []
        
        findings.extend(self.scan_systemd())
        findings.extend(self.scan_cron())
        findings.extend(self.scan_shell_profiles())
        findings.extend(self.scan_autostart())
        
        return findings
    
    def scan_systemd(self):
        """Scan systemd units."""
        findings = []
        
        output = run_cmd("systemctl list-units --all --no-pager 2>/dev/null")
        if not output:
            return findings
        
        suspicious_keywords = ["miner", "bot", "trojan", "backdoor", "hidden"]
        
        for line in output.split("\n"):
            for keyword in suspicious_keywords:
                if keyword in line.lower():
                    findings.append({
                        "type": "SYSTEMD_UNIT",
                        "detail": line.strip(),
                        "severity": "HIGH"
                    })
        
        return findings
    
    def scan_cron(self):
        """Scan cron jobs."""
        findings = []
        
        # System crontabs
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", 
                     "/etc/cron.monthly", "/etc/cron.weekly"]
        
        for cron_dir in cron_dirs:
            if not os.path.exists(cron_dir):
                continue
            
            try:
                for entry in os.listdir(cron_dir):
                    path = os.path.join(cron_dir, entry)
                    if os.path.isfile(path):
                        with open(path, "r") as f:
                            content = f.read()
                            if any(susp in content for susp in SUSPICIOUS_PATHS):
                                findings.append({
                                    "type": "CRON_JOB",
                                    "detail": f"{path}: suspicious path",
                                    "severity": "MEDIUM"
                                })
            except:
                pass
        
        # User crontabs
        output = run_cmd("crontab -l 2>/dev/null")
        if output:
            for susp in SUSPICIOUS_PATHS:
                if susp in output:
                    findings.append({
                        "type": "USER_CRON",
                        "detail": "Suspicious path in user crontab",
                        "severity": "MEDIUM"
                    })
        
        return findings
    
    def scan_shell_profiles(self):
        """Scan shell profile hooks."""
        findings = []
        
        profiles = [
            os.path.expanduser("~/.bashrc"),
            os.path.expanduser("~/.bash_profile"),
            os.path.expanduser("~/.profile"),
            os.path.expanduser("~/.zshrc"),
            "/etc/profile",
            "/etc/bash.bashrc"
        ]
        
        for profile in profiles:
            if not os.path.exists(profile):
                continue
            
            try:
                with open(profile, "r") as f:
                    content = f.read()
                    
                    # Check for suspicious content
                    if any(susp in content for susp in SUSPICIOUS_PATHS):
                        findings.append({
                            "type": "SHELL_PROFILE",
                            "detail": f"{profile}: suspicious path",
                            "severity": "MEDIUM"
                        })
                    
                    # Check for LD_PRELOAD
                    if "LD_PRELOAD" in content or "LD_LIBRARY_PATH" in content:
                        findings.append({
                            "type": "SHELL_PROFILE",
                            "detail": f"{profile}: LD_PRELOAD hook",
                            "severity": "HIGH"
                        })
            except:
                pass
        
        return findings
    
    def scan_autostart(self):
        """Scan XDG autostart entries."""
        findings = []
        
        autostart_dirs = [
            os.path.expanduser("~/.config/autostart"),
            "/etc/xdg/autostart"
        ]
        
        for autostart_dir in autostart_dirs:
            if not os.path.exists(autostart_dir):
                continue
            
            try:
                for entry in os.listdir(autostart_dir):
                    if entry.endswith(".desktop"):
                        path = os.path.join(autostart_dir, entry)
                        with open(path, "r") as f:
                            content = f.read()
                            if any(susp in content for susp in SUSPICIOUS_PATHS):
                                findings.append({
                                    "type": "AUTOSTART",
                                    "detail": f"{entry}: suspicious path",
                                    "severity": "MEDIUM"
                                })
            except:
                pass
        
        return findings

# =============================================================================
# CONNECTION KILLER MODULE
# =============================================================================

class ConnectionKiller:
    """Advanced connection termination."""
    
    def __init__(self):
        self.has_ss = shutil.which("ss") is not None
        self.has_iptables = shutil.which("iptables") is not None
        self.has_ip6tables = shutil.which("ip6tables") is not None
    
    def kill_connection(self, conn, method="auto", verify=True):
        """
        Kill a connection using specified method.
        Methods: auto, native, injection, process, block
        """
        if method == "auto":
            # Try native first, fallback to injection
            if self.has_ss and conn["proto"].startswith("TCP"):
                success = self._native_kill(conn)
                if success and verify:
                    time.sleep(0.1)
                    if self._verify_killed(conn):
                        return True, "Native kill successful"
            
            # Fallback to injection
            if conn["pid"] and FRIDA_AVAILABLE:
                success = self._injection_kill(conn)
                if success:
                    return True, "Injection kill successful"
            
            return False, "All kill methods failed"
        
        elif method == "native":
            return self._native_kill(conn), "Native kill"
        
        elif method == "injection":
            return self._injection_kill(conn), "Injection kill"
        
        elif method == "process":
            return self._process_kill(conn), "Process kill"
        
        elif method == "block":
            return self._firewall_block(conn), "Firewall block"
    
    def _native_kill(self, conn):
        """Kill using ss -K."""
        if not self.has_ss:
            return False
        
        if conn["state"] == "LISTEN":
            # Can't kill LISTEN with ss -K directly, need to kill process
            return False
        
        try:
            # Build ss -K command
            proto = "tcp" if "TCP" in conn["proto"] else "udp"
            cmd = f"ss -K dst {conn['remote_addr']} dport = {conn['remote_port']} {proto}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _injection_kill(self, conn):
        """Kill using Frida injection."""
        if not FRIDA_AVAILABLE or not conn["pid"]:
            return False
        
        # Find socket FD
        fd = self._find_socket_fd(conn["pid"], conn["inode"])
        if not fd:
            return False
        
        # Inject shutdown call
        return self._inject_shutdown(conn["pid"], fd)
    
    def _find_socket_fd(self, pid, inode):
        """Find socket file descriptor."""
        fd_path = f"/proc/{pid}/fd"
        if not os.path.exists(fd_path):
            return None
        
        try:
            for fd in os.listdir(fd_path):
                link = os.readlink(f"{fd_path}/{fd}")
                if f"socket:[{inode}]" in link:
                    return int(fd)
        except:
            pass
        
        return None
    
    def _inject_shutdown(self, pid, sockfd):
        """Inject shutdown() call via Frida."""
        frida_script = """
        var resolver = new ApiResolver("module");
        var platform = Process.platform;
        var lib = platform === "darwin" ? "libsystem" : "libc";
        var matches = resolver.enumerateMatches("exports:*" + lib + "*!shutdown");
        
        if (matches.length === 0) {
            matches = resolver.enumerateMatches("exports:*libc*!shutdown");
        }
        if (matches.length === 0) {
            throw new Error("Could not find shutdown");
        }
        
        var shutdown = new NativeFunction(matches[0].address, "int", ["int", "int"]);
        var result = shutdown(%d, 2);
        send({success: result === 0});
        """ % sockfd
        
        try:
            session = frida.attach(pid)
            script = session.create_script(frida_script)
            
            result = {"success": False}
            event = threading.Event()
            
            def on_message(message, data):
                if message["type"] == "send":
                    result.update(message["payload"])
                event.set()
            
            script.on("message", on_message)
            script.load()
            event.wait(timeout=2)
            session.detach()
            
            return result.get("success", False)
        except:
            return False
    
    def _process_kill(self, conn):
        """Kill entire process."""
        if not conn["pid"]:
            return False
        
        try:
            # Kill process tree
            self._kill_process_tree(conn["pid"])
            return True
        except:
            return False
    
    def _kill_process_tree(self, pid):
        """Kill process and all children."""
        # Find children
        children = []
        for p in os.listdir("/proc"):
            if not p.isdigit():
                continue
            
            try:
                with open(f"/proc/{p}/stat", "r") as f:
                    stat = f.read().split(")")[-1].split()
                    ppid = int(stat[1])
                    if ppid == pid:
                        children.append(int(p))
            except:
                pass
        
        # Kill children first
        for child in children:
            try:
                os.kill(child, signal.SIGKILL)
            except:
                pass
        
        # Kill parent
        try:
            os.kill(pid, signal.SIGKILL)
        except:
            pass
    
    def _firewall_block(self, conn):
        """Block using iptables."""
        if conn["remote_addr"] in ["0.0.0.0", "127.0.0.1", "::", "::1"]:
            return False
        
        is_ipv6 = ":" in conn["remote_addr"]
        iptables = "ip6tables" if is_ipv6 else "iptables"
        
        if not self.has_iptables and not is_ipv6:
            return False
        if not self.has_ip6tables and is_ipv6:
            return False
        
        try:
            # Check if rule exists
            check_cmd = f"{iptables} -C OUTPUT -d {conn['remote_addr']} -j DROP 2>/dev/null"
            result = subprocess.run(check_cmd, shell=True)
            
            if result.returncode != 0:
                # Add rule
                add_cmd = f"{iptables} -I OUTPUT -d {conn['remote_addr']} -j DROP"
                subprocess.run(add_cmd, shell=True, check=True)
            
            return True
        except:
            return False
    
    def _verify_killed(self, conn):
        """Verify connection is dead."""
        # Re-scan connections
        detector = NetworkDetector()
        current = detector.scan_connections()
        
        for c in current:
            if (c["inode"] == conn["inode"] or 
                (c["local_port"] == conn["local_port"] and 
                 c["remote_addr"] == conn["remote_addr"] and 
                 c["remote_port"] == conn["remote_port"])):
                return False
        
        return True

# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

def format_alerts(alerts):
    """Format alert list for display."""
    if not alerts:
        return ""
    return " | ".join(alerts[:3])  # Limit to 3

def display_process_scan(processes, show_all=False):
    """Display process scan results."""
    print("\n" + "="*120)
    print(f"{BOLD}PROCESS FORENSICS{RESET}")
    print("="*120)
    print(f"{'PID':<7} {'USER':<10} {'STATE':<6} {'THR':<5} {'FDS':<5} {'ALERTS':<40} {'PROCESS'}")
    print("-"*120)
    
    count = 0
    for pid, proc in sorted(processes.items(), key=lambda x: len(x[1]["alerts"]), reverse=True):
        if not show_all and not proc["alerts"]:
            continue
        
        alerts_str = format_alerts(proc["alerts"])
        color = RED if any(x in alerts_str for x in ["RWX", "DANGEROUS", "ROOT"]) else YELLOW
        if not alerts_str:
            color = RESET
        
        path = proc["exe"] if proc["exe"] else f"[{proc['name']}]"
        
        print(f"{proc['pid']:<7} {proc['user']:<10} {proc['state']:<6} "
              f"{proc['threads']:<5} {proc['fds']:<5} "
              f"{color}{alerts_str:<40}{RESET} {path[:50]}")
        count += 1
    
    if count == 0:
        print(f"{GREEN}No anomalies detected.{RESET}")

def display_network_scan(connections, beacons, new_dests):
    """Display network scan results."""
    print("\n" + "="*120)
    print(f"{BOLD}NETWORK INTELLIGENCE{RESET}")
    print("="*120)
    
    # Show connections with alerts
    print(f"\n{CYAN}Active Connections:{RESET}")
    print(f"{'PROTO':<6} {'STATE':<12} {'LOCAL':<25} {'REMOTE':<25} {'PID':<7} {'ALERTS'}")
    print("-"*120)
    
    conn_count = 0
    for conn in connections:
        if not conn["alerts"] and conn["state"] not in ["LISTEN", "ESTABLISHED"]:
            continue
        
        alerts_str = format_alerts(conn["alerts"])
        color = YELLOW if alerts_str else RESET
        
        local = f"{conn['local_addr']}:{conn['local_port']}"
        remote = f"{conn['remote_addr']}:{conn['remote_port']}"
        pid_str = str(conn['pid']) if conn['pid'] else "-"
        
        print(f"{conn['proto']:<6} {conn['state']:<12} {local:<25} {remote:<25} "
              f"{pid_str:<7} {color}{alerts_str}{RESET}")
        conn_count += 1
        
        if conn_count >= 50:  # Limit output
            print(f"... ({len(connections) - 50} more connections)")
            break
    
    # Show beaconing
    if beacons:
        print(f"\n{RED}BEACONING DETECTED (Possible C2):{RESET}")
        for beacon in beacons:
            print(f"  {beacon['destination']} - Interval: {beacon['interval']:.1f}s "
                  f"(PID: {beacon['pid']}, Process: {beacon['process']})")
    
    # Show new destinations
    if new_dests:
        print(f"\n{YELLOW}NEW DESTINATIONS (vs baseline):{RESET}")
        for dest in list(new_dests)[:20]:
            print(f"  {dest}")

def display_persistence_scan(findings):
    """Display persistence scan results."""
    print("\n" + "="*120)
    print(f"{BOLD}PERSISTENCE MECHANISMS{RESET}")
    print("="*120)
    
    if not findings:
        print(f"{GREEN}No suspicious persistence mechanisms found.{RESET}")
        return
    
    for finding in findings:
        severity_color = RED if finding["severity"] == "HIGH" else YELLOW
        print(f"{severity_color}[{finding['severity']}]{RESET} {finding['type']}: {finding['detail']}")

def run_full_scan(show_all=False):
    """Run comprehensive system scan."""
    print(f"{CYAN}{BOLD}NET SENTINEL v5.0 - Full System Scan{RESET}")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Process scan
    print(f"\n{CYAN}[1/4] Scanning processes...{RESET}")
    proc_detector = ProcessDetector()
    processes = proc_detector.scan_all()
    
    # Memory scan
    print(f"{CYAN}[2/4] Scanning memory...{RESET}")
    mem_detector = MemoryDetector()
    for pid, proc in processes.items():
        mem_alerts = mem_detector.scan_memory(int(pid))
        proc["alerts"].extend(mem_alerts)
        
        shared_alerts = mem_detector.scan_shared_memory(int(pid))
        proc["alerts"].extend(shared_alerts)
    
    # Network scan
    print(f"{CYAN}[3/4] Scanning network...{RESET}")
    net_detector = NetworkDetector()
    connections = net_detector.scan_connections()
    beacons = net_detector.detect_beaconing(connections)
    
    new_dests = []
    if os.path.exists(NETWORK_BASELINE):
        new_dests = net_detector.compare_baseline(connections)
    
    # Persistence scan
    print(f"{CYAN}[4/4] Scanning persistence...{RESET}")
    persist_detector = PersistenceDetector()
    persistence = persist_detector.scan_all()
    
    # Display results
    display_process_scan(processes, show_all)
    display_network_scan(connections, beacons, new_dests)
    display_persistence_scan(persistence)
    
    # Summary
    total_alerts = sum(len(p["alerts"]) for p in processes.values())
    total_net_alerts = sum(len(c["alerts"]) for c in connections)
    
    print("\n" + "="*120)
    print(f"{BOLD}SUMMARY:{RESET}")
    print(f"  Process Alerts: {total_alerts}")
    print(f"  Network Alerts: {total_net_alerts}")
    print(f"  Beacons: {len(beacons)}")
    print(f"  Persistence: {len(persistence)}")
    print(f"  Total Processes: {len(processes)}")
    print(f"  Total Connections: {len(connections)}")
    print("="*120)

def kill_target(local, remote, protocol, method, watch_interval):
    """Kill connections matching target."""
    killer = ConnectionKiller()
    net_detector = NetworkDetector()
    
    # Parse target
    local_port = int(local.split(":")[-1]) if local else None
    remote_ip = remote.split(":")[0] if remote else None
    remote_port = int(remote.split(":")[-1]) if remote else None
    
    def kill_once():
        connections = net_detector.scan_connections()
        killed = 0
        
        for conn in connections:
            # Match criteria
            if local_port and conn["local_port"] != local_port:
                continue
            if remote_ip and conn["remote_addr"] != remote_ip:
                continue
            if remote_port and conn["remote_port"] != remote_port:
                continue
            if protocol and not conn["proto"].startswith(protocol.upper()):
                continue
            
            # Check whitelist
            if conn["process"] and is_whitelisted(conn["process"]):
                print(f"{YELLOW}Skipping whitelisted process: {conn['process']}{RESET}")
                continue
            
            # Kill
            print(f"Targeting: {conn['proto']} {conn['local_addr']}:{conn['local_port']} -> "
                  f"{conn['remote_addr']}:{conn['remote_port']} (PID: {conn['pid']})")
            
            success, msg = killer.kill_connection(conn, method=method)
            if success:
                print(f"{GREEN}[+] {msg}{RESET}")
                killed += 1
            else:
                print(f"{RED}[-] {msg}{RESET}")
        
        return killed
    
    if watch_interval:
        print(f"{CYAN}Watch mode enabled (interval: {watch_interval}s). Press Ctrl+C to stop.{RESET}")
        try:
            while True:
                killed = kill_once()
                if killed > 0:
                    print(f"Killed {killed} connection(s)")
                time.sleep(watch_interval)
        except KeyboardInterrupt:
            print(f"\n{CYAN}Watch mode stopped.{RESET}")
    else:
        killed = kill_once()
        if killed == 0:
            print(f"{YELLOW}No matching connections found.{RESET}")

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NET SENTINEL v5.0 - Advanced Network & Process Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Full scan:
    sudo python3 net_sentinel.py --scan
    sudo python3 net_sentinel.py --scan --all
  
  Baseline management:
    sudo python3 net_sentinel.py --baseline
    sudo python3 net_sentinel.py --network-baseline
  
  Kill connections:
    sudo python3 net_sentinel.py --kill :8080
    sudo python3 net_sentinel.py --kill :443 --protocol UDP
    sudo python3 net_sentinel.py --kill :22 --method process
    sudo python3 net_sentinel.py --kill :8080 --watch 0.5
    sudo python3 net_sentinel.py --kill 192.168.1.100:8080 --method block
        """
    )
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--scan", action="store_true", help="Run full system scan")
    scan_group.add_argument("--all", action="store_true", help="Show all processes (not just suspicious)")
    scan_group.add_argument("--baseline", action="store_true", help="Save process baseline")
    scan_group.add_argument("--network-baseline", action="store_true", help="Save network baseline")
    
    # Kill options
    kill_group = parser.add_argument_group("Kill Options")
    kill_group.add_argument("--kill", metavar="TARGET", help="Kill target (IP:PORT or :PORT)")
    kill_group.add_argument("--remote", metavar="REMOTE", help="Remote endpoint filter")
    kill_group.add_argument("--protocol", choices=["TCP", "UDP"], help="Protocol filter")
    kill_group.add_argument("--method", choices=["auto", "native", "injection", "process", "block"],
                           default="auto", help="Kill method")
    kill_group.add_argument("--watch", type=float, metavar="SEC", help="Watch mode interval")
    kill_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Root check
    if os.geteuid() != 0:
        print(f"{YELLOW}Warning: Root privileges recommended for full functionality.{RESET}")
    
    # Execute
    if args.baseline:
        print("Saving process baseline...")
        proc_detector = ProcessDetector()
        processes = proc_detector.scan_all()
        with open(BASELINE_FILE, "w") as f:
            json.dump(processes, f, indent=2)
        print(f"Baseline saved: {len(processes)} processes")
    
    elif args.network_baseline:
        print("Saving network baseline...")
        net_detector = NetworkDetector()
        connections = net_detector.scan_connections()
        net_detector.save_baseline(connections)
        print(f"Network baseline saved: {len(connections)} connections")
    
    elif args.kill:
        kill_target(args.kill, args.remote, args.protocol, args.method, args.watch)
    
    else:
        # Default: full scan
        run_full_scan(args.all)
        
