#!/usr/bin/env python3
# Copyright 2026.
# Process Reveal v2.0 - System Intelligence & Anomaly Baseline
#
# UPDATES:
# - Added Memory Map Scanning (W^X Violation Detection)
# - Added Environment Hook Detection (LD_PRELOAD)
# - Integrated full forensic tracking

import os
import sys
import argparse
import pwd
import json
import time
from datetime import datetime

BASELINE_FILE = "process_baseline.json"

# Color Codes
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def scan_memory_anomalies(pid):
    """
    Scans for Process Hollowing and Code Injection.
    Looks for memory segments that are both Writable AND Executable (rwx).
    """
    maps_path = f"/proc/{pid}/maps"
    anomalies = []
    
    if not os.path.exists(maps_path):
        return []

    try:
        with open(maps_path, "r") as f:
            for line in f:
                # Example: 00400000-0040b000 r-xp ...
                parts = line.split()
                perms = parts[1]
                
                # CHECK: The "RWX" Violation
                if "w" in perms and "x" in perms:
                    path = parts[-1] if len(parts) > 5 else "[Anonymous Memory]"
                    
                    if "[stack]" in path or "[heap]" in path:
                        anomalies.append(f"RWX_STACK/HEAP")
                    elif path == "[Anonymous Memory]":
                         anomalies.append("RWX_ANONYMOUS (Injection Risk)")
                    elif not path.startswith("/dev/"):
                        # Generic RWX alert for weird files
                        anomalies.append(f"RWX_SEGMENT")
    except (PermissionError, FileNotFoundError, OSError):
        pass

    return anomalies

def check_environment_hooks(pid):
    """
    Checks for LD_PRELOAD hooks used by user-land rootkits.
    """
    env_path = f"/proc/{pid}/environ"
    hooks = []
    try:
        with open(env_path, "rb") as f:
            # Environ is null-separated
            env_data = f.read().replace(b'\x00', b'\n').decode('utf-8', errors='ignore')
            for line in env_data.split('\n'):
                if line.startswith("LD_PRELOAD="):
                     # Clean up the string for display
                     val = line.split('=', 1)[1]
                     if val: # Only alert if it's not empty
                        hooks.append(f"PRELOAD_HOOK: {val}")
    except (PermissionError, FileNotFoundError, OSError):
        pass
        
    return hooks

def get_proc_data(pid):
    """Deep inspection of a single process node."""
    p_path = f"/proc/{pid}"
    if not os.path.exists(p_path):
        return None

    data = {
        "pid": pid,
        "name": "?",
        "ppid": 0,
        "uid": -1,
        "user": "?",
        "rss": 0,    # RAM
        "swap": 0,   # Disk Swap
        "exe": "",   # Binary Path
        "cwd": "",   # Working Directory
        "cmdline": "",
        "hidden": False,
        "alerts": []
    }

    try:
        # 1. Status Parsing
        with open(f"{p_path}/status", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2: continue
                key, val = parts[0].strip(":"), parts[1]
                
                if key == "Name": data["name"] = val
                elif key == "PPid": data["ppid"] = int(val)
                elif key == "Uid": 
                    data["uid"] = int(val)
                    try: data["user"] = pwd.getpwuid(int(val)).pw_name
                    except: data["user"] = str(val)
                elif key == "VmRSS": data["rss"] = int(val)
                elif key == "VmSwap": data["swap"] = int(val)

        # 2. Cmdline Parsing
        try:
            with open(f"{p_path}/cmdline", "rb") as f:
                data["cmdline"] = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
        except: pass

        # 3. Path Resolution & Hidden Check
        try:
            data["exe"] = os.readlink(f"{p_path}/exe")
            if " (deleted)" in data["exe"]:
                data["hidden"] = True
                data["alerts"].append("DELETED_BINARY")
        except (FileNotFoundError, OSError):
            pass
        
        # 4. SWAP Check
        if data["swap"] > 10000 and data["rss"] < 1000:
            data["alerts"].append("SWAP_HIDER")

        # 5. NEW: Injection & Rootkit Checks
        mem_alerts = scan_memory_anomalies(pid)
        if mem_alerts:
            data["alerts"].extend(mem_alerts)
            
        hook_alerts = check_environment_hooks(pid)
        if hook_alerts:
            data["alerts"].extend(hook_alerts)

    except Exception:
        return None 

    return data

def scan_processes():
    """Returns a dictionary of all active processes."""
    pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
    snapshot = {}
    for pid in pids:
        info = get_proc_data(pid)
        if info:
            snapshot[str(pid)] = info
    return snapshot

def save_baseline():
    """Saves current state as the 'Normal' baseline."""
    print(f"[*] Establishing baseline...")
    current = scan_processes()
    with open(BASELINE_FILE, "w") as f:
        json.dump(current, f, indent=2)
    print(f"[*] Baseline established: {len(current)} processes tracked.")

def diff_scan():
    """Compares current state against baseline."""
    if not os.path.exists(BASELINE_FILE):
        print(f"{RED}[!] No baseline found. Run --baseline first.{RESET}")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)
    
    current = scan_processes()
    
    print(f"[*] Comparing {len(current)} current processes against {len(baseline)} baseline entries...")
    print("-" * 120)
    print(f"{'PID':<7} {'USER':<10} {'ALERTS / DIFF':<40} {'PROCESS'}")
    print("-" * 120)
    
    anomalies = 0

    for pid_str, info in current.items():
        pid = int(pid_str)
        alerts = info['alerts']
        
        # Check 1: Is this PID new?
        if pid_str not in baseline:
            alerts.append("NEW_PROCESS")
        
        # Check 2: Did it develop new alerts?
        if alerts:
            alert_str = " | ".join(alerts)
            path = info['exe'] if info['exe'] else f"[{info['name']}]"
            
            # Color coding
            c_code = RED if "RWX" in alert_str or "PRELOAD" in alert_str else YELLOW
            
            print(f"{pid:<7} {info['user']:<10} {c_code}{alert_str:<40}{RESET} {path}")
            anomalies += 1
            
    if anomalies == 0:
        print("[*] System clean. No deviations or threats detected.")
    else:
        print("-" * 120)
        print(f"{RED}[!] WARNING: {anomalies} anomalies detected.{RESET}")

def full_dump(show_all=False):
    """Dumps process list with Parent/Swap/Injection tracking."""
    procs = scan_processes()
    
    print(f"{'PID':<7} {'PPID':<7} {'USER':<10} {'RSS':<8} {'SWAP':<8} {'ALERTS':<30} {'PATH'}")
    print("-" * 120)
    
    for pid, i in procs.items():
        alerts = i['alerts']
        
        if not show_all and not alerts:
            continue
            
        path = i['exe']
        if not path: path = f"[{i['name']}]"
        
        alert_str = " ".join(alerts)
        if alert_str:
            alert_str = f"{RED}{alert_str}{RESET}"
            
        print(f"{i['pid']:<7} {i['ppid']:<7} {i['user']:<10} {i['rss']:<8} {i['swap']:<8} {alert_str:<40} {path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Reveal v2.0: Deep Forensic Scanner")
    parser.add_argument("--baseline", action="store_true", help="Establish the 'Normal' warning baseline.")
    parser.add_argument("--scan", action="store_true", help="View current interesting processes.")
    parser.add_argument("--all", action="store_true", help="Used with --scan to show EVERYTHING.")
    parser.add_argument("--diff", action="store_true", help="Compare current to Baseline.")
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print(f"{YELLOW}[!] Warning: Run as root to see memory maps and hidden paths.{RESET}")

    if args.baseline:
        save_baseline()
    elif args.diff:
        diff_scan()
    else:
        full_dump(args.all)
