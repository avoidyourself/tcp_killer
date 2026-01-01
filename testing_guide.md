# NET SENTINEL v5.0 - Testing & Validation Guide

## Overview

This guide provides safe methods to test NET SENTINEL's detection and killing capabilities without deploying actual malware.

---

## Test Environment Setup

### Prerequisites

```bash
# Install test tools
sudo apt install netcat socat python3 gcc

# Create test directory
mkdir ~/sentinel_tests
cd ~/sentinel_tests
```

---

## Detection Testing

### Test 1: Suspicious Binary Location

**Create test binary in /tmp**:
```bash
# Compile simple program
cat > /tmp/test_suspicious.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
    printf("Test process\n");
    sleep(3600);
    return 0;
}
EOF

gcc /tmp/test_suspicious.c -o /tmp/test_suspicious
/tmp/test_suspicious &
TEST_PID=$!

# Scan for alert
sudo python3 net_sentinel.py --scan

# Expected: SUSPICIOUS_PATH:/tmp alert
# Clean up
kill $TEST_PID
```

---

### Test 2: Deleted Binary Detection

**Run binary then delete it**:
```bash
# Create and run binary
cat > ~/test_deleted.c << 'EOF'
#include <unistd.h>
int main() { sleep(3600); return 0; }
EOF

gcc ~/test_deleted.c -o ~/test_deleted
~/test_deleted &
TEST_PID=$!

# Delete the binary
rm ~/test_deleted

# Scan
sudo python3 net_sentinel.py --scan

# Expected: DELETED_BINARY alert
# Clean up
kill $TEST_PID
```

---

### Test 3: High Thread Count

**Create multi-threaded process**:
```bash
cat > test_threads.py << 'EOF'
import threading
import time

def worker():
    time.sleep(3600)

# Spawn 150 threads
threads = []
for i in range(150):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

time.sleep(3600)
EOF

python3 test_threads.py &
TEST_PID=$!

# Scan
sudo python3 net_sentinel.py --scan

# Expected: HIGH_THREADS:150 alert
# Clean up
kill $TEST_PID
```

---

### Test 4: High File Descriptor Count

**Open many files**:
```bash
cat > test_fds.py << 'EOF'
import time

files = []
for i in range(600):
    try:
        files.append(open(f'/tmp/test_fd_{i}', 'w'))
    except:
        break

time.sleep(3600)
EOF

python3 test_fds.py &
TEST_PID=$!

# Scan
sudo python3 net_sentinel.py --scan

# Expected: HIGH_FDS alert
# Clean up
kill $TEST_PID
rm /tmp/test_fd_*
```

---

### Test 5: Network Listener Detection

**Create listener on high port**:
```bash
# Start listener on port 51234
nc -l 51234 &
TEST_PID=$!

# Scan
sudo python3 net_sentinel.py --scan

# Expected: HIGH_PORT_LISTENER:51234 or LISTEN_ALL_INTERFACES:51234
# Clean up
kill $TEST_PID
```

---

### Test 6: Beaconing Detection (Simulated C2)

**Create periodic connection pattern**:
```bash
# Server side (run in one terminal)
while true; do nc -l 8888 < /dev/null; done &
SERVER_PID=$!

# Client side (beaconing - run in another terminal)
cat > beacon_test.sh << 'EOF'
#!/bin/bash
for i in {1..10}; do
    echo "Beacon $i" | nc localhost 8888
    sleep 10  # 10 second interval
done
EOF

chmod +x beacon_test.sh
./beacon_test.sh &
CLIENT_PID=$!

# After 30+ seconds, scan
sudo python3 net_sentinel.py --scan

# Expected: BEACONING DETECTED with ~10s interval
# Clean up
kill $SERVER_PID $CLIENT_PID
```

---

### Test 7: CLOSE_WAIT Zombie Detection

**Create zombie connection**:
```bash
# Server that doesn't close properly
python3 << 'EOF' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 9999))
s.listen(1)
conn, addr = s.accept()
# Don't close - creates CLOSE_WAIT on client
import time
time.sleep(3600)
EOF
SERVER_PID=$!

sleep 2

# Client that closes
python3 << 'EOF' &
import socket
s = socket.socket()
s.connect(('127.0.0.1', 9999))
s.close()  # Client closes, server doesn't = CLOSE_WAIT
import time
time.sleep(3600)
EOF

sleep 2

# Scan
sudo python3 net_sentinel.py --scan

# Expected: ZOMBIE_CONN alert
# Clean up
kill $SERVER_PID
```

---

## Killing Testing

### Test 8: Kill TCP Connection

**Setup**:
```bash
# Terminal 1: Server
nc -l 8080 &
SERVER_PID=$!

# Terminal 2: Client
nc localhost 8080 &
CLIENT_PID=$!

# Verify connection
sudo lsof -i :8080
```

**Test Kill**:
```bash
# Kill the connection
sudo python3 net_sentinel.py --kill :8080

# Verify killed
sudo lsof -i :8080  # Should show nothing

# Clean up
kill $SERVER_PID $CLIENT_PID 2>/dev/null
```

---

### Test 9: Kill UDP Connection

**Setup**:
```bash
# UDP listener
nc -u -l 9999 &
SERVER_PID=$!

# UDP client
nc -u localhost 9999 &
CLIENT_PID=$!
```

**Test Kill**:
```bash
sudo python3 net_sentinel.py --kill :9999 --protocol UDP

# Clean up
kill $SERVER_PID $CLIENT_PID 2>/dev/null
```

---

### Test 10: Kill Method Comparison

**Test all kill methods**:
```bash
# Test script
cat > test_kill_methods.sh << 'EOF'
#!/bin/bash

test_method() {
    METHOD=$1
    echo "Testing method: $METHOD"
    
    # Start test server
    nc -l 7777 &
    SERVER_PID=$!
    sleep 1
    
    # Connect
    nc localhost 7777 &
    CLIENT_PID=$!
    sleep 1
    
    # Kill with method
    sudo python3 net_sentinel.py --kill :7777 --method $METHOD
    
    # Check if killed
    if sudo lsof -i :7777 > /dev/null 2>&1; then
        echo "FAIL: Connection still exists"
    else
        echo "PASS: Connection killed"
    fi
    
    # Clean up
    kill $SERVER_PID $CLIENT_PID 2>/dev/null
    sleep 1
}

test_method "native"
test_method "injection"
test_method "process"
EOF

chmod +x test_kill_methods.sh
./test_kill_methods.sh
```

---

### Test 11: Firewall Block Testing

**Test IPTables blocking**:
```bash
# Start server
nc -l 8888 &
SERVER_PID=$!

# Block with firewall
sudo python3 net_sentinel.py --kill :8888 --remote 127.0.0.1:8888 --method block

# Verify rule exists
sudo iptables -L OUTPUT -n | grep 127.0.0.1

# Try to connect (should fail)
timeout 2 nc localhost 8888 && echo "FAIL: Connected" || echo "PASS: Blocked"

# Clean up rule
sudo iptables -D OUTPUT -d 127.0.0.1 -j DROP
kill $SERVER_PID 2>/dev/null
```

---

### Test 12: Watch Mode Testing

**Test continuous monitoring**:
```bash
# Create reconnecting client
cat > reconnect_test.sh << 'EOF'
#!/bin/bash
# Server
while true; do 
    nc -l 6666 < /dev/null
    sleep 0.5
done &
SERVER_PID=$!

# Auto-reconnecting client
while true; do
    echo "test" | nc localhost 6666
    sleep 1
done &
CLIENT_PID=$!

echo $SERVER_PID > /tmp/test_pids
echo $CLIENT_PID >> /tmp/test_pids
EOF

chmod +x reconnect_test.sh
./reconnect_test.sh

# In another terminal, run watch mode
sudo python3 net_sentinel.py --kill :6666 --watch 0.5

# Should continuously kill connections
# Press Ctrl+C to stop

# Clean up
kill $(cat /tmp/test_pids)
rm /tmp/test_pids
```

---

## Baseline Testing

### Test 13: Process Baseline

```bash
# Establish clean baseline
sudo python3 net_sentinel.py --baseline

# Start new process
sleep 3600 &
NEW_PID=$!

# Scan again - should show NEW_PROCESS
sudo python3 net_sentinel.py --scan

# Clean up
kill $NEW_PID
```

---

### Test 14: Network Baseline

```bash
# Establish network baseline
sudo python3 net_sentinel.py --network-baseline

# Create new connection
nc -l 7777 &
TEST_PID=$!

# Scan - should show new destination
sudo python3 net_sentinel.py --scan

# Clean up
kill $TEST_PID
```

---

## Persistence Testing

### Test 15: Detect Suspicious Cron Job

```bash
# Add test cron job with suspicious path
(crontab -l 2>/dev/null; echo "* * * * * /tmp/suspicious_script") | crontab -

# Scan persistence
sudo python3 net_sentinel.py --scan

# Expected: Alert about suspicious path in cron

# Clean up
crontab -l | grep -v "/tmp/suspicious_script" | crontab -
```

---

### Test 16: Detect Shell Profile Hook

```bash
# Add test hook to bashrc
echo 'export LD_PRELOAD=/tmp/hook.so' >> ~/.bashrc

# Scan
sudo python3 net_sentinel.py --scan

# Expected: Shell profile LD_PRELOAD alert

# Clean up
sed -i '/LD_PRELOAD/d' ~/.bashrc
```

---

## Performance Testing

### Test 17: Large Process Scan

```bash
# Spawn many processes
for i in {1..500}; do
    sleep 3600 &
done

# Time the scan
time sudo python3 net_sentinel.py --scan

# Expected: < 5 seconds for 500 processes

# Clean up
killall sleep
```

---

### Test 18: High Connection Load

```bash
# Create many connections
for port in {10000..10100}; do
    nc -l $port &
done

# Scan
time sudo python3 net_sentinel.py --scan

# Clean up
killall nc
```

---

## Validation Checklist

### Detection Validation

- [ ] Suspicious paths detected (/tmp, /dev/shm)
- [ ] Deleted binaries detected
- [ ] High thread count detected (>100)
- [ ] High FD count detected (>500)
- [ ] RWX memory segments detected
- [ ] Listening on 0.0.0.0 detected
- [ ] High port listeners detected (>50000)
- [ ] Beaconing patterns detected
- [ ] CLOSE_WAIT zombies detected
- [ ] Dangerous capabilities detected

### Killing Validation

- [ ] TCP connections killed (native method)
- [ ] TCP connections killed (injection method)
- [ ] UDP connections killed
- [ ] Process tree killed
- [ ] Firewall rules added correctly
- [ ] IPv6 connections handled
- [ ] Watch mode loops correctly
- [ ] Kill verification works
- [ ] Whitelist protection works

### Baseline Validation

- [ ] Process baseline saves correctly
- [ ] Network baseline saves correctly
- [ ] New processes detected after baseline
- [ ] New connections detected after baseline

---

## Safety Tests

### Test 19: Whitelist Protection

```bash
# Try to kill whitelisted process (should be protected)
sudo python3 net_sentinel.py --kill :22  # SSH

# Should see: "Skipping whitelisted process: sshd"
```

---

### Test 20: Localhost Block Protection

```bash
# Try to block localhost (should refuse)
sudo python3 net_sentinel.py --kill :8080 --remote 127.0.0.1:8080 --method block

# Should refuse to block localhost
```

---

## Automated Test Suite

```bash
cat > run_all_tests.sh << 'EOF'
#!/bin/bash

echo "NET SENTINEL Test Suite"
echo "======================="

PASS=0
FAIL=0

run_test() {
    TEST_NAME=$1
    TEST_CMD=$2
    
    echo -n "Running $TEST_NAME... "
    if eval "$TEST_CMD" > /tmp/test_output 2>&1; then
        echo "PASS"
        ((PASS++))
    else
        echo "FAIL"
        cat /tmp/test_output
        ((FAIL++))
    fi
}

# Add your tests here
run_test "Basic Scan" "sudo python3 net_sentinel.py --scan > /dev/null"
run_test "Baseline Creation" "sudo python3 net_sentinel.py --baseline"
run_test "Network Baseline" "sudo python3 net_sentinel.py --network-baseline"

echo ""
echo "Results: $PASS passed, $FAIL failed"
EOF

chmod +x run_all_tests.sh
./run_all_tests.sh
```

---

## Common Issues

### Frida injection fails
```bash
# Check Frida installation
python3 -c "import frida; print(frida.__version__)"

# Reinstall if needed
pip3 install --upgrade frida frida-tools
```

### Native kill doesn't work
```bash
# Check ss availability
which ss

# Install if missing
sudo apt install iproute2
```

### Permissions errors
```bash
# Always use sudo
sudo python3 net_sentinel.py --scan
```

---

## Test Data Cleanup

```bash
# Clean up all test artifacts
cat > cleanup.sh << 'EOF'
#!/bin/bash
killall sleep nc netcat python3 2>/dev/null
rm -f /tmp/test_* ~/test_* *.pyc
rm -f sentinel_baseline_v5.json network_baseline_v5.json
sudo iptables -F OUTPUT  # WARNING: Removes all OUTPUT rules
crontab -l | grep -v "/tmp/" | crontab -
EOF

chmod +x cleanup.sh
# Review before running!
# ./cleanup.sh
```

---

## Reporting Issues

When reporting bugs, include:

1. Test case that reproduces issue
2. NET SENTINEL output
3. System information:
```bash
uname -a
python3 --version
sudo lsof -v
ss -V
```

4. Configuration used
5. Expected vs actual behavior

---

## Next Steps

After testing:
1. Review `README_ADVANCED.md` for production deployment
2. Customize `config.yaml` for your environment
3. Set up automated monitoring
4. Integrate with incident response procedures
