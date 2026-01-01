```markdown
# tcp_killer (v2.0)

**Advanced Connection Termination for Linux & macOS**

`tcp_killer` shuts down TCP and UDP connections on Linux or macOS. It finds the process and socket file descriptor associated with a given connection and injects code to shut it down.

**New in v2.0:**
* **Python 3 Support:** Fully modernized codebase.
* **UDP & QUIC Support:** Now targets UDP sockets (essential for killing HTTP/3 and QUIC connections).
* **Persistence Monitoring:** A new `--watch` mode to continuously kill connections that attempt to auto-restart.
* **Nuclear Option:** A `--kill-process` flag to terminate the entire process if the socket cannot be closed gracefully.

The functionality mimics [TCPView](https://technet.microsoft.com/en-us/sysinternals/tcpview.aspx)'s "Close Connection" and [tcpdrop](http://man.openbsd.org/tcpdrop.8)'s functionality, but with added persistence features.

## Usage

**Note:** This script usually requires `sudo` (root privileges) to inspect and inject into processes owned by other users.

```bash
sudo python3 tcp_killer.py [options] <local endpoint> [remote endpoint]

```

### Arguments

| Argument | Description |
| --- | --- |
| `local endpoint` | The local IP address and port (e.g., `127.0.0.1:8080` or `:8080`). |
| `remote endpoint` | (Optional) The remote IP address and port. If omitted, it targets *any* connection on the local port. |
| `-v`, `--verbose` | Show verbose output (PID, FD details). |
| `--udp` | Target UDP sockets (includes QUIC/HTTP3). |
| `--tcp` | Target TCP sockets (Default if unspecified). |
| `-w`, `--watch SECONDS` | Run in a loop, checking for the connection every X seconds. |
| `--kill-process` | **Aggressive:** If the connection is found, kill the entire process (SIGKILL) instead of just closing the socket. |

## Examples

### 1. Basic TCP Kill

Shut down a specific TCP connection between local port 50246 and remote port 443.

```bash
sudo python3 tcp_killer.py 10.31.33.7:50246 93.184.216.34:443

```

### 2. Kill UDP / QUIC Connections

Shut down any UDP connection on port 443 (effectively killing QUIC/HTTP3 traffic on that port).

```bash
sudo python3 tcp_killer.py :443 --udp

```

### 3. Persistence Mode (Anti-Auto-Restart)

Continuously monitor for a connection on port 8080 and kill it every 0.5 seconds. Useful for stopping services that immediately reconnect.

```bash
sudo python3 tcp_killer.py :8080 --watch 0.5

```

### 4. The "Nuclear Option"

If a malware beacon or stubborn process refuses to drop the connection, this finds the process attached to the remote IP `192.168.1.50` and kills the process entirely.

```bash
sudo python3 tcp_killer.py 0.0.0.0:0 192.168.1.50:80 --kill-process

```

## Full Walkthrough

```bash
geffner@ubuntu:~$ # 1. Create a persistent listener (simulating a service)
geffner@ubuntu:~$ nc -l -u -p 9999 &
[1] 135578

geffner@ubuntu:~$ # 2. Verify it is running
geffner@ubuntu:~$ sudo lsof -i :9999
COMMAND   PID    USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
nc      135578 geffner   3u  IPv4 999999      0t0  UDP *:9999

geffner@ubuntu:~$ # 3. Kill it using tcp_killer (targeting UDP)
geffner@ubuntu:~$ sudo python3 tcp_killer.py :9999 --udp --verbose
Found UDP connection: *:9999 (PID: 135578, FD: 3)
Successfully shutdown socket FD 3 in PID 135578

geffner@ubuntu:~$ # 4. Verify the socket is gone
geffner@ubuntu:~$ sudo lsof -i :9999
(No output - connection closed)

```

## Dependencies

### Python 3 & Lsof

Ensure you have Python 3 and `lsof` installed.

```bash
sudo apt-get install python3 lsof
# or on macOS
brew install lsof

```

### Frida

This program uses [frida](https://www.frida.re/) for dynamic binary instrumentation (code injection).

```bash
pip3 install frida-tools frida

```

## Disclaimer

This is not an official Google product. Use responsibly and only on systems you own or have permission to manage.

```

```
