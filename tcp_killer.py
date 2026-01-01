#!/usr/bin/env python3
# Copyright 2017 Google Inc. All Rights Reserved.
# Modified 2025 for Python 3 and Extended Capabilities.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# ... (License header preserved) ...

"""
Shuts down TCP/UDP connections on Linux or macOS.
Capable of handling persistent connections, UDP (QUIC), and generic protocols.
"""

import argparse
import os
import platform
import re
import socket
import subprocess
import threading
import sys
import time
import signal

# Attempt to import frida; warn if missing
try:
    import frida
except ImportError:
    sys.exit("Error: Frida is missing. Install it via: pip3 install frida-tools frida")

__author__ = "geffner@google.com (Jason Geffner), Modified by Gemini"
__version__ = "2.0"

# Javascript to inject. 
# Updated to handle potential module naming differences and cleaner logging.
_FRIDA_SCRIPT = """
var resolver = new ApiResolver("module");
var platform = Process.platform;
var lib = platform === "darwin" ? "libsystem" : "libc";
var funcName = "shutdown";

// Find the shutdown export
var matches = resolver.enumerateMatches("exports:*" + lib + "*!" + funcName);

if (matches.length === 0) {
    // Fallback for some Linux distros where libc might be named differently
    matches = resolver.enumerateMatches("exports:*libc*!" + funcName);
}

if (matches.length === 0) {
    throw new Error("Could not find " + funcName + " in target process.");
}

var shutdownAddr = matches[0].address;
var shutdown = new NativeFunction(shutdownAddr, "int", ["int", "int"]);

// SHUT_RDWR is usually 2
var SHUT_RDWR = 2;

// Attempt to shutdown the file descriptor
// args: (int fd, int how)
var result = shutdown(%d, SHUT_RDWR);

if (result !== 0) {
    // If shutdown fails, we can try 'close' as a fallback, 
    // but usually shutdown is safer for stability.
    send({type: "error", description: "shutdown() returned error code: " + result});
} else {
    send({type: "success", description: "Socket shutdown successful."});
}
"""

def canonicalize_ip_address(address):
    """Ensures IP address is in a standard format."""
    try:
        # Check for IPv6 brackets
        if address.startswith("[") and address.endswith("]"):
            address = address[1:-1]
            
        if ":" in address:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET
        packed = socket.inet_pton(family, address)
        return socket.inet_ntop(family, packed)
    except socket.error:
        # If it's a hostname or invalid, return as is for lsof to handle or fail
        return address

def get_process_and_fd(local_port, remote_port=None, protocol="TCP"):
    """
    Finds the PID and FD using lsof. 
    Refactored to be more robust and support UDP.
    """
    # -n: No host names, -P: No port names, -l: No login names
    # -i: Select internet files
    proto_flag = f"-i{protocol}" # -iTCP or -iUDP
    
    cmd = ["lsof", "-n", "-P", "-l", proto_flag]
    
    try:
        # Run lsof
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8')
    except subprocess.CalledProcessError:
        # lsof returns return code 1 if no network files are found
        return []

    results = []
    
    # Parse lines. Skip header.
    # Output format example:
    # COMMAND   PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
    # python3 12345     1000   3u  IPv4  99999      0t0  TCP 10.0.0.1:54321->1.2.3.4:443 (ESTABLISHED)
    
    lines = output.splitlines()[1:]
    
    for line in lines:
        parts = line.split()
        if len(parts) < 9:
            continue
            
        pid_str = parts[1]
        fd_str = parts[3]
        name_field = parts[-1] # Usually the last field is the connection string
        state_field = parts[-2] if len(parts) > 9 else "" # (ESTABLISHED) often sits at end

        # Extract numerical FD (remove 'u', 'r', 'w' etc)
        if not fd_str[0].isdigit():
            continue
        fd = int(re.search(r'\d+', fd_str).group())

        # Check ports in the name field
        # Expected format: local_ip:local_port->remote_ip:remote_port
        # OR local_ip:local_port (listening/UDP sometimes)
        
        if f":{local_port}" in name_field:
            # If remote_port is specified, we must match it too
            if remote_port and f":{remote_port}" not in name_field:
                continue
                
            results.append({
                "pid": int(pid_str),
                "fd": fd,
                "name": name_field,
                "proto": protocol
            })

    return results

def inject_shutdown(pid, sockfd):
    """Injects the shutdown call into the target process."""
    js_error = {}
    event = threading.Event()

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if isinstance(payload, dict) and payload.get("type") == "error":
                js_error["error"] = payload["description"]
        elif message["type"] == "error":
            js_error["error"] = message["description"]
        event.set()

    try:
        session = frida.attach(pid)
        script = session.create_script(_FRIDA_SCRIPT % sockfd)
        script.on("message", on_message)
        script.load()
        
        # Wait for script execution
        # We don't wait forever, just enough for the syscall
        event.wait(timeout=2.0)
        session.detach()
        
    except frida.ProcessNotFoundError:
        return False, "Process disappeared before injection."
    except Exception as e:
        return False, str(e)

    if "error" in js_error:
        return False, js_error["error"]

    return True, "Success"

def kill_connection(local, remote, protocols, verbose=False, force_kill_process=False):
    """
    Main logic to find and kill connections.
    """
    local_port = int(local.split(":")[-1])
    remote_port = int(remote.split(":")[-1]) if remote else None
    
    targets_found = False

    for proto in protocols:
        targets = get_process_and_fd(local_port, remote_port, proto)
        
        for t in targets:
            targets_found = True
            msg = f"Found {t['proto']} connection: {t['name']} (PID: {t['pid']}, FD: {t['fd']})"
            if verbose:
                print(msg)
            
            if force_kill_process:
                if verbose: print(f"NUCLEAR OPTION: Killing PID {t['pid']}...")
                try:
                    os.kill(t['pid'], signal.SIGKILL)
                    print(f"Killed process {t['pid']}")
                except OSError as e:
                    print(f"Failed to kill process: {e}")
            else:
                success, reason = inject_shutdown(t['pid'], t['fd'])
                if success:
                    print(f"Successfully shutdown socket FD {t['fd']} in PID {t['pid']}")
                else:
                    print(f"Failed to shutdown socket: {reason}")
                    
    return targets_found

def monitor_loop(local, remote, protocols, interval, verbose, force_kill):
    """
    Continuous monitoring for persistent connections.
    """
    print(f"[*] Starting monitor loop. Checking every {interval} seconds.")
    print("[*] Press Ctrl+C to stop.")
    
    try:
        while True:
            kill_connection(local, remote, protocols, verbose, force_kill)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Monitor stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Advanced TCP/UDP Connection Killer (Python 3)",
        epilog="Examples:\n"
               "  sudo python3 kill.py 127.0.0.1:8080\n"
               "  sudo python3 kill.py :443 :5555 --udp --watch\n"
               "  sudo python3 kill.py :22 --kill-process (The Nuclear Option)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("local", help="Local endpoint (IP:Port or :Port)")
    parser.add_argument("remote", nargs="?", help="Remote endpoint (IP:Port or :Port) [Optional]")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # Protocol Support
    parser.add_argument("--udp", action="store_true", help="Target UDP sockets (includes QUIC)")
    parser.add_argument("--tcp", action="store_true", default=True, help="Target TCP sockets (Default)")
    
    # Persistence Support
    parser.add_argument("-w", "--watch", type=float, metavar="SECONDS", 
                        help="Run in loop mode, checking every X seconds (e.g., 0.5)")
    
    # Aggressive Mode
    parser.add_argument("--kill-process", action="store_true", 
                        help="If found, KILL the entire process, not just the socket.")

    args = parser.parse_args()

    # Permission check
    if os.geteuid() != 0:
        print("Warning: This script usually requires root/sudo to see other processes' sockets.")

    # Determine protocols
    protos = []
    if args.tcp: protos.append("TCP")
    if args.udp: protos.append("UDP")
    
    # Clean up args
    if args.local.startswith(":"): args.local = "0.0.0.0" + args.local
    if args.remote and args.remote.startswith(":"): args.remote = "0.0.0.0" + args.remote

    if args.watch:
        monitor_loop(args.local, args.remote, protos, args.watch, args.verbose, args.kill_process)
    else:
        found = kill_connection(args.local, args.remote, protos, args.verbose, args.kill_process)
        if not found and args.verbose:
            print("No matching connections found.")import platform
import re
import socket
import subprocess
import threading

import frida


_FRIDA_SCRIPT = """
  var resolver = new ApiResolver("module");
  var lib = Process.platform == "darwin" ? "libsystem" : "libc";
  var matches = resolver.enumerateMatchesSync("exports:*" + lib + "*!shutdown");
  if (matches.length == 0)
  {
    throw new Error("Could not find *" + lib + "*!shutdown in target process.");
  }
  else if (matches.length != 1)
  {
    // Sometimes Frida returns duplicates.
    var address = 0;
    var s = "";
    var duplicates_only = true;
    for (var i = 0; i < matches.length; i++)
    {
      if (s.length != 0)
      {
        s += ", ";
      }
      s += matches[i].name + "@" + matches[i].address;
      if (address == 0)
      {
        address = matches[i].address;
      }
      else if (!address.equals(matches[i].address))
      {
        duplicates_only = false;
      }
    }
    if (!duplicates_only)
    {
      throw new Error("More than one match found for *libc*!shutdown: " + s);
    }
  }
  var shutdown = new NativeFunction(matches[0].address, "int", ["int", "int"]);
  if (shutdown(%d, 0) != 0)
  {
    throw new Error("Call to shutdown() returned an error.");
  }
  send("");
  """


def canonicalize_ip_address(address):
  if ":" in address:
    family = socket.AF_INET6
  else:
    family = socket.AF_INET
  return socket.inet_ntop(family, socket.inet_pton(family, address))


def tcp_kill(local_addr, local_port, remote_addr, remote_port, verbose=False):
  """Shuts down a TCP connection on Linux or macOS.

  Finds the process and socket file descriptor associated with a given TCP
  connection. Then injects into that process a call to shutdown()
  (http://man7.org/linux/man-pages/man2/shutdown.2.html) that file descriptor,
  thereby shutting down the TCP connection.

  Args:
    local_addr: The IP address (as a string) associated with the local endpoint
      of the connection.
    local_port: The port (as an int) associated with the local endpoint of the
      connection.
    remote_addr: The IP address (as a string) associated with the remote
      endpoint of the connection.
    remote_port: The port (as an int) associated with the remote endpoint of the
      connection.
    verbose: If True, print verbose output to the console.

  Returns:
    No return value if successful. If unsuccessful, raises an exception.

  Raises:
    KeyError: Unexpected output from lsof command.
    NotImplementedError: Not running on a Linux or macOS system.
    OSError: TCP connection not found or socket file descriptor not found.
    RuntimeError: Error during execution of JavaScript injected into process.
  """

  if platform.system() not in ("Darwin", "Linux"):
    raise NotImplementedError("This function is only implemented for Linux and "
                              "macOS systems.")

  local_addr = canonicalize_ip_address(local_addr)
  remote_addr = canonicalize_ip_address(remote_addr)

  name_pattern = re.compile(
      r"^\[?(.+?)]?:([0-9]{1,5})->\[?(.+?)]?:([0-9]{1,5})$")
  fd_pattern = re.compile(r"^(\d)+")

  field_names = ("PID", "FD", "NAME")
  fields = {}
  pid = None
  sockfd = None
  for line in subprocess.check_output("lsof -bnlPiTCP -sTCP:ESTABLISHED "
                                      "2>/dev/null", shell=True).splitlines():
    words = line.split()

    if len(fields) != len(field_names):
      for i in xrange(len(words)):
        for field in field_names:
          if words[i] == field:
            fields[field] = i
            break
      if len(fields) != len(field_names):
        raise KeyError("Unexpected field headers in output of lsof command.")
      continue

    name = name_pattern.match(words[fields["NAME"]])
    if not name:
      raise KeyError("Unexpected NAME in output of lsof command.")
    if (int(name.group(2)) == local_port and int(name.group(4)) == remote_port
        and canonicalize_ip_address(name.group(1)) == local_addr and
        canonicalize_ip_address(name.group(3)) == remote_addr):
      pid = int(words[fields["PID"]])
      sockfd = int(fd_pattern.match(words[fields["FD"]]).group(1))
      if verbose:
        print "Process ID of socket's process: %d" % pid
        print "Socket file descriptor: %d" % sockfd
      break

  if not sockfd:
    s = " Try running as root." if os.geteuid() != 0 else ""
    raise OSError("Socket not found for connection." + s)

  _shutdown_sockfd(pid, sockfd)


def _shutdown_sockfd(pid, sockfd):
  """Injects into a process a call to shutdown() a socket file descriptor.

  Injects into a process a call to shutdown()
  (http://man7.org/linux/man-pages/man2/shutdown.2.html) a socket file
  descriptor, thereby shutting down its associated TCP connection.

  Args:
    pid: The process ID (as an int) of the target process.
    sockfd: The socket file descriptor (as an int) in the context of the target
      process to be shutdown.

  Raises:
    RuntimeError: Error during execution of JavaScript injected into process.
  """

  js_error = {}  # Using dictionary since Python 2.7 doesn't support "nonlocal".
  event = threading.Event()

  def on_message(message, data):  # pylint: disable=unused-argument
    if message["type"] == "error":
      js_error["error"] = message["description"]
    event.set()

  session = frida.attach(pid)
  script = session.create_script(_FRIDA_SCRIPT % sockfd)
  script.on("message", on_message)
  closed = False

  try:
    script.load()
  except frida.TransportError as e:
    if str(e) != "the connection is closed":
      raise
    closed = True

  if not closed:
    event.wait()
    session.detach()
  if "error" in js_error:
    raise RuntimeError(js_error["error"])


if __name__ == "__main__":

  class ArgParser(argparse.ArgumentParser):

    def error(self, message):
      print "tcp_killer v" + __version__
      print "by " + __author__
      print
      print "Error: " + message
      print
      print self.format_help().replace("usage:", "Usage:")
      self.exit(0)

  parser = ArgParser(
      add_help=False,
      description="Shuts down a TCP connection on Linux or macOS. Local and "
      "remote endpoint arguments can be copied from the output of 'netstat "
      "-lanW'.",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog=r"""
Examples:
  %(prog)s 10.31.33.7:50246 93.184.216.34:443
  %(prog)s 2001:db8:85a3::8a2e:370:7334.93 2606:2800:220:1:248:1893:25c8:1946.80
  %(prog)s -verbose [2001:4860:4860::8888]:46820 [2607:f8b0:4005:807::200e]:80
""")

  args = parser.add_argument_group("Arguments")
  args.add_argument("-verbose", required=False, action="store_const",
                    const=True, help="Show verbose output")
  args.add_argument("local", metavar="<local endpoint>",
                    help="Connection's local IP address and port")
  args.add_argument("remote", metavar="<remote endpoint>",
                    help="Connection's remote IP address and port")
  parsed = parser.parse_args()

  ep_format = re.compile(r"^(.+)[:\.]([0-9]{1,5})$")
  local = ep_format.match(parsed.local)
  remote = ep_format.match(parsed.remote)
  if not local or not remote:
    parser.error("Invalid command-line argument.")

  local_address = local.group(1)
  if local_address.startswith("[") and local_address.endswith("]"):
    local_address = local_address[1:-1]

  remote_address = remote.group(1)
  if remote_address.startswith("[") and remote_address.endswith("]"):
    remote_address = remote_address[1:-1]

  tcp_kill(local_address, int(local.group(2)), remote_address,
           int(remote.group(2)), parsed.verbose)

  print "TCP connection was successfully shutdown."
