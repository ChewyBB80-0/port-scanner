# Port Scanner

A multi-threaded TCP port scanner in Python with two scan modes and service banner grabbing.
I built it by hand as a learning project, in five stages, as the first module of a larger
security audit tool.

> **Only scan machines you own or have written permission to test.** Unauthorized scanning is
> illegal in most places (US CFAA, UK Computer Misuse Act). `scanme.nmap.org` is run by the Nmap
> project specifically so people can test scanners against it.

## Features

- **Connect scan** (default): uses the operating system's `connect()` and needs no admin rights.
- **SYN scan** (`syn` mode): sends raw half-open SYN packets with Scapy and reads the reply
  flags. SYN/ACK means open, so the scanner sends a RST to tear it down; RST/ACK means closed;
  no reply means filtered. This mode needs root, on Linux.
- **Three port states**: open, closed and filtered, not just open or not.
- **Fast**: every (host, port) pair goes into one thread pool, so many hosts and ports scan in
  parallel.
- **Service identification**: grabs a banner from each open port. It waits for services that
  speak first (SSH, FTP) and sends an HTTP probe to the ones that stay silent.
- **Usable as a library**: `from scanner import scan`.

## Usage

```bash
python scanner.py
```

It asks for the target(s), the port range and the mode:

```
Target(s) - host/IP, comma-separated: scanme.nmap.org
Ports (e.g. 1-100 or 80) [default 1-1024]: 20-100
Mode - connect / syn [default connect]: connect

scanning 1 target(s) x 81 ports  [mode=connect]

45.33.32.156: [22, 53, 80]
    22     'SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13'
    53     None
    80     'HTTP/1.1 200 OK ... Server: Apache/2.4.7 (Ubuntu) ...'

done in 2.4s  {'closed': 78, 'open': 3}
```

SYN mode needs Scapy and root:

```bash
pip install -r requirements.txt
sudo python3 scanner.py      # then choose "syn"
```

As a library:

```python
from scanner import scan

open_by_host, counts, ips = scan(["scanme.nmap.org"], range(1, 1025), mode="connect")
```

## How it was built

| Stage | Goal | Result |
|---|---|---|
| 1 | Scan one port with a socket | Returns open, closed or filtered |
| 2 | Tell closed and filtered apart | Fixed by measuring the timeout (see below) |
| 3 | Concurrency | 1,005 ports in about 31 s, 10x faster than scanning one by one |
| 4 | Service identification | Pulled OpenSSH 6.6.1 and Apache 2.4.7 banners off scanme.nmap.org |
| 5 | SYN scan with Scapy | Working in a Linux Mint VM on Hyper-V, where raw sockets are native |

Then the three stage scripts (connect, SYN, multi-target) were merged into this one module,
with the mode as a parameter.

### The bug worth telling

On Windows my scanner reported closed ports as **filtered**. The plan said the fix would be
non-blocking sockets with `select()`. It wasn't. I measured it: this PC takes about 2.0 to 2.4
seconds to deliver a "connection refused", even on localhost, so a 2-second timeout gave up
before the refusal arrived. Raising the timeout to 3 seconds fixed it. A longer timeout also
costs nothing on ports that answer, because `connect_ex` returns as soon as the reply lands.
The lesson was to measure the behaviour first, then pick the fix.

## Next

- Command-line arguments (argparse), nmap-style
- OS hint from the TTL of the SYN/ACK reply (64 or less usually means Linux)
- More modules for the audit tool: a packet sniffer and a file integrity monitor are in progress

## Requirements

Python 3.8+. Connect mode uses only the standard library. SYN mode needs Scapy (`requirements.txt`).
