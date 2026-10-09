# EndoScan

EndoScan is a lightweight concurrent TCP Connect port scanner written in Python. It was built as a hands-on networking and cybersecurity project to explore TCP connections, socket programming, port states, timeouts, concurrency, input validation, and CLI tool development.

EndoScan is intended for systems you own or environments where you have explicit authorization to perform network scanning.

## Features

- TCP Connect port scanning
- IPv4 and hostname targets
- Single ports, port ranges, and comma-separated port lists
- Concurrent scanning using a bounded thread pool
- Configurable connection timeout (up to 3,600 seconds)
- Configurable worker count (up to 256)
- Port-state classification:
  - `OPEN`
  - `CLOSED`
  - `TIMEOUT`
  - `ERROR`
- Duplicate port removal
- Input validation and clean CLI errors
- Sorted scan results
- Scan statistics and execution timing
- Automated tests using Python's `unittest`

## Requirements

- Python 3.8 or newer
- No third-party Python packages

EndoScan uses only Python's standard library.

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/McEndo/endoscan.git
cd endoscan
```

No package installation step is required. Run EndoScan directly with a
supported Python interpreter.

## Usage

Basic syntax:

```bash
python endoscan.py <target> -p <ports>
```

Scan a single port:

```bash
python endoscan.py 127.0.0.1 -p 80
```

Scan a port range:

```bash
python endoscan.py 127.0.0.1 -p 1-100
```

Scan selected ports:

```bash
python endoscan.py 127.0.0.1 -p 22,80,443
```

Set a custom timeout:

```bash
python endoscan.py 127.0.0.1 -p 1-100 -t 1
```

Set the maximum number of concurrent workers:

```bash
python endoscan.py 127.0.0.1 -p 1-100 -w 20
```

Combine the options:

```bash
python endoscan.py 127.0.0.1 -p 1-100 -t 1 -w 20
```

Display the version:

```bash
python endoscan.py --version
```

Display all CLI options:

```bash
python endoscan.py --help
```

Successful scans, `--help`, and `--version` exit with status `0`. Invalid
arguments, invalid port specifications, and DNS resolution failures are CLI
usage errors and exit with status `2`. Individual per-port `ERROR` results do
not currently change the process exit status.

## Example Output

```text
EndoScan v1.0.1
-----------------
Target  : 127.0.0.1
Address : 127.0.0.1
Ports   : 7998-8002
Workers : 5
Timeout : 1.0s

PORT       STATE
-----------------
7998       CLOSED
7999       CLOSED
8000       OPEN
8001       CLOSED
8002       CLOSED

SCAN SUMMARY
-----------------
Ports scanned : 5
Open          : 1
Closed        : 4
Timeout       : 0
Errors        : 0
Duration      : 0.01s
```

This illustrative localhost output assumes an HTTP server is listening on TCP
port `8000` and the operating system immediately refuses the other connection
attempts. Firewall policy can produce different results.

## How It Works

EndoScan first parses and validates the requested ports and resolves the supplied target to an IPv4 address.

Each individual port scan creates an IPv4 TCP socket and attempts a connection using Python's socket interface.

The observed result is classified as:

| State | Meaning |
| --- | --- |
| `OPEN` | The TCP connection succeeded. |
| `CLOSED` | The operating system reported that the connection was refused. |
| `TIMEOUT` | The connection attempt exceeded the configured timeout without a decisive response. |
| `ERROR` | Another socket or operating-system networking error occurred. |

EndoScan deliberately reports `TIMEOUT` rather than assuming that an unanswered connection is `FILTERED`. A timeout alone does not establish why a response was not received.

## Concurrency

The initial implementation scanned ports sequentially. This meant that multiple connection timeouts accumulated one after another.

EndoScan v1.0 uses Python's `ThreadPoolExecutor` to run multiple TCP connection attempts concurrently while limiting the maximum number of worker threads.

Each individual connection attempt remains synchronous, but multiple port scans can be in progress at the same time.

The scanner keeps at most one pending task per active worker instead of queuing
the entire port range at once. Results are returned and displayed in ascending
port order, regardless of the order in which connection attempts finish.

The default worker count is:

```text
20
```

It can be changed with `-w` or `--workers`.

Worker values must be between `1` and `256`. If fewer ports than workers are
requested, EndoScan creates only as many worker threads as there are unique
ports.

## Performance Notes

Concurrency reduces the wall-clock impact of independent connection attempts,
especially when several attempts reach their timeout. Actual duration depends
on the target, routing, firewall behavior, operating system, timeout, and worker
count. Unused localhost ports normally fail quickly with `CLOSED`; they should
not be used as a stand-in for timeout-heavy network behavior.

The default remains 20 workers to provide bounded concurrency without creating
an unnecessarily large burst of connection attempts.

## Testing

EndoScan includes automated tests for deterministic functionality such as port parsing, validation, duplicate removal, and target resolution.

Run the test suite with:

```bash
python -m unittest test_endoscan.py -v
```

Current test suite:

```text
Ran 28 tests

OK
```

The tests cover parsing and boundary validation, DNS error translation, socket
result classification and cleanup, deterministic concurrent results, worker
limits, version output, timeout validation, and CLI error exit codes. Most
network outcomes are mocked for determinism; one integration test uses only a
temporary loopback listener to confirm a real successful TCP connection.

## Project Structure

```text
endoscan/
├── endoscan.py
├── test_endoscan.py
├── README.md
├── LICENSE
└── .gitignore
```

## Limitations

EndoScan v1.0 is intentionally limited in scope.

It does not currently implement:

- SYN scanning
- UDP scanning
- Service or version detection
- OS fingerprinting
- Vulnerability detection
- Subnet scanning
- Mixed port specifications such as `22,80,100-200`
- Advanced retry or timing strategies
- Raw packet construction
- IPv6 targets
- Scanning every address returned for a multi-address hostname
- Detailed operating-system error messages for per-port `ERROR` results

EndoScan is a learning and portfolio project, not a replacement for mature network scanners such as Nmap.

## What I Learned

Building EndoScan involved working with:

- IPv4 addressing and hostname resolution
- TCP ports and connection establishment
- TCP Connect scanning
- Python sockets
- Blocking network operations
- Connection timeouts
- Exception handling
- Port-state interpretation
- I/O-bound concurrency
- Thread pools and Futures
- CLI argument parsing
- Input validation
- Automated testing
- Concurrency and performance tradeoffs

The project progressed from networking fundamentals and a sequential scanner to
a bounded concurrent implementation, followed by validation, automated testing,
and documentation.

## Responsible Use

Only scan systems that you own or have explicit permission to test.

Unauthorized network scanning may violate organizational policies, service agreements, or applicable laws.

## License

EndoScan is released under the [MIT License](LICENSE).

## Version

**EndoScan v1.0.1**
