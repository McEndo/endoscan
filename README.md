# EndoScan

EndoScan is a lightweight concurrent TCP Connect port scanner written in Python. It was built as a hands-on networking and cybersecurity project to explore TCP connections, socket programming, port states, timeouts, concurrency, input validation, and CLI tool development.

EndoScan is intended for systems you own or environments where you have explicit authorization to perform network scanning.

## Features

- TCP Connect port scanning
- IPv4 and hostname targets
- Single ports, port ranges, and comma-separated port lists
- Concurrent scanning using a bounded thread pool
- Configurable connection timeout
- Configurable worker count
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

- Python 3
- No third-party Python packages

EndoScan uses only Python's standard library.

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

## Example Output

```text
EndoScan v1.0.0
-----------------
Target  : 127.0.0.1
Address : 127.0.0.1
Ports   : 7998-8002
Workers : 5
Timeout : 1.0s

PORT       STATE
-----------------
7998       TIMEOUT
7999       TIMEOUT
8000       OPEN
8001       TIMEOUT
8002       TIMEOUT

SCAN SUMMARY
-----------------
Ports scanned : 5
Open          : 1
Closed        : 0
Timeout       : 4
Errors        : 0
Duration      : 1.01s
```

In this controlled test, a local HTTP server was intentionally listening on TCP port `8000`.

## How It Works

EndoScan first parses and validates the requested ports and resolves the supplied target to an IPv4 address.

Each individual port scan creates an IPv4 TCP socket and attempts a connection using Python's socket interface.

The observed result is classified as:

| State | Meaning |
| --- | --- |
| `OPEN` | The TCP connection succeeded. |
| `CLOSED` | The connection was explicitly refused. |
| `TIMEOUT` | The connection attempt exceeded the configured timeout without a decisive response. |
| `ERROR` | Another socket or operating-system networking error occurred. |

EndoScan deliberately reports `TIMEOUT` rather than assuming that an unanswered connection is `FILTERED`. A timeout alone does not establish why a response was not received.

## Concurrency

The initial implementation scanned ports sequentially. This meant that multiple connection timeouts accumulated one after another.

EndoScan v1.0 uses Python's `ThreadPoolExecutor` to run multiple TCP connection attempts concurrently while limiting the maximum number of worker threads.

Each individual connection attempt remains synchronous, but multiple port scans can be in progress at the same time.

The default worker count is:

```text
20
```

It can be changed with `-w` or `--workers`.

## Benchmark

Concurrency was tested in a controlled localhost environment using 41 TCP ports and a one-second connection timeout.

| Workers | Duration |
| ---: | ---: |
| 1 | 40.33 s |
| 5 | 8.07 s |
| 20 | 2.03 s |
| 50 | 1.02 s |

The same test produced one known-open port and 40 timeouts across the recorded runs.

These results represent this specific local test environment and should not be interpreted as general performance guarantees.

The default remains 20 workers to provide bounded concurrency without choosing a more aggressive worker count solely because it performed faster in this benchmark.

## Testing

EndoScan includes automated tests for deterministic functionality such as port parsing, validation, duplicate removal, and target resolution.

Run the test suite with:

```bash
python -m unittest test_endoscan.py -v
```

Current v1.0 testing:

```text
Ran 11 tests

OK
```

Manual validation was also performed against controlled localhost services, including an HTTP server intentionally bound to TCP port 8000.

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
- Performance benchmarking

The project progressed from networking fundamentals and a sequential scanner to a bounded concurrent implementation, followed by validation, benchmarking, automated testing, and documentation.

## Responsible Use

Only scan systems that you own or have explicit permission to test.

Unauthorized network scanning may violate organizational policies, service agreements, or applicable laws.

## Version

**EndoScan v1.0.0**