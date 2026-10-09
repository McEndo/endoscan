import argparse
import math
import socket
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait


VERSION = "1.0.1"
MAX_WORKERS = 256
MAX_TIMEOUT = 3600.0


def _validate_port(port):
    if port < 1 or port > 65535:
        raise ValueError(
            f"Invalid port: {port}. Ports must be between 1 and 65535."
        )


def parse_ports(port_input):
    if not isinstance(port_input, str):
        raise ValueError("Ports must be provided as text.")

    value = port_input.strip()

    if "-" in value:
        parts = value.split("-")

        if len(parts) != 2 or any(part.strip() == "" for part in parts):
            raise ValueError("Invalid port range.")

        try:
            start, end = (int(part.strip()) for part in parts)
        except ValueError as error:
            raise ValueError("Ports must contain valid numbers.") from error

        # Validate endpoints before expanding the range. This prevents invalid
        # inputs such as 1-999999999 from causing an excessive allocation.
        _validate_port(start)
        _validate_port(end)

        if start > end:
            raise ValueError(
                "Invalid port range: start port cannot be greater than end port."
            )

        ports = list(range(start, end + 1))

    elif "," in value:
        parts = value.split(",")

        if any(part.strip() == "" for part in parts):
            raise ValueError("Invalid comma-separated port list.")

        try:
            ports = [int(port.strip()) for port in parts]
        except ValueError as error:
            raise ValueError("Ports must contain valid numbers.") from error

        for port in ports:
            _validate_port(port)

    else:
        try:
            ports = [int(value)]
        except ValueError as error:
            raise ValueError("Ports must contain valid numbers.") from error

        _validate_port(ports[0])

    return sorted(set(ports))


def resolve_target(target):
    try:
        return socket.gethostbyname(target)

    except (socket.gaierror, UnicodeError) as error:
        raise ValueError(f"Could not resolve target: {target}") from error


def scan_port(target_ip, port, timeout):
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        return "OPEN"

    except ConnectionRefusedError:
        return "CLOSED"

    except socket.timeout:
        return "TIMEOUT"

    except (OSError, ValueError, OverflowError):
        return "ERROR"

    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                # A cleanup failure does not change the observed connect result.
                pass


def scan_ports(target_ip, ports, timeout, workers):
    if workers < 1 or workers > MAX_WORKERS:
        raise ValueError(f"Workers must be between 1 and {MAX_WORKERS}.")

    ordered_ports = sorted(set(ports))
    if not ordered_ports:
        return {}

    results = {}
    worker_count = min(workers, len(ordered_ports))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        port_iterator = iter(ordered_ports)
        future_to_port = {}

        for _ in range(worker_count):
            port = next(port_iterator)
            future = executor.submit(scan_port, target_ip, port, timeout)
            future_to_port[future] = port

        while future_to_port:
            completed, _ = wait(future_to_port, return_when=FIRST_COMPLETED)

            for future in completed:
                port = future_to_port.pop(future)
                results[port] = future.result()

                try:
                    next_port = next(port_iterator)
                except StopIteration:
                    continue

                next_future = executor.submit(
                    scan_port, target_ip, next_port, timeout
                )
                future_to_port[next_future] = next_port

    return {port: results[port] for port in ordered_ports}


def display_results(results):
    print()
    print("PORT       STATE")
    print("-----------------")

    for port in sorted(results):
        print(f"{port:<10} {results[port]}")


def display_summary(results, elapsed_time):
    open_count = sum(
        1 for state in results.values()
        if state == "OPEN"
    )

    closed_count = sum(
        1 for state in results.values()
        if state == "CLOSED"
    )

    timeout_count = sum(
        1 for state in results.values()
        if state == "TIMEOUT"
    )

    error_count = sum(
        1 for state in results.values()
        if state == "ERROR"
    )

    print()
    print("SCAN SUMMARY")
    print("-----------------")
    print(f"Ports scanned : {len(results)}")
    print(f"Open          : {open_count}")
    print(f"Closed        : {closed_count}")
    print(f"Timeout       : {timeout_count}")
    print(f"Errors        : {error_count}")
    print(f"Duration      : {elapsed_time:.2f}s")


def create_parser():
    parser = argparse.ArgumentParser(
        prog="endoscan",
        description="A concurrent TCP Connect port scanner."
    )

    parser.add_argument(
        "target",
        help="IPv4 address or hostname to scan"
    )

    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help="Ports to scan, e.g. 1-100 or 22,80,443"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help=f"Connection timeout in seconds (default: 2.0, max: {MAX_TIMEOUT:g})"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=20,
        help=f"Maximum concurrent workers (default: 20, max: {MAX_WORKERS})"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"EndoScan {VERSION}"
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if (
        not math.isfinite(args.timeout)
        or args.timeout <= 0
        or args.timeout > MAX_TIMEOUT
    ):
        parser.error(
            f"Timeout must be greater than 0 and at most {MAX_TIMEOUT:g} seconds."
        )

    if args.workers < 1 or args.workers > MAX_WORKERS:
        parser.error(f"Workers must be between 1 and {MAX_WORKERS}.")

    try:
        ports = parse_ports(args.ports)
        target_ip = resolve_target(args.target)

    except ValueError as error:
        parser.error(str(error))

    print()
    print(f"EndoScan v{VERSION}")
    print("-----------------")
    print(f"Target  : {args.target}")
    print(f"Address : {target_ip}")
    print(f"Ports   : {args.ports}")
    print(f"Workers : {args.workers}")
    print(f"Timeout : {args.timeout}s")
    print()

    start_time = time.perf_counter()

    results = scan_ports(
        target_ip,
        ports,
        args.timeout,
        args.workers
    )

    elapsed_time = time.perf_counter() - start_time

    display_results(results)
    display_summary(results, elapsed_time)


if __name__ == "__main__":
    main()
