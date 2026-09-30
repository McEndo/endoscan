import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


VERSION = "1.0.0"


def parse_ports(port_input):
    try:
        if "-" in port_input:
            parts = port_input.split("-")

            if len(parts) != 2:
                raise ValueError("Invalid port range.")

            start = int(parts[0])
            end = int(parts[1])

            if start > end:
                raise ValueError(
                    "Invalid port range: start port cannot be greater than end port."
                )

            ports = list(range(start, end + 1))

        elif "," in port_input:
            parts = port_input.split(",")

            if any(part.strip() == "" for part in parts):
                raise ValueError("Invalid comma-separated port list.")

            ports = [int(port.strip()) for port in parts]

        else:
            ports = [int(port_input)]

    except ValueError as error:
        if str(error).startswith("Invalid"):
            raise

        raise ValueError("Ports must contain valid numbers.")

    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(
                f"Invalid port: {port}. Ports must be between 1 and 65535."
            )

    return sorted(set(ports))


def resolve_target(target):
    try:
        return socket.gethostbyname(target)

    except socket.gaierror:
        raise ValueError(f"Could not resolve target: {target}")


def scan_port(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target_ip, port))
        return "OPEN"

    except ConnectionRefusedError:
        return "CLOSED"

    except socket.timeout:
        return "TIMEOUT"

    except OSError:
        return "ERROR"

    finally:
        sock.close()


def scan_ports(target_ip, ports, timeout, workers):
    results = {}

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {
            executor.submit(
                scan_port,
                target_ip,
                port,
                timeout
            ): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            results[port] = future.result()

    return results


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
        help="Connection timeout in seconds (default: 2.0)"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=20,
        help="Maximum concurrent workers (default: 20)"
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

    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0.")

    if args.workers <= 0:
        parser.error("Workers must be greater than 0.")

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