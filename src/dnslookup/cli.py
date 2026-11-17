"""Command line parsing and exit codes."""

import argparse
import ipaddress
import math
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from .output import render, render_batch
from .resolver import RECORD_TYPES, lookup, parse_name, result

EXIT_CODES = {"ok": 0, "no_answer": 0, "nxdomain": 1, "invalid_input": 2,
              "timeout": 3, "resolver_failure": 3}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def batch_names(filename):
    try:
        if filename == "-":
            lines = sys.stdin.read().splitlines()
        else:
            lines = Path(filename).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read batch input: {exc}") from exc
    names = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    if not names:
        raise ValueError("batch input contains no query names")
    return names


def validate_server(server, doh):
    if server is not None:
        try:
            address = ipaddress.ip_address(server)
            if getattr(address, "scope_id", None) is None:
                return str(address)
        except ValueError:
            pass
        raise ValueError("--server requires an unscoped IPv4 or IPv6 address")
    if doh is not None:
        try:
            endpoint = urlsplit(doh)
            port = endpoint.port
            if (endpoint.scheme == "https" and endpoint.hostname
                    and endpoint.username is None and "#" not in doh
                    and port != 0 and not any(char.isspace() for char in doh)):
                return doh
        except ValueError:
            pass
        raise ValueError("--doh requires a valid HTTPS URL without credentials or a fragment")
    return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    as_json = "--json" in argv[:argv.index("--")] if "--" in argv else "--json" in argv
    parser = Parser(prog="dnslookup", description="Look up DNS records.", allow_abbrev=False)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("name", nargs="?", help="DNS name or, with --reverse, an IP address")
    source.add_argument("--batch", metavar="FILE", help="one query per line; use - for stdin")
    record = parser.add_mutually_exclusive_group()
    record.add_argument("--type", type=str.upper, choices=RECORD_TYPES, help="default: A")
    record.add_argument("--reverse", action="store_true", help="look up an IP's PTR record")
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("--server", help="DNS resolver IPv4 or IPv6 address")
    transport.add_argument("--doh", metavar="URL", help="DNS over HTTPS endpoint")
    parser.add_argument("--jobs", type=int, help="batch workers, 1–32 (default: 4)")
    parser.add_argument("--timeout", type=float, default=5.0, help="total seconds per query")
    parser.add_argument("--json", action="store_true", help="emit JSON")

    try:
        args = parser.parse_args(argv)
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("--timeout must be a finite positive number")
        if args.jobs is not None and (args.batch is None or not 1 <= args.jobs <= 32):
            raise ValueError("--jobs requires --batch and a value between 1 and 32")
        server = validate_server(args.server, args.doh)
        names = batch_names(args.batch) if args.batch is not None else [args.name]
    except ValueError as exc:
        if not as_json:
            parser.print_usage(sys.stderr)
        response = result("invalid_input", error=str(exc))
        render(response, as_json)
        return 2

    record_type = "PTR" if args.reverse else args.type or "A"

    def query(value):
        try:
            name = parse_name(value, args.reverse)
        except ValueError as exc:
            return result("invalid_input", query=dict(name=value, type=record_type), error=str(exc))
        return lookup(name, record_type, server, args.timeout)

    if args.batch is None:
        response = query(names[0])
        render(response, as_json)
        return EXIT_CODES[response["status"]]

    with ThreadPoolExecutor(max_workers=args.jobs or 4) as executor:
        responses = list(executor.map(query, names))
    render_batch(responses, as_json)
    return max(EXIT_CODES[response["status"]] for response in responses)


if __name__ == "__main__":
    sys.exit(main())
