# DNS lookup CLI

Install from this directory with Python 3.10 or later:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

```sh
dnslookup example.com
dnslookup example.com --type MX
dnslookup example.com --server 1.1.1.1
dnslookup 8.8.8.8 --reverse
dnslookup example.com --type TXT --json
dnslookup example.com --timeout 5
```

Batch and encrypted DNS examples:

```sh
printf 'example.com\nexample.org\n' | dnslookup --batch - --jobs 2 --json
dnslookup --batch domains.txt --type MX
dnslookup example.com --doh https://cloudflare-dns.com/dns-query
```

Batch input accepts one name (or IP with `--reverse`) per line and skips
blank lines and full-line comments starting with `#`. Results are emitted in
input order, as a JSON array in JSON mode. The process exits with the
highest exit code among its results. Each lookup gets its own timeout.
`--doh` uses HTTPS with TLS certificate verification and replaces the
system resolver. `--server` and `--doh` are mutually exclusive.

The tool defaults to an A query, the system's configured DNS resolver, and a
five-second deadline per lookup. Names are queried as absolute DNS names.
Answer lines contain the owner, TTL in seconds, record type, and record data
in DNS presentation format (including MX priority when applicable).

Exit codes: **0** for an answer or an existing name without the requested
records, **1** for NXDOMAIN, **2** for invalid input, and **3** for a timeout
or resolver failure. JSON results distinguish these cases using `status`.
JSON goes to stdout and human-readable error messages go to stderr.

Run tests after installing with `python -m unittest discover -s tests -v`.
