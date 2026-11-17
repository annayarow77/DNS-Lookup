"""Validate DNS inputs and translate resolver responses."""

import asyncio
import ipaddress
import re
import time

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import dns.reversename

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR")
LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?")


def parse_name(value, reverse):
    if reverse:
        try:
            address = ipaddress.ip_address(value)
            if getattr(address, "scope_id", None) is not None:
                raise ValueError
            return dns.reversename.from_address(str(address))
        except (ValueError, dns.exception.DNSException):
            raise ValueError("--reverse requires an unscoped IPv4 or IPv6 address") from None

    value = value.translate(str.maketrans("。．｡", "..."))
    labels = value.removesuffix(".").split(".")
    try:
        ascii_labels = [label.encode("idna").decode("ascii") for label in labels]
        if value != "." and not all(LABEL.fullmatch(label) for label in ascii_labels):
            raise ValueError
        return dns.name.from_text(".".join(ascii_labels) + ".")
    except (ValueError, dns.exception.DNSException):
        raise ValueError(f"invalid DNS name: {value!r}") from None


def result(status, query=None, answers=None, elapsed_ms=None, resolver=None, error=None,
           canonical_name=None):
    return dict(query=query, status=status, answers=answers or [], resolver=resolver,
                elapsed_ms=elapsed_ms, error=error, canonical_name=canonical_name)


async def resolve(name, record_type, server, timeout):
    resolver = dns.asyncresolver.Resolver(configure=server is None)
    if server:
        resolver.nameservers = [server]
    # Bound the retry backoff as well as the time spent waiting for replies.
    return await asyncio.wait_for(
        resolver.resolve(name, record_type, search=False, lifetime=timeout,
                         raise_on_no_answer=False),
        timeout,
    )


def lookup(name, record_type, server, timeout):
    query = dict(name=name.to_text(), type=record_type)
    started = time.monotonic()

    def finish(status, **fields):
        return result(status, query=query, elapsed_ms=round((time.monotonic() - started) * 1000, 2),
                      **fields)

    try:
        reply = asyncio.run(resolve(name, record_type, server, timeout))
    except dns.resolver.NXDOMAIN:
        return finish("nxdomain", error="DNS name does not exist")
    except (dns.exception.Timeout, asyncio.TimeoutError):
        return finish("timeout", error=f"DNS lookup timed out ({timeout:g}s deadline)")
    except (dns.exception.DNSException, OSError) as exc:
        return finish("resolver_failure", error=str(exc))

    details = dict(resolver=reply.nameserver, canonical_name=reply.canonical_name.to_text())
    if reply.rrset is None:
        return finish("no_answer", **details)

    answers = [
        dict(name=reply.rrset.name.to_text(), type=record_type, ttl=reply.rrset.ttl,
             value=record.to_text())
        for record in reply.rrset
    ]
    return finish("ok", answers=answers, **details)
