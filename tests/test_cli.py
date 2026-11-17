import json
import shutil
import socketserver
import struct
import subprocess
import sys
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch

import dns.asyncresolver
import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from dnslookup.cli import main
from dnslookup.resolver import parse_name


def reply_to(wire, tcp):
    query = dns.message.from_wire(wire)
    question = query.question[0]
    name = question.name.to_text()
    reply = dns.message.make_response(query)
    reply.flags |= dns.flags.RA
    if name == "timeout.test.":
        return None
    if name == "missing.test.":
        reply.set_rcode(dns.rcode.NXDOMAIN)
    elif name == "broken.test.":
        reply.set_rcode(dns.rcode.SERVFAIL)
    elif name == "truncated.test." and not tcp:
        reply.flags |= dns.flags.TC
    elif name.endswith(".ip6.arpa.") or name.endswith(".in-addr.arpa."):
        reply.answer.append(dns.rrset.from_text(name, 50, "IN", "PTR", "host.test."))
    elif name == "records.test." and question.rdtype == dns.rdatatype.MX:
        reply.answer.append(dns.rrset.from_text(name, 90, "IN", "MX", "10 mail.test."))
    elif name == "alias.test.":
        reply.answer.append(dns.rrset.from_text(name, 60, "IN", "CNAME", "records.test."))
        if question.rdtype == dns.rdatatype.A:
            reply.answer.append(dns.rrset.from_text("records.test.", 120, "IN", "A", "192.0.2.1"))
    elif name in {"records.test.", "truncated.test."} and question.rdtype == dns.rdatatype.A:
        reply.answer.append(dns.rrset.from_text(name, 120, "IN", "A", "192.0.2.1", "192.0.2.2"))
    return reply.to_wire()


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        if (reply := reply_to(wire, tcp=False)) is not None:
            sock.sendto(reply, self.client_address)


class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        size_bytes = self.rfile.read(2)
        if len(size_bytes) == 2:
            size = struct.unpack("!H", size_bytes)[0]
            if (reply := reply_to(self.rfile.read(size), tcp=True)) is not None:
                self.wfile.write(struct.pack("!H", len(reply)) + reply)


def run_cli(*args):
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main([*args, "--json"])
    return code, json.loads(out.getvalue()), err.getvalue()


class ValidationTests(unittest.TestCase):
    def test_absolute_names_idna_and_service_labels(self):
        self.assertEqual(parse_name("_dmarc.bücher.test", False).to_text(),
                         "_dmarc.xn--bcher-kva.test.")

    def test_invalid_arguments_are_json_and_exit_two(self):
        for args in [(), ("https://example.com",), ("bad..test",), ("x", "--type", "ANY"),
                     ("x", "--timeout", "nan"), ("x", "--timeout", "-1"),
                     ("x", "--server", "example.com"), ("x", "--reverse"),
                     ("x", "--doh", "http://example.com/dns-query"),
                     ("x", "--doh", "https://user@example.com/dns-query"),
                     ("x", "--server", "::1", "--doh", "https://example.com/dns-query"),
                     ("--batch", "-", "--jobs", "33"), ("x", "--jobs", "2")]:
            with self.subTest(args=args):
                code, response, stderr = run_cli(*args)
                self.assertEqual((code, response["status"], stderr), (2, "invalid_input", ""))
                self.assertTrue(response["error"])


class DNSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tcp = socketserver.TCPServer(("127.0.0.1", 0), TCPHandler)
        cls.addClassCleanup(tcp.server_close)
        cls.port = tcp.server_address[1]
        udp = socketserver.UDPServer(("127.0.0.1", cls.port), UDPHandler)
        cls.addClassCleanup(udp.server_close)
        for server in (tcp, udp):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05},
                                      daemon=True)
            thread.start()
            cls.addClassCleanup(thread.join, 2)
            cls.addClassCleanup(server.shutdown)

    def lookup(self, *args):
        real_resolver = dns.asyncresolver.Resolver

        def on_test_port(*args, **kwargs):
            resolver = real_resolver(*args, **kwargs)
            resolver.port = self.port
            return resolver

        with patch("dnslookup.resolver.dns.asyncresolver.Resolver", side_effect=on_test_port):
            return run_cli(*args, "--server", "127.0.0.1")

    def test_batch_keeps_input_order_and_reports_each_status(self):
        with patch.object(sys, "stdin", StringIO("# comment\n\nrecords.test\nbad..name\nmissing.test\n")):
            code, results, err = self.lookup("--batch", "-", "--jobs", "2")
        self.assertEqual((code, err), (2, ""))
        self.assertEqual([row["status"] for row in results], ["ok", "invalid_input", "nxdomain"])

    def test_multiple_answers_and_dig_agree(self):
        code, result, err = self.lookup("records.test")
        self.assertEqual((code, result["status"], err), (0, "ok", ""))
        values = {row["value"] for row in result["answers"]}
        self.assertEqual(values, {"192.0.2.1", "192.0.2.2"})
        self.assertEqual({row["ttl"] for row in result["answers"]}, {120})
        self.assertEqual(result["resolver"], "127.0.0.1")
        if shutil.which("dig"):
            dig = subprocess.check_output(
                ["dig", "@127.0.0.1", "-p", str(self.port), "records.test.", "A", "+short"],
                text=True, timeout=3,
            )
            self.assertEqual(values, set(dig.split()))

    def test_record_data_and_alias(self):
        _, result, _ = self.lookup("records.test", "--type", "mx")
        self.assertEqual(result["answers"][0]["value"], "10 mail.test.")
        _, result, _ = self.lookup("alias.test")
        self.assertEqual(result["canonical_name"], "records.test.")
        self.assertEqual(result["answers"][0]["name"], "records.test.")
        _, result, _ = self.lookup("alias.test", "--type", "CNAME")
        self.assertEqual(result["answers"][0]["value"], "records.test.")

    def test_reverse_lookups(self):
        for address, suffix in [("192.0.2.1", ".in-addr.arpa."), ("2001:db8::1", ".ip6.arpa.")]:
            with self.subTest(address=address):
                code, result, _ = self.lookup(address, "--reverse")
                self.assertEqual(code, 0)
                self.assertTrue(result["query"]["name"].endswith(suffix))
                self.assertEqual(result["answers"][0]["value"], "host.test.")

    def test_tcp_fallback(self):
        code, result, _ = self.lookup("truncated.test")
        self.assertEqual(code, 0)
        self.assertEqual(len(result["answers"]), 2)

    def test_empty_missing_and_server_failure(self):
        for name, code, status in [("empty", 0, "no_answer"), ("missing", 1, "nxdomain"),
                                   ("broken", 3, "resolver_failure")]:
            with self.subTest(name=name):
                actual, result, _ = self.lookup(name + ".test")
                self.assertEqual((actual, result["status"], result["answers"]), (code, status, []))
                if name == "broken":
                    self.assertIn("SERVFAIL", result["error"])

    def test_timeout(self):
        started = time.monotonic()
        code, result, _ = self.lookup("timeout.test", "--timeout", "0.15")
        self.assertEqual((code, result["status"]), (3, "timeout"))
        self.assertLess(time.monotonic() - started, 0.4)
