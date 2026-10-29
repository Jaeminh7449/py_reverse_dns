import socket
import unittest

from py_reverse_dns.core import Resolver, Result


def make_resolver(stub):
    """Build a Resolver whose socket.getaddrinfo stand-in is *stub*."""
    return Resolver(resolver=stub)


class PtrStub:
    """Fake getaddrinfo + getnameinfo behaviour for tests.

    The stub holds:
      * ptr_map: ip -> list of PTR host names returned for that ip
      * forward_map: hostname -> list of IPs it resolves to
    A separate socket.getnameinfo override is applied per test because
    getnameinfo is a module-level function in socket and is restored in
    tearDown.
    """

    def __init__(self, ptr_map, forward_map):
        self.ptr_map = ptr_map
        self.forward_map = forward_map

    def __call__(self, host, port, family=0, type=0, proto=0, flags=0):
        if host in self.ptr_map:
            out = []
            for _ in self.ptr_map[host]:
                out.append((socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (host, port)))
            return out
        if host in self.forward_map:
            out = []
            for ip in self.forward_map[host]:
                out.append((socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (ip, port)))
            return out
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")


class ResolverTests(unittest.TestCase):

    def setUp(self):
        self._orig_getnameinfo = socket.getnameinfo

    def tearDown(self):
        socket.getnameinfo = self._orig_getnameinfo

    def test_confirmed_ptr(self):
        stub = PtrStub(
            ptr_map={"1.2.3.4": ["host.example.test"]},
            forward_map={"host.example.test": ["1.2.3.4"]},
        )
        socket.getnameinfo = lambda sockaddr, flags: ("host.example.test", None)
        r = make_resolver(stub)
        result = r.resolve("1.2.3.4")
        self.assertEqual(result.confirmed, ["host.example.test"])
        self.assertEqual(result.unconfirmed, [])
        self.assertEqual(result.error, "")

    def test_unconfirmed_ptr(self):
        stub = PtrStub(
            ptr_map={"5.6.7.8": ["spoof.example.test"]},
            forward_map={"spoof.example.test": ["9.9.9.9"]},
        )
        socket.getnameinfo = lambda sockaddr, flags: ("spoof.example.test", None)
        r = make_resolver(stub)
        result = r.resolve("5.6.7.8")
        self.assertEqual(result.confirmed, [])
        self.assertEqual(result.unconfirmed, ["spoof.example.test"])

    def test_multiple_ptrs_confirmed_and_unconfirmed(self):
        stub = PtrStub(
            ptr_map={"10.0.0.1": ["a.example.test", "b.example.test"]},
            forward_map={
                "a.example.test": ["10.0.0.1"],
                "b.example.test": ["10.0.0.2"],
            },
        )
        seq = {iter([("a.example.test", None), ("b.example.test", None)])}
        def fake_getnameinfo(sockaddr, flags):
            ip = sockaddr[0]
            if ip == "10.0.0.1":
                ptr_names = self._ptr_names
                idx = self._ptr_idx
                if idx < len(ptr_names):
                    self._ptr_idx = idx + 1
                    return (ptr_names[idx], None)
            return ("", None)
        self._ptr_names = ["a.example.test", "b.example.test"]
        self._ptr_idx = 0
        socket.getnameinfo = fake_getnameinfo
        r = make_resolver(stub)
        result = r.resolve("10.0.0.1")
        self.assertEqual(result.confirmed, ["a.example.test"])
        self.assertEqual(result.unconfirmed, ["b.example.test"])

    def test_no_ptr_record(self):
        stub = PtrStub(ptr_map={"192.0.2.1": []}, forward_map={})
        socket.getnameinfo = lambda sockaddr, flags: ("", None)
        r = make_resolver(stub)
        result = r.resolve("192.0.2.1")
        self.assertEqual(result.confirmed, [])
        self.assertEqual(result.unconfirmed, [])

    def test_ptr_getnameinfo_error(self):
        stub = PtrStub(ptr_map={"192.0.2.2": []}, forward_map={})
        def fail(sockaddr, flags):
            raise socket.gaierror(socket.EAI_NONAME, "no PTR")
        socket.getnameinfo = fail
        r = make_resolver(stub)
        result = r.resolve("192.0.2.2")
        self.assertEqual(result.confirmed, [])
        self.assertEqual(result.unconfirmed, [])

    def test_invalid_ip(self):
        r = Resolver()
        result = r.resolve("not.an.ip.address")
        self.assertEqual(result.confirmed, [])
        self.assertEqual(result.unconfirmed, [])
        self.assertEqual(result.error, "invalid IP address")

    def test_empty_string(self):
        r = Resolver()
        result = r.resolve("")
        self.assertEqual(result.error, "invalid IP address")

    def test_duplicate_ptrs_deduplicated(self):
        stub = PtrStub(
            ptr_map={"10.0.0.3": ["dup.example.test"]},
            forward_map={"dup.example.test": ["10.0.0.3"]},
        )
        socket.getnameinfo = lambda sockaddr, flags: ("dup.example.test", None)
        r = make_resolver(stub)
        result = r.resolve("10.0.0.3")
        self.assertEqual(result.confirmed, ["dup.example.test"])

    def test_result_is_frozen(self):
        r = Resolver()
        try:
            socket.inet_aton("1.2.3.4")
            result = r.resolve("1.2.3.4")
        except (socket.gaierror, OSError):
            result = Result(address="1.2.3.4")
        with self.assertRaises(Exception):
            result.address = "5.6.7.8"

    def test_ipv6_confirmed(self):
        ip = "2001:db8::1"
        stub = PtrStub(
            ptr_map={ip: ["v6.example.test"]},
            forward_map={"v6.example.test": [ip]},
        )
        def resolve_v6(host, port, family=0, type=0, proto=0, flags=0):
            if host == ip:
                return [(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (host, port, 0, 0))]
            if host == "v6.example.test":
                return [(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (ip, port, 0, 0))]
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        socket.getnameinfo = lambda sockaddr, flags: ("v6.example.test", None)
        r = Resolver(resolver=resolve_v6)
        result = r.resolve(ip)
        self.assertEqual(result.confirmed, ["v6.example.test"])
        self.assertEqual(result.error, "")


if __name__ == "__main__":
    unittest.main()
