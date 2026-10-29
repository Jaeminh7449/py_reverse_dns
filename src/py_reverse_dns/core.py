"""Reverse DNS resolution with forward-confirmation of PTR records.

This module uses only the Python standard library and performs network I/O
exclusively through :py:mod:`socket`. Reverse lookups are started by
``socket.getaddrinfo`` with the ``socket.AI_NUMERICHOST`` flag so that a
host name can never be accidentally treated as an address. Every PTR
record returned is then forward-confirmed by resolving the host name to a
list of addresses and checking that the original IP is present in that
list. Unconfirmed names are dropped to avoid returning spoofed PTR data.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Result:
    """Outcome of a reverse DNS lookup for a single IP address.

    ``confirmed`` is the list of PTR host names that were independently
    resolved back to the original address. ``unconfirmed`` is the list of
    PTR names the resolver produced but that did not forward-resolve to
    the query address; keeping them lets callers see what was rejected
    and why. ``error`` is the message captured when the lookup itself
    failed and is the empty string when no error occurred.
    """

    address: str
    confirmed: List[str] = field(default_factory=list)
    unconfirmed: List[str] = field(default_factory=list)
    error: str = ""


class Resolver:
    """Reverse DNS resolver with forward-confirmation.

    The resolver wraps :py:mod:`socket` so that callers can provide a
    custom resolution function in tests, avoiding live network access
    entirely. The default ``resolver`` is :py:func:`socket.getaddrinfo`.
    """

    def __init__(self, resolver=None) -> None:
        # Allow injection of a fake resolver so tests never touch the
        # network. The signature mirrors socket.getaddrinfo.
        self._resolve = resolver or socket.getaddrinfo

    def _lookup_ptr(self, ip: str) -> List[str]:
        """Return PTR host names for *ip*, or an empty list on failure."""
        try:
            # AI_NUMERICHOST guarantees getaddrinfo treats *ip* as an
            # address literal and never re-parses it as a host name.
            infos = self._resolve(
                ip, None, proto=socket.IPPROTO_UDP, flags=socket.AI_NUMERICHOST
            )
        except socket.gaierror:
            return []
        names: List[str] = []
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            # getnameinfo on the sockaddr performs the actual PTR query.
            try:
                host = socket.getnameinfo(sockaddr, socket.NI_NAMEREQD)
            except socket.gaierror:
                continue
            name = host[0]
            if name and name not in names:
                names.append(name)
        return names

    def _forward_resolves_to(self, hostname: str, ip: str) -> bool:
        """Return True if *hostname* resolves to a list containing *ip*."""
        try:
            infos = self._resolve(hostname, None)
        except socket.gaierror:
            return False
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            if sockaddr[0] == ip:
                return True
        return False

    def resolve(self, ip: str) -> Result:
        """Perform a reverse DNS lookup for *ip* with confirmation.

        If *ip* is not a valid address literal, ``error`` is set and no
        names are returned. Otherwise each PTR name found is split on
        forward-confirmation: only names that forward-resolve back to
        *ip* appear in ``confirmed``.
        """
        confirmed: List[str] = []
        unconfirmed: List[str] = []
        try:
            socket.inet_aton(ip)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
            except OSError:
                return Result(address=ip, error="invalid IP address")
        ptr_names = self._lookup_ptr(ip)
        for name in ptr_names:
            if self._forward_resolves_to(name, ip):
                confirmed.append(name)
            else:
                unconfirmed.append(name)
        return Result(
            address=ip,
            confirmed=confirmed,
            unconfirmed=unconfirmed,
        )
