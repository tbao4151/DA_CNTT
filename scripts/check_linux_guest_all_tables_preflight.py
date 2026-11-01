"""Conservative, read-only comparison of pinned Linux all-table route snapshots.

Does not inspect the running kernel or certify Host-only isolation.
"""
from __future__ import annotations

import ipaddress
import json
from collections import Counter

_TABLES = {"main": 254, "local": 255}
_LOCAL_TYPES = frozenset({"local", "broadcast", "multicast", "anycast"})
_FORBIDDEN_LOCAL = frozenset({
    "gateway", "via", "multipath", "nhid", "encap", "nexthops", "newdst",
})


def _table_id(value):
    if type(value) is int:
        return value
    if isinstance(value, str):
        return _TABLES.get(value)
    return None


def _main_signature(route):
    if not isinstance(route, dict) or _table_id(route.get("table", "main")) != 254:
        raise ValueError("Malformed main route")
    normalized = dict(route)
    normalized.pop("table", None)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _local_destination_allowed(network, *, route_type, dev, adapter, scope):
    """Bound local-table destinations to the approved guest or kernel-local ranges.

    These are conservative snapshot constraints, not proof of live routing.
    """
    if network.version == 4:
        multicast = ipaddress.IPv4Network("224.0.0.0/4")
        if route_type == "multicast":
            return network.subnet_of(multicast)
        if network.subnet_of(multicast):
            return False
        if (route_type == "broadcast" and dev == adapter
                and network == ipaddress.IPv4Network("255.255.255.255/32")):
            return True
        allowed = (ipaddress.IPv4Network("127.0.0.0/8") if dev == "lo"
                   else scope)
        return network.subnet_of(allowed)
    multicast = ipaddress.IPv6Network("ff00::/8")
    if route_type == "multicast":
        return network.subnet_of(multicast)
    if network.subnet_of(multicast):
        return False
    allowed = (ipaddress.IPv6Network("::1/128") if dev == "lo"
               else ipaddress.IPv6Network("fe80::/10"))
    return network.subnet_of(allowed)


def _check_family(main_routes, all_routes, *, version, adapter, scope):
    if (not isinstance(main_routes, list) or not isinstance(all_routes, list)
            or len(all_routes) > 64):
        raise ValueError("Invalid all-table route inventory")
    expected = Counter(_main_signature(route) for route in main_routes)
    observed = Counter()
    for route in all_routes:
        if not isinstance(route, dict):
            raise ValueError("Malformed all-table route")
        table = _table_id(route.get("table", "main"))
        if table == 254:
            observed[_main_signature(route)] += 1
            continue
        if table != 255:
            raise ValueError("Non-local alternate routing table present")
        if (route.get("type") not in _LOCAL_TYPES
                or route.get("dev") not in ("lo", adapter)
                or _FORBIDDEN_LOCAL.intersection(route)):
            raise ValueError("Unexpected local-table route")
        destination = route.get("dst")
        if not isinstance(destination, str) or destination == "default":
            raise ValueError("Invalid local-table destination")
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError as exc:
            raise ValueError("Invalid local-table destination") from exc
        if network.version != version or network.prefixlen == 0:
            raise ValueError("Wrong-family or default local-table route")
        if not _local_destination_allowed(
                network, route_type=route["type"], dev=route["dev"],
                adapter=adapter, scope=scope):
            raise ValueError("Local-table destination outside approved scope")
    if observed != expected:
        raise ValueError("All-table and main-table route snapshots disagree")


def assess_all_tables(main_v4, main_v6, all_v4, all_v6, *, adapter, cidr):
    """Reject alternate tables, out-of-scope local entries and mismatched routes."""
    if not isinstance(adapter, str) or not adapter.strip() or adapter == "lo":
        raise ValueError("Approved adapter required")
    scope = ipaddress.ip_network(cidr, strict=True)
    if not isinstance(scope, ipaddress.IPv4Network):
        raise ValueError("Approved IPv4 lab CIDR required")
    _check_family(main_v4, all_v4, version=4, adapter=adapter, scope=scope)
    _check_family(main_v6, all_v6, version=6, adapter=adapter, scope=scope)
    return True
