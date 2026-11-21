"""Scope-kontrol: AgentWatch scanner kun private netværk, du selv har angivet.

Det forhindrer både uheld (en tastefejl der scanner en offentlig IP) og at
LLM-analytikeren kan finde på at scanne noget uden for dit netværk.
"""

from __future__ import annotations

import ipaddress


class ScopeError(ValueError):
    pass


def parse_networks(cidrs: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if not (net.is_private or net.is_link_local):
            raise ScopeError(f"{c} er ikke et privat netværk – AgentWatch scanner kun lokale netværk")
        if net.version == 4 and net.prefixlen < 16:
            raise ScopeError(f"{c} er for stort (mindste prefix er /16)")
        nets.append(net)
    return nets


def ensure_in_scope(target: str, allowed: list[str]) -> str:
    """Returnér target hvis det (IP eller CIDR) ligger inden for de tilladte netværk."""
    nets = parse_networks(allowed)
    try:
        t = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScopeError(f"Ugyldigt mål: {target!r}") from exc
    for n in nets:
        if t.version == n.version and t.subnet_of(n):  # type: ignore[arg-type]
            return target
    raise ScopeError(f"{target} ligger uden for de tilladte netværk {allowed}")
