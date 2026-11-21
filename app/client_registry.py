"""Operator-pinned OAuth client identities and conversation-ID sources.

Display names are never OAuth principals. No wildcard identity matching.
"""
from __future__ import annotations

import json
import re
from typing import Any, cast

from .client_metadata import _parts
from .dcr_registry import DCR_CLIENT_ID_PATTERN

_HEADER = re.compile(r"X-[A-Za-z0-9][A-Za-z0-9-]{0,62}\Z", re.I | re.ASCII)
_FIELD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}\Z", re.ASCII)
_BLOCKED = {"authorization", "cookie", "set-cookie", "x-real-ip", "x-client-ip",
            "x-remote-ip", "x-true-client-ip", "x-cluster-client-ip", "x-proxyuser-ip"}
_MAX_CLIENTS = 32
_MAX_IDENTITIES = 16
_MAX_SOURCES = 8


def parse_clients(raw: Any) -> dict[str, dict[str, Any]]:
    """Fail closed on ambiguous labels, duplicate identities or unsafe selectors."""
    if type(raw) is not dict or len(raw) > _MAX_CLIENTS:
        raise ValueError("Invalid client definitions")
    result: dict[str, dict[str, Any]] = {}
    names = {"unknown"}
    identities: set[str] = set()
    for label, definition in raw.items():
        if (type(label) is not str or not 1 <= len(label) <= 32
                or label != label.strip() or not label.isprintable()
                or label.casefold() in names):
            raise ValueError("Invalid or duplicate client display name")
        names.add(label.casefold())
        if (type(definition) is not dict
                or not {"identities", "conversation_id"} <= set(definition)
                or set(definition) - {"identities", "conversation_id", "offline_redirect_uris"}):
            raise ValueError("Invalid client definition")
        values = definition["identities"]
        if (type(values) is not list or not 1 <= len(values) <= _MAX_IDENTITIES
                or any(type(value) is not str for value in values)):
            raise ValueError("Invalid client identities")
        for value in values:
            if not DCR_CLIENT_ID_PATTERN.fullmatch(value):
                _parts(value, metadata=True)
            if value in identities:
                raise ValueError("Duplicate OAuth client identity")
            identities.add(value)
        cid = definition["conversation_id"]
        if type(cid) is not dict or set(cid) != {"sources"}:
            raise ValueError("Invalid conversation selector configuration")
        sources = cid["sources"]
        if type(sources) is not list or len(sources) > _MAX_SOURCES:
            raise ValueError("Invalid conversation selector sources")
        distinct: set[tuple[str, str, str]] = set()
        for source in sources:
            if type(source) is not dict or source.get("type") not in ("header", "metadata"):
                raise ValueError("Invalid conversation selector")
            kind = source["type"]
            if (set(source) != ({"type", "name"} if kind == "header"
                                else {"type", "name", "field"} if "field" in source
                                else {"type", "name"})):
                raise ValueError("Invalid conversation selector fields")
            name = source.get("name")
            field = source.get("field", "")
            if kind == "header":
                if (type(name) is not str or not _HEADER.fullmatch(name)
                        or name.lower().startswith(("x-forwarded-", "x-original-"))
                        or name.lower() in _BLOCKED):
                    raise ValueError("Unsafe conversation header")
            elif (type(name) is not str or not _FIELD.fullmatch(name)
                  or ("field" in source and
                      (type(field) is not str or not _FIELD.fullmatch(field)))):
                raise ValueError("Invalid conversation metadata path")
            fingerprint = (kind, name.lower() if kind == "header" else name, field)
            if fingerprint in distinct:
                raise ValueError("Duplicate conversation source")
            distinct.add(fingerprint)
        offline = definition.get("offline_redirect_uris", [])
        if (type(offline) is not list or len(offline) > 16
                or any(type(uri) is not str for uri in offline)):
            raise ValueError("Invalid offline redirect URIs")
        # Strict HTTPS redirect syntax; dynamic clients use DCR's independent
        # native-loopback policy instead.
        for uri in offline:
            parts = _parts(uri)
            if parts.scheme != "https" or "#" in uri or "," in uri:
                raise ValueError("Offline redirects must be HTTPS")
        if offline and (len(offline) != len(set(offline))
                        or not values[0].startswith("https://")):
            raise ValueError("Invalid offline client")
        result[label] = definition
    if sum(bool(v.get("offline_redirect_uris")) for v in result.values()) > 1:
        raise ValueError("Only one offline fallback client may be configured")
    return result


def labels(clients: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {identity: name for name, data in clients.items()
            for identity in data["identities"]}


def sources_for(client_id: str | None,
                clients: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    if client_id is None:
        return []
    for data in clients.values():
        if client_id in data["identities"]:
            return cast(list[dict[str, str]], data["conversation_id"]["sources"])
    return []


def offline_client(clients: dict[str, dict[str, Any]]) -> tuple[str, list[str]] | None:
    for data in clients.values():
        if uris := data.get("offline_redirect_uris", []):
            return data["identities"][0], uris
    return None


def clients_from_environment(value: str) -> dict[str, dict[str, Any]]:
    return parse_clients(json.loads(value))
