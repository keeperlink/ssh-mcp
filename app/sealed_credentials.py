"""Versioned, independently salted password verifiers and per-host sudo sealing.

Only an operator-entered Console password can open an encrypted sudo entry.
Verifier bytes are never useful as a decryption key. All data fields and KDF
parameters are bounded before any expensive work is performed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import threading
from copy import deepcopy
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

VERSION = 2
KDF_MEMORY_KIB = 65536
KDF_ITERATIONS = 3
KDF_LANES = 1
_SALT = 16
_NONCE = 12
_DIGEST = 32
_ALIAS = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_VERIFIER_KEYS = {"algorithm", "salt", "digest", "memory_kib", "iterations", "lanes"}
_ENVELOPE_KEYS = {"algorithm", "salt", "nonce", "ciphertext"}
_PURPOSES = {"oauth-login", "console-login"}
# At most 128 MiB of Argon2 workspace in simultaneous service requests.
# Call sites in HTTP handlers must also offload this synchronous work.
_KDF_CAPACITY = threading.BoundedSemaphore(value=2)


class InvalidCredential(ValueError):
    """Credential invalid or sealed material cannot be opened."""


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _decode(raw: Any, *, length: int | None = None, maximum: int = 8192) -> bytes:
    if type(raw) is not str or not 1 <= len(raw) <= ((maximum + 2) // 3) * 4:
        raise InvalidCredential("Invalid sealed credential encoding")
    try:
        result = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidCredential("Invalid sealed credential encoding") from None
    if len(result) > maximum or (length is not None and len(result) != length):
        raise InvalidCredential("Invalid sealed credential length")
    if _b64(result) != raw:
        raise InvalidCredential("Noncanonical sealed credential encoding")
    return result


def _password_bytes(password: str) -> bytes:
    if type(password) is not str or not 1 <= len(password) <= 256 or "\x00" in password:
        raise InvalidCredential("Invalid password input")
    result = password.encode("utf-8")
    if len(result) > 1024:
        raise InvalidCredential("Invalid password input")
    return result


def _derive(password: str, salt: bytes, purpose: str) -> bytes:
    # A verifier's digest or salt can never directly unlock an encrypted entry.
    if purpose not in {"oauth-login", "console-login", "sudo-wrap"}:
        raise InvalidCredential("Invalid key derivation domain")
    key = _password_bytes(password) + b"\x00ssh-mcp/v2/" + purpose.encode("ascii")
    with _KDF_CAPACITY:
        return Argon2id(salt=salt, length=_DIGEST, iterations=KDF_ITERATIONS,
                        lanes=KDF_LANES, memory_cost=KDF_MEMORY_KIB).derive(key)


def create_verifier(password: str, purpose: str) -> dict[str, str | int]:
    if purpose not in _PURPOSES:
        raise InvalidCredential("Invalid password verifier purpose")
    salt = secrets.token_bytes(_SALT)
    digest = _derive(password, salt, purpose)
    return {"algorithm": "argon2id", "salt": _b64(salt), "digest": _b64(digest),
            "memory_kib": KDF_MEMORY_KIB, "iterations": KDF_ITERATIONS, "lanes": KDF_LANES}


def validate_verifier(value: Any) -> None:
    if (type(value) is not dict or set(value) != _VERIFIER_KEYS or
            value["algorithm"] != "argon2id" or
            type(value["memory_kib"]) is not int or value["memory_kib"] != KDF_MEMORY_KIB or
            type(value["iterations"]) is not int or value["iterations"] != KDF_ITERATIONS or
            type(value["lanes"]) is not int or value["lanes"] != KDF_LANES):
        raise InvalidCredential("Unsupported password verifier")
    _decode(value["salt"], length=_SALT)
    _decode(value["digest"], length=_DIGEST)


def verify_password(password: str, value: Any, purpose: str) -> bool:
    validate_verifier(value)
    if purpose not in _PURPOSES:
        raise InvalidCredential("Invalid password verifier purpose")
    try:
        computed = _derive(password, _decode(value["salt"], length=_SALT), purpose)
    except InvalidCredential:
        return False
    return hmac.compare_digest(computed, _decode(value["digest"], length=_DIGEST))


def create_token_verifier(token: str) -> dict[str, str]:
    if type(token) is not str or not 32 <= len(token) <= 1024:
        raise InvalidCredential("Invalid metrics token")
    return {"algorithm": "sha256", "digest": hashlib.sha256(token.encode("utf-8")).hexdigest()}


def validate_token_verifier(value: Any) -> None:
    if (type(value) is not dict or set(value) != {"algorithm", "digest"} or
            value["algorithm"] != "sha256" or type(value["digest"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", value["digest"]) is None):
        raise InvalidCredential("Invalid metrics token verifier")


def verify_token(token: str, value: Any) -> bool:
    validate_token_verifier(value)
    if type(token) is not str or not 1 <= len(token) <= 1024:
        return False
    return hmac.compare_digest(hashlib.sha256(token.encode("utf-8")).hexdigest(),
                               value["digest"])


def _associated_data(deployment: str, issuer: str, alias: str, username: str) -> bytes:
    if (type(deployment) is not str or deployment not in {"lab", "production"} or
            type(issuer) is not str or not 8 <= len(issuer) <= 2048 or
            type(alias) is not str or _ALIAS.fullmatch(alias) is None or
            type(username) is not str or not 1 <= len(username) <= 32 or
            re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) is None):
        raise InvalidCredential("Invalid sudo encryption binding")
    return "\x00".join(("ssh-mcp-sudo-v2", deployment, issuer, alias, username)).encode("utf-8")


def seal_sudo(password: str, sudo_password: str, *, deployment: str, issuer: str,
              alias: str, username: str) -> dict[str, str]:
    if type(sudo_password) is not str or not 1 <= len(sudo_password.encode("utf-8")) <= 4096 or any(
        char in sudo_password for char in ("\x00", "\r", "\n")
    ):
        raise InvalidCredential("Invalid sudo credential")
    associated = _associated_data(deployment, issuer, alias, username)
    salt, nonce = secrets.token_bytes(_SALT), secrets.token_bytes(_NONCE)
    key = _derive(password, salt, "sudo-wrap")
    ciphertext = AESGCM(key).encrypt(nonce, sudo_password.encode("utf-8"), associated)
    return {"algorithm": "aes-256-gcm", "salt": _b64(salt),
            "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}


def validate_sealed_sudo(value: Any) -> None:
    if type(value) is not dict or set(value) != _ENVELOPE_KEYS or value["algorithm"] != "aes-256-gcm":
        raise InvalidCredential("Invalid sealed sudo envelope")
    _decode(value["salt"], length=_SALT)
    _decode(value["nonce"], length=_NONCE)
    if len(_decode(value["ciphertext"], maximum=4112)) < 17:
        raise InvalidCredential("Invalid sealed sudo ciphertext")


def unseal_sudo(password: str, value: Any, *, deployment: str, issuer: str,
                alias: str, username: str) -> str:
    validate_sealed_sudo(value)
    associated = _associated_data(deployment, issuer, alias, username)
    key = _derive(password, _decode(value["salt"], length=_SALT), "sudo-wrap")
    try:
        clear = AESGCM(key).decrypt(_decode(value["nonce"], length=_NONCE),
                                     _decode(value["ciphertext"], maximum=4112), associated)
    except (InvalidTag, ValueError):
        raise InvalidCredential("Sudo credentials could not be unlocked") from None
    try:
        result = clear.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidCredential("Invalid sudo credential") from None
    if not 1 <= len(clear) <= 4096 or any(ch in result for ch in ("\x00", "\r", "\n")):
        raise InvalidCredential("Invalid sudo credential")
    return result


def validate_v2_secrets(value: Any) -> None:
    keys = {"version", "oauth_login_verifier", "viewer_verifier", "viewer_generation",
            "metrics_verifier", "oauth_signing_key", "ssh_private_key", "sealed_sudo"}
    if type(value) is not dict or set(value) != keys or type(value.get("version")) is not int or value["version"] != VERSION:
        raise InvalidCredential("Managed secrets must use v2 sealed schema")
    validate_verifier(value["oauth_login_verifier"])
    validate_verifier(value["viewer_verifier"])
    validate_token_verifier(value["metrics_verifier"])
    generation = value["viewer_generation"]
    if (type(generation) is not str or re.fullmatch("[0-9a-f]{32}", generation) is None or
            type(value["sealed_sudo"]) is not dict):
        raise InvalidCredential("Invalid sealed secret generation or host mapping")
    for alias, envelope in value["sealed_sudo"].items():
        if type(alias) is not str or _ALIAS.fullmatch(alias) is None:
            raise InvalidCredential("Invalid sealed sudo alias")
        validate_sealed_sudo(envelope)
    signing = value["oauth_signing_key"]
    identity = value["ssh_private_key"]
    if (type(signing) is not str or not 32 <= len(signing) <= 8192
            or "\x00" in signing or
            type(identity) is not str or not 80 <= len(identity) <= 100000 or
            not identity.startswith("-----BEGIN OPENSSH PRIVATE KEY-----") or
            not identity.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----")
            or "\x00" in identity):
        raise InvalidCredential("Invalid recoverable service key")


def from_legacy(value: dict[str, Any], *, console_password: str,
                deployment: str, issuer: str,
                hosts: dict[str, str]) -> dict[str, Any]:
    """Convert one trusted v1 source entirely in memory; caller controls staging.

    Host identities must come from the independently reviewed signed inventory.
    Unknown/stale sudo aliases fail closed instead of silently dropping secrets.
    """
    required = {"version", "oauth_login_key", "oauth_signing_key", "viewer_password",
                "metrics_token", "ssh_private_key"}
    if (type(value) is not dict or set(value) not in (required, required | {"sudo_passwords"})
            or type(value["version"]) is not int or value["version"] != 1):
        raise InvalidCredential("Invalid legacy source; no conversion performed")
    keys = ("oauth_login_key", "oauth_signing_key", "viewer_password", "metrics_token")
    if any(type(value[k]) is not str or not 32 <= len(value[k]) <= 8192
           for k in keys if k != "viewer_password"):
        raise InvalidCredential("Invalid legacy credential")
    if type(value["viewer_password"]) is not str or len(value["viewer_password"]) < 16:
        raise InvalidCredential("Invalid legacy Console password")
    if len({value[k] for k in keys}) != len(keys) or not hmac.compare_digest(
        _password_bytes(console_password), _password_bytes(value["viewer_password"])
    ):
        raise InvalidCredential("Invalid Console password or credential separation")
    old_sudo = value.get("sudo_passwords", {})
    if (type(old_sudo) is not dict or type(hosts) is not dict or
            any(type(alias) is not str or alias not in hosts for alias in old_sudo)):
        raise InvalidCredential("Unrecognized sudo host alias")
    encrypted = {
        alias: seal_sudo(console_password, credential, deployment=deployment,
                         issuer=issuer, alias=alias, username=hosts[alias])
        for alias, credential in old_sudo.items()
    }
    converted = {
        "version": VERSION,
        "oauth_login_verifier": create_verifier(value["oauth_login_key"], "oauth-login"),
        "viewer_verifier": create_verifier(console_password, "console-login"),
        "viewer_generation": secrets.token_hex(16),
        "metrics_verifier": create_token_verifier(value["metrics_token"]),
        "oauth_signing_key": value["oauth_signing_key"],
        "ssh_private_key": value["ssh_private_key"],
        "sealed_sudo": encrypted,
    }
    validate_v2_secrets(converted)
    return converted


def rotate_console(value: dict[str, Any], *, old_password: str, new_password: str,
                   deployment: str, issuer: str,
                   hosts: dict[str, str]) -> dict[str, Any]:
    """Atomically prepare a full rekey; never edit the original secret revision."""
    validate_v2_secrets(value)
    if not verify_password(old_password, value["viewer_verifier"], "console-login"):
        raise InvalidCredential("Console password rejected")
    if old_password == new_password or len(_password_bytes(new_password)) < 16:
        raise InvalidCredential("Console password must change")
    if set(value["sealed_sudo"]) - set(hosts):
        raise InvalidCredential("Missing signed host binding")
    entries = {
        alias: unseal_sudo(old_password, envelope, deployment=deployment,
                           issuer=issuer, alias=alias, username=hosts[alias])
        for alias, envelope in value["sealed_sudo"].items()
    }
    replacement = deepcopy(value)
    replacement["viewer_verifier"] = create_verifier(new_password, "console-login")
    replacement["viewer_generation"] = secrets.token_hex(16)
    replacement["sealed_sudo"] = {
        alias: seal_sudo(new_password, credential, deployment=deployment,
                         issuer=issuer, alias=alias, username=hosts[alias])
        for alias, credential in entries.items()
    }
    validate_v2_secrets(replacement)
    return replacement


def rotate_host_sudo(value: dict[str, Any], *, console_password: str,
                     new_sudo_password: str, deployment: str, issuer: str,
                     alias: str, username: str) -> dict[str, Any]:
    validate_v2_secrets(value)
    if alias not in value["sealed_sudo"] or not verify_password(
        console_password, value["viewer_verifier"], "console-login"
    ):
        raise InvalidCredential("Sudo rotation not authorized")
    previous = unseal_sudo(console_password, value["sealed_sudo"][alias],
                            deployment=deployment, issuer=issuer, alias=alias,
                            username=username)
    if hmac.compare_digest(previous, new_sudo_password):
        raise InvalidCredential("Host sudo password must change")
    replacement = deepcopy(value)
    replacement["sealed_sudo"][alias] = seal_sudo(
        console_password, new_sudo_password, deployment=deployment, issuer=issuer,
        alias=alias, username=username,
    )
    return replacement
