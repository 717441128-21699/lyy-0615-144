import hashlib
import hmac
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Optional, Tuple
from .metadata import MetadataStore
from .models import Tenant


class AuthError(Exception):
    pass


class Signer:
    ALGORITHM = "OBJSTORE-HMAC-SHA256"

    @staticmethod
    def compute_signature(secret_key: str, method: str, path: str,
                          date: str, content_hash: str) -> str:
        canonical = f"{method}\n{path}\n\n{date}\n{content_hash}"
        return hmac.new(
            secret_key.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_signature(secret_key: str, method: str, path: str,
                         date: str, content_hash: str,
                         provided_sig: str) -> bool:
        expected = Signer.compute_signature(secret_key, method, path,
                                            date, content_hash)
        return hmac.compare_digest(expected, provided_sig)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def authenticate_request(handler: BaseHTTPRequestHandler,
                         meta: MetadataStore) -> Tenant:
    auth_header = handler.headers.get("Authorization", "")
    date_header = handler.headers.get("X-ObjStore-Date",
                  handler.headers.get("X-Date", ""))
    content_hash_header = handler.headers.get("X-ObjStore-Content-Sha256",
                          handler.headers.get("X-Content-SHA256",
                          handler.headers.get("X-Content-Sha256", "")))

    if not auth_header or not date_header:
        raise AuthError("Missing Authorization or X-ObjStore-Date header")

    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != Signer.ALGORITHM:
        raise AuthError(f"Invalid Authorization format, expected {Signer.ALGORITHM}")

    credential_sig = parts[1]
    cred_parts = credential_sig.split(":", 1)
    if len(cred_parts) != 2:
        raise AuthError("Invalid credential format, expected access_key:signature")

    access_key, provided_sig = cred_parts[0], cred_parts[1]

    tenant = meta.get_tenant_by_access_key(access_key)
    if not tenant:
        raise AuthError("Invalid access key")

    if not content_hash_header:
        content_hash_header = sha256_hex(b"")

    method = handler.command
    path = handler.path

    if not Signer.verify_signature(tenant.secret_key, method, path,
                                   date_header, content_hash_header,
                                   provided_sig):
        raise AuthError("Signature verification failed")

    return tenant
