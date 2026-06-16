from dataclasses import dataclass, field
from typing import Optional
import time
import uuid


@dataclass
class Tenant:
    tenant_id: str
    access_key: str
    secret_key: str
    quota_bytes: int
    used_bytes: int = 0
    created_at: float = field(default_factory=time.time)


@dataclass
class Bucket:
    tenant_id: str
    bucket_name: str
    acl: str = "private"
    created_at: float = field(default_factory=time.time)


@dataclass
class ObjectMeta:
    tenant_id: str
    bucket_name: str
    object_key: str
    object_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    size: int = 0
    checksum_sha256: str = ""
    content_type: str = "application/octet-stream"
    acl: str = "private"
    is_multipart: bool = False
    upload_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class MultipartPart:
    upload_id: str
    part_number: int
    tenant_id: str
    bucket_name: str
    object_key: str
    size: int = 0
    etag: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class Grant:
    resource_type: str
    resource_name: str
    owner_tenant_id: str
    grantee_tenant_id: str
    permission: str
    granted_at: float = field(default_factory=time.time)
