import json
import sys
import traceback
import time
import uuid
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Optional
from .auth import authenticate_request, AuthError
from .metadata import MetadataStore
from .storage import DataStore
from .quota import QuotaManager, QuotaError
from .models import Tenant, Bucket, ObjectMeta, MultipartPart, Grant


class ObjStoreHandler(BaseHTTPRequestHandler):
    meta: MetadataStore = None
    storage: DataStore = None
    quota: QuotaManager = None
    admin_tenant_id: Optional[str] = None

    def log_message(self, format, *args):
        pass

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code: int, message: str):
        self._send_json(code, {"error": message})

    def _send_data(self, code: int, data: bytes, content_type: str,
                   metadata: Optional[ObjectMeta] = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if metadata:
            self.send_header("X-Object-Id", metadata.object_id)
            self.send_header("X-Object-Size", str(metadata.size))
            self.send_header("X-Object-Sha256", metadata.checksum_sha256)
            self.send_header("X-Object-ACL", metadata.acl)
            self.send_header("X-Object-Created", str(metadata.created_at))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _drain_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            try:
                while length > 0:
                    chunk = self.rfile.read(min(65536, length))
                    if not chunk:
                        break
                    length -= len(chunk)
            except Exception:
                pass

    def _get_tenant(self) -> Tenant:
        return authenticate_request(self, self.meta)

    def _parse_path(self) -> tuple:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.strip("/")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        parts = path.split("/", 1) if path else []
        bucket = parts[0] if len(parts) >= 1 else ""
        key = parts[1] if len(parts) >= 2 else ""
        return bucket, key, query

    def _require_bucket(self, tenant: Tenant, bucket_name: str,
                        require_owner: bool = True) -> Optional[Bucket]:
        b = self.meta.get_bucket(tenant.tenant_id, bucket_name)
        if not b:
            if require_owner:
                self._send_error(404, f"Bucket '{bucket_name}' not found")
                return None
            b = None
            all_buckets = self.meta.list_all_buckets()
            for ab in all_buckets:
                if ab.bucket_name == bucket_name:
                    b = ab
                    break
            if not b:
                self._send_error(404, f"Bucket '{bucket_name}' not found")
                return None
        return b

    def _check_bucket_read(self, tenant: Tenant, bucket: Bucket) -> bool:
        if bucket.tenant_id == tenant.tenant_id:
            return True
        if bucket.acl == "public-read":
            return True
        if self.meta.check_grant("bucket", bucket.bucket_name,
                                 bucket.tenant_id, tenant.tenant_id, "READ"):
            return True
        return False

    def _check_bucket_write(self, tenant: Tenant, bucket: Bucket) -> bool:
        if bucket.tenant_id == tenant.tenant_id:
            return True
        if bucket.acl == "public-read-write":
            return True
        if self.meta.check_grant("bucket", bucket.bucket_name,
                                 bucket.tenant_id, tenant.tenant_id, "WRITE"):
            return True
        return False

    def _check_object_read(self, tenant: Tenant, bucket: Bucket,
                           obj: ObjectMeta) -> bool:
        if obj.tenant_id == tenant.tenant_id:
            return True
        if obj.acl == "public-read":
            return True
        if bucket.acl == "public-read":
            return True
        if bucket.acl == "public-read-write":
            return True
        if self.meta.check_grant("object", f"{bucket.bucket_name}/{obj.object_key}",
                                 obj.tenant_id, tenant.tenant_id, "READ"):
            return True
        if self.meta.check_grant("bucket", bucket.bucket_name,
                                 bucket.tenant_id, tenant.tenant_id, "READ"):
            return True
        return False

    def _check_object_write(self, tenant: Tenant, bucket: Bucket,
                            obj: Optional[ObjectMeta]) -> bool:
        if obj is not None and obj.tenant_id == tenant.tenant_id:
            return True
        if bucket.tenant_id == tenant.tenant_id:
            return True
        if bucket.acl == "public-read-write":
            return True
        if obj is not None and self.meta.check_grant(
                "object", f"{bucket.bucket_name}/{obj.object_key}",
                obj.tenant_id, tenant.tenant_id, "WRITE"):
            return True
        if self.meta.check_grant("bucket", bucket.bucket_name,
                                 bucket.tenant_id, tenant.tenant_id, "WRITE"):
            return True
        return False

    # ── GET ──

    def do_GET(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            return self._send_error(401, str(e))

        bucket_name, key, query = self._parse_path()

        try:
            if not bucket_name:
                return self._handle_list_buckets(tenant)

            if bucket_name == "_admin":
                return self._handle_admin_get(tenant, key, query)

            if key == "":
                if "acl" in query:
                    return self._handle_get_bucket_acl(tenant, bucket_name)
                if "quota" in query:
                    return self._handle_get_quota(tenant, bucket_name)
                return self._handle_list_objects(tenant, bucket_name, query)

            if "acl" in query:
                return self._handle_get_object_acl(tenant, bucket_name, key)

            if "uploadId" in query:
                return self._handle_list_parts(tenant, bucket_name, key, query)

            return self._handle_get_object(tenant, bucket_name, key)
        except Exception as e:
            traceback.print_exc()
            self._send_error(500, f"Internal error: {e}")

    def _handle_admin_get(self, tenant: Tenant, subpath: str, query: dict):
        if self.admin_tenant_id and tenant.tenant_id != self.admin_tenant_id:
            return self._send_error(403, "Admin access required")

        parts = subpath.split("/", 1) if subpath else []
        action = parts[0] if parts else ""

        if action == "tenants":
            tenants = self.meta.list_all_tenants()
            result = []
            for t in tenants:
                usage = self.meta.calc_tenant_real_usage(t.tenant_id)
                result.append({
                    "tenant_id": t.tenant_id,
                    "access_key": t.access_key,
                    "quota_bytes": t.quota_bytes,
                    "recorded_used_bytes": t.used_bytes,
                    "real_usage": usage,
                })
            return self._send_json(200, {"tenants": result})

        if action == "tenant" and len(parts) >= 2:
            target_id = parts[1]
            usage = self.meta.calc_tenant_real_usage(target_id)
            return self._send_json(200, usage)

        if action == "expired-multipart":
            expired = self.meta.list_expired_multipart_uploads()
            return self._send_json(200, {
                "count": len(expired),
                "uploads": [
                    {
                        "tenant_id": o.tenant_id,
                        "bucket": o.bucket_name,
                        "key": o.object_key,
                        "upload_id": o.upload_id,
                        "updated_at": o.updated_at,
                    }
                    for o in expired
                ]
            })

        return self._send_error(400, "Unknown admin action")

    def _handle_list_buckets(self, tenant: Tenant):
        buckets = self.meta.list_buckets(tenant.tenant_id)
        self._send_json(200, {
            "buckets": [
                {
                    "name": b.bucket_name,
                    "acl": b.acl,
                    "created_at": b.created_at,
                }
                for b in buckets
            ]
        })

    def _handle_get_bucket_acl(self, tenant: Tenant, bucket_name: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if b.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Bucket '{bucket_name}' not found")
        grants = self.meta.list_grants("bucket", bucket_name, b.tenant_id)
        self._send_json(200, {
            "bucket": bucket_name,
            "acl": b.acl,
            "owner": b.tenant_id,
            "grants": [
                {
                    "grantee_tenant_id": g.grantee_tenant_id,
                    "permission": g.permission,
                }
                for g in grants
            ]
        })

    def _handle_get_object_acl(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Object '{key}' not found")
        grants = self.meta.list_grants(
            "object", f"{bucket_name}/{key}", meta.tenant_id
        )
        self._send_json(200, {
            "bucket": bucket_name,
            "key": key,
            "acl": meta.acl,
            "owner": meta.tenant_id,
            "grants": [
                {
                    "grantee_tenant_id": g.grantee_tenant_id,
                    "permission": g.permission,
                }
                for g in grants
            ]
        })

    def _handle_list_objects(self, tenant: Tenant, bucket_name: str, query: dict):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        if not self._check_bucket_read(tenant, b):
            return self._send_error(404, f"Bucket '{bucket_name}' not found")
        prefix = query.get("prefix", [""])[0]
        objects = self.meta.list_objects(b.tenant_id, bucket_name, prefix)
        self._send_json(200, {
            "bucket": bucket_name,
            "prefix": prefix,
            "objects": [
                {
                    "key": o.object_key,
                    "size": o.size,
                    "sha256": o.checksum_sha256,
                    "acl": o.acl,
                    "content_type": o.content_type,
                    "is_multipart": o.is_multipart,
                    "created_at": o.created_at,
                    "updated_at": o.updated_at,
                }
                for o in objects
            ]
        })

    def _handle_get_object(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if meta.is_multipart and meta.upload_id:
            return self._send_error(404, f"Object '{key}' not found")
        if not self._check_object_read(tenant, b, meta):
            return self._send_error(404, f"Object '{key}' not found")
        data = self.storage.read_object(b.tenant_id, bucket_name, meta.object_id)
        if data is None:
            return self._send_error(404, "Object data not found on disk")
        self._send_data(200, data, meta.content_type, meta)

    def _handle_get_quota(self, tenant: Tenant, bucket_name: str):
        try:
            usage = self.quota.get_usage(tenant.tenant_id)
            detail = self.meta.calc_tenant_real_usage(tenant.tenant_id)
            usage["detail"] = detail
            self._send_json(200, usage)
        except QuotaError as e:
            self._send_error(404, str(e))

    def _handle_list_parts(self, tenant: Tenant, bucket_name: str,
                           key: str, query: dict):
        upload_id = query["uploadId"][0]
        mp_meta = self.meta.get_multipart_meta(upload_id)
        if not mp_meta or mp_meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, "Multipart upload not found")
        parts = self.meta.list_parts(upload_id)
        self._send_json(200, {
            "upload_id": upload_id,
            "bucket": bucket_name,
            "key": key,
            "parts": [
                {
                    "part_number": p.part_number,
                    "size": p.size,
                    "etag": p.etag,
                    "created_at": p.created_at,
                }
                for p in parts
            ]
        })

    # ── PUT ──

    def do_PUT(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            return self._send_error(401, str(e))

        try:
            bucket_name, key, query = self._parse_path()

            if not bucket_name:
                return self._send_error(400, "Bucket name required")

            if "uploads" in query and not key:
                return self._handle_create_bucket(tenant, bucket_name)

            if "acl" in query and not key:
                return self._handle_put_bucket_acl(tenant, bucket_name)

            if "acl" in query and key:
                return self._handle_put_object_acl(tenant, bucket_name, key)

            if "grant" in query and not key:
                return self._handle_put_bucket_grant(tenant, bucket_name)

            if "grant" in query and key:
                return self._handle_put_object_grant(tenant, bucket_name, key)

            if "uploadId" in query and key:
                return self._handle_upload_part(tenant, bucket_name, key, query)

            if not key:
                return self._send_error(400, "Object key required")

            return self._handle_put_object(tenant, bucket_name, key)
        except Exception as e:
            traceback.print_exc()
            self._send_error(500, f"Internal error: {e}")

    def _handle_create_bucket(self, tenant: Tenant, bucket_name: str):
        existing = self.meta.get_bucket(tenant.tenant_id, bucket_name)
        if existing:
            return self._send_json(200, {
                "name": existing.bucket_name,
                "acl": existing.acl,
                "created": False,
            })
        acl = self.headers.get("X-Bucket-ACL", "private")
        bucket = Bucket(
            tenant_id=tenant.tenant_id,
            bucket_name=bucket_name,
            acl=acl,
        )
        self.meta.create_bucket(bucket)
        self._send_json(201, {
            "name": bucket.bucket_name,
            "acl": bucket.acl,
            "created": True,
        })

    def _handle_put_bucket_acl(self, tenant: Tenant, bucket_name: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if b.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Bucket '{bucket_name}' not found")
        acl = self.headers.get("X-Bucket-ACL")
        if not acl:
            return self._send_error(400, "X-Bucket-ACL header required")
        if acl not in ("private", "public-read", "public-read-write"):
            return self._send_error(400, "Invalid ACL: must be private/public-read/public-read-write")
        self.meta.set_bucket_acl(tenant.tenant_id, bucket_name, acl)
        self._send_json(200, {"bucket": bucket_name, "acl": acl})

    def _handle_put_object_acl(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Object '{key}' not found")
        acl = self.headers.get("X-Object-ACL")
        if not acl:
            return self._send_error(400, "X-Object-ACL header required")
        if acl not in ("private", "public-read", "public-read-write"):
            return self._send_error(400, "Invalid ACL: must be private/public-read/public-read-write")
        meta.acl = acl
        meta.updated_at = time.time()
        self.meta.put_object_meta(meta)
        self._send_json(200, {"bucket": bucket_name, "key": key, "acl": acl})

    def _handle_put_bucket_grant(self, tenant: Tenant, bucket_name: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if b.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Bucket '{bucket_name}' not found")
        body = self._read_body()
        try:
            req = json.loads(body)
        except Exception:
            return self._send_error(400, "Invalid JSON body")
        grantee_id = req.get("grantee_tenant_id")
        permission = req.get("permission", "READ")
        if not grantee_id:
            return self._send_error(400, "grantee_tenant_id required")
        if permission not in ("READ", "WRITE"):
            return self._send_error(400, "permission must be READ or WRITE")
        grant = Grant(
            resource_type="bucket",
            resource_name=bucket_name,
            owner_tenant_id=tenant.tenant_id,
            grantee_tenant_id=grantee_id,
            permission=permission,
        )
        self.meta.add_grant(grant)
        self._send_json(200, {
            "bucket": bucket_name,
            "grantee_tenant_id": grantee_id,
            "permission": permission,
        })

    def _handle_put_object_grant(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Object '{key}' not found")
        body = self._read_body()
        try:
            req = json.loads(body)
        except Exception:
            return self._send_error(400, "Invalid JSON body")
        grantee_id = req.get("grantee_tenant_id")
        permission = req.get("permission", "READ")
        if not grantee_id:
            return self._send_error(400, "grantee_tenant_id required")
        if permission not in ("READ", "WRITE"):
            return self._send_error(400, "permission must be READ or WRITE")
        grant = Grant(
            resource_type="object",
            resource_name=f"{bucket_name}/{key}",
            owner_tenant_id=tenant.tenant_id,
            grantee_tenant_id=grantee_id,
            permission=permission,
        )
        self.meta.add_grant(grant)
        self._send_json(200, {
            "bucket": bucket_name,
            "key": key,
            "grantee_tenant_id": grantee_id,
            "permission": permission,
        })

    def _handle_put_object(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        if not self._check_bucket_write(tenant, b):
            return self._send_error(404, f"Bucket '{bucket_name}' not found")

        content_length = int(self.headers.get("Content-Length", 0))
        content_type = self.headers.get("Content-Type", "application/octet-stream")
        acl = self.headers.get("X-Object-ACL", "private")

        old_meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
        effective_tenant_id = b.tenant_id

        try:
            if old_meta:
                self.quota.replace_object(effective_tenant_id, old_meta.size, content_length)
            else:
                self.quota.check_and_reserve(effective_tenant_id, content_length)
        except QuotaError as e:
            self._drain_body()
            return self._send_error(413, str(e))

        object_id = uuid.uuid4().hex
        old_object_id = old_meta.object_id if old_meta else None
        try:
            size, checksum = self.storage.write_object_stream(
                effective_tenant_id, bucket_name, object_id,
                self.rfile, content_length
            )
        except Exception as e:
            self.quota.release(effective_tenant_id, content_length)
            if old_meta:
                self.quota.check_and_reserve(effective_tenant_id, old_meta.size)
            return self._send_error(500, f"Failed to write object: {e}")

        if size != content_length:
            self.quota.release(effective_tenant_id, content_length - size)

        now = time.time()
        obj = ObjectMeta(
            tenant_id=effective_tenant_id,
            bucket_name=bucket_name,
            object_key=key,
            object_id=object_id,
            size=size,
            checksum_sha256=checksum,
            content_type=content_type,
            acl=acl,
            created_at=old_meta.created_at if old_meta else now,
            updated_at=now,
        )
        self.meta.put_object_meta(obj)
        if old_object_id and old_object_id != object_id:
            self.storage.delete_object(effective_tenant_id, bucket_name, old_object_id)

        self._send_json(200, {
            "key": key,
            "object_id": object_id,
            "size": size,
            "sha256": checksum,
        })

    def _handle_upload_part(self, tenant: Tenant, bucket_name: str,
                            key: str, query: dict):
        upload_id = query["uploadId"][0]
        part_number = int(query.get("partNumber", [0])[0])
        if part_number < 1 or part_number > 10000:
            return self._send_error(400, "partNumber must be 1-10000")

        mp_meta = self.meta.get_multipart_meta(upload_id)
        if not mp_meta or mp_meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, "Multipart upload not found")

        content_length = int(self.headers.get("Content-Length", 0))

        existing_part = self.meta.get_part(upload_id, part_number)
        old_size = existing_part.size if existing_part else 0

        try:
            if old_size > 0:
                self.quota.replace_object(tenant.tenant_id, old_size, content_length)
            else:
                self.quota.check_and_reserve(tenant.tenant_id, content_length)
        except QuotaError as e:
            self._drain_body()
            return self._send_error(413, str(e))

        try:
            size, etag = self.storage.write_part_stream(
                tenant.tenant_id, bucket_name, upload_id, part_number,
                self.rfile, content_length
            )
        except Exception as e:
            self.quota.release(tenant.tenant_id, content_length)
            return self._send_error(500, f"Failed to write part: {e}")

        if size != content_length:
            self.quota.release(tenant.tenant_id, content_length - size)

        part = MultipartPart(
            upload_id=upload_id,
            part_number=part_number,
            tenant_id=tenant.tenant_id,
            bucket_name=bucket_name,
            object_key=key,
            size=size,
            etag=etag,
        )
        old_size_from_db = self.meta.add_part(part)
        self._send_json(200, {
            "upload_id": upload_id,
            "part_number": part_number,
            "size": size,
            "etag": etag,
        })

    # ── DELETE ──

    def do_DELETE(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            return self._send_error(401, str(e))

        try:
            bucket_name, key, query = self._parse_path()

            if not bucket_name:
                return self._send_error(400, "Bucket name required")

            if bucket_name == "_admin":
                return self._handle_admin_delete(tenant, key, query)

            if "grant" in query and not key:
                return self._handle_delete_bucket_grant(tenant, bucket_name)

            if "grant" in query and key:
                return self._handle_delete_object_grant(tenant, bucket_name, key)

            if "uploadId" in query or "abort" in query:
                upload_id = query.get("uploadId", query.get("abort", [""]))[0]
                if upload_id:
                    return self._handle_abort_multipart(tenant, bucket_name, key, upload_id)

            if key:
                return self._handle_delete_object(tenant, bucket_name, key)

            return self._handle_delete_bucket(tenant, bucket_name)
        except Exception as e:
            traceback.print_exc()
            self._send_error(500, f"Internal error: {e}")

    def _handle_admin_delete(self, tenant: Tenant, subpath: str, query: dict):
        if self.admin_tenant_id and tenant.tenant_id != self.admin_tenant_id:
            return self._send_error(403, "Admin access required")
        return self._send_error(400, "Use POST for admin maintenance")

    def _handle_delete_bucket_grant(self, tenant: Tenant, bucket_name: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if b.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Bucket '{bucket_name}' not found")
        grantee_id = self.headers.get("X-Grantee-Tenant-Id")
        permission = self.headers.get("X-Grant-Permission", "READ")
        if not grantee_id:
            return self._send_error(400, "X-Grantee-Tenant-Id header required")
        self.meta.remove_grant("bucket", bucket_name, tenant.tenant_id,
                               grantee_id, permission)
        self._send_json(200, {"deleted": True})

    def _handle_delete_object_grant(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Object '{key}' not found")
        grantee_id = self.headers.get("X-Grantee-Tenant-Id")
        permission = self.headers.get("X-Grant-Permission", "READ")
        if not grantee_id:
            return self._send_error(400, "X-Grantee-Tenant-Id header required")
        self.meta.remove_grant(
            "object", f"{bucket_name}/{key}", tenant.tenant_id,
            grantee_id, permission
        )
        self._send_json(200, {"deleted": True})

    def _handle_delete_bucket(self, tenant: Tenant, bucket_name: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if b.tenant_id != tenant.tenant_id:
            return self._send_error(404, f"Bucket '{bucket_name}' not found")
        deleted = self.meta.delete_bucket(tenant.tenant_id, bucket_name)
        if not deleted:
            return self._send_error(409, "Bucket is not empty")
        self.storage.delete_bucket_dir(tenant.tenant_id, bucket_name)
        self._send_json(204, {"deleted": bucket_name})

    def _handle_delete_object(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if not self._check_object_write(tenant, b, meta):
            return self._send_error(404, f"Object '{key}' not found")

        old_size = meta.size
        deleted = self.meta.delete_object_meta(b.tenant_id, bucket_name, key)
        if deleted:
            self.quota.release(b.tenant_id, old_size)
            self.storage.delete_object(b.tenant_id, bucket_name, meta.object_id)

        self._send_json(204, {"deleted": key})

    def _handle_abort_multipart(self, tenant: Tenant, bucket_name: str,
                                key: str, upload_id: str):
        mp_meta = self.meta.get_multipart_meta(upload_id)
        if not mp_meta or mp_meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, "Multipart upload not found")

        total_part_size, _, _ = self.meta.abort_multipart(
            tenant.tenant_id, mp_meta.bucket_name, mp_meta.object_key, upload_id
        )
        self.quota.release(tenant.tenant_id, total_part_size)
        self.storage.cleanup_parts(tenant.tenant_id, mp_meta.bucket_name, upload_id)
        self._send_json(204, {"aborted": upload_id})

    # ── POST ──

    def do_POST(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            return self._send_error(401, str(e))

        try:
            bucket_name, key, query = self._parse_path()

            if bucket_name == "_admin":
                return self._handle_admin_post(tenant, key, query)

            if not bucket_name:
                return self._send_error(400, "Bucket name required")

            if "uploads" in query and key:
                return self._handle_initiate_multipart(tenant, bucket_name, key)

            if "uploadId" in query and key:
                return self._handle_complete_multipart(tenant, bucket_name, key, query)

            return self._send_error(400, "Invalid POST request")
        except Exception as e:
            traceback.print_exc()
            self._send_error(500, f"Internal error: {e}")

    def _handle_admin_post(self, tenant: Tenant, subpath: str, query: dict):
        if self.admin_tenant_id and tenant.tenant_id != self.admin_tenant_id:
            return self._send_error(403, "Admin access required")

        parts = subpath.split("/", 1) if subpath else []
        action = parts[0] if parts else ""

        if action == "cleanup-multipart":
            expired = self.meta.list_expired_multipart_uploads()
            cleaned = []
            for mp in expired:
                size = self.meta.purge_multipart_upload(
                    mp.upload_id, mp.tenant_id,
                    mp.bucket_name, mp.object_key
                )
                if size > 0:
                    self.quota.release(mp.tenant_id, size)
                self.storage.cleanup_parts(mp.tenant_id, mp.bucket_name, mp.upload_id)
                cleaned.append({
                    "tenant_id": mp.tenant_id,
                    "bucket": mp.bucket_name,
                    "key": mp.object_key,
                    "upload_id": mp.upload_id,
                    "reclaimed_bytes": size,
                })
            return self._send_json(200, {
                "cleaned_count": len(cleaned),
                "cleaned": cleaned,
            })

        if action == "recalculate-quota":
            tenants = self.meta.list_all_tenants()
            results = []
            for t in tenants:
                usage = self.meta.calc_tenant_real_usage(t.tenant_id)
                self.meta.set_tenant_used_bytes(t.tenant_id, usage["total_bytes"])
                results.append({
                    "tenant_id": t.tenant_id,
                    "old_used": t.used_bytes,
                    "new_used": usage["total_bytes"],
                })
            return self._send_json(200, {"recalculated": results})

        if action == "tenant" and len(parts) >= 2:
            target_id = parts[1]
            t = self.meta.get_tenant(target_id)
            if not t:
                return self._send_error(404, f"Tenant {target_id} not found")
            usage = self.meta.calc_tenant_real_usage(target_id)
            self.meta.set_tenant_used_bytes(target_id, usage["total_bytes"])
            return self._send_json(200, {
                "tenant_id": target_id,
                "old_used": t.used_bytes,
                "new_used": usage["total_bytes"],
            })

        return self._send_error(400, "Unknown admin action")

    def _handle_initiate_multipart(self, tenant: Tenant,
                                   bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name, require_owner=False)
        if not b:
            return
        if not self._check_bucket_write(tenant, b):
            return self._send_error(404, f"Bucket '{bucket_name}' not found")

        upload_id = uuid.uuid4().hex
        object_id = uuid.uuid4().hex
        now = time.time()
        content_type = self.headers.get("Content-Type", "application/octet-stream")
        acl = self.headers.get("X-Object-ACL", "private")

        obj = ObjectMeta(
            tenant_id=b.tenant_id,
            bucket_name=bucket_name,
            object_key=key,
            object_id=object_id,
            size=0,
            checksum_sha256="",
            content_type=content_type,
            acl=acl,
            is_multipart=True,
            upload_id=upload_id,
            created_at=now,
            updated_at=now,
        )
        self.meta.create_multipart_upload(obj)
        self._send_json(200, {
            "upload_id": upload_id,
            "key": key,
            "object_id": object_id,
        })

    def _handle_complete_multipart(self, tenant: Tenant, bucket_name: str,
                                   key: str, query: dict):
        upload_id = query["uploadId"][0]
        mp_meta = self.meta.get_multipart_meta(upload_id)
        if not mp_meta or mp_meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, "Multipart upload not found")

        raw_body = self._read_body()
        client_parts = None
        if raw_body:
            try:
                body = json.loads(raw_body)
                if "parts" in body and isinstance(body["parts"], list):
                    client_parts = body["parts"]
            except Exception:
                return self._send_error(400, "Invalid JSON body")

        db_parts = self.meta.list_parts(upload_id)
        if not db_parts:
            return self._send_error(400, "No parts uploaded")

        parts_to_merge = db_parts
        if client_parts is not None:
            if not client_parts:
                return self._send_error(400, "Empty part list in request body")
            db_parts_map = {p.part_number: p for p in db_parts}
            parts_to_merge = []
            pn_list = []
            for cp in client_parts:
                pn = int(cp.get("part_number", 0))
                etag = cp.get("etag", "")
                if pn < 1:
                    return self._send_error(400, f"Invalid part_number: {pn}")
                if pn not in db_parts_map:
                    return self._send_error(400, f"Part {pn} not uploaded")
                dbp = db_parts_map[pn]
                if etag and etag != dbp.etag:
                    return self._send_error(400, f"ETag mismatch for part {pn}")
                parts_to_merge.append(dbp)
                pn_list.append(pn)
            if len(set(pn_list)) != len(pn_list):
                return self._send_error(400, "Duplicate part_number in list")
            for i in range(len(pn_list) - 1):
                if pn_list[i + 1] != pn_list[i] + 1:
                    return self._send_error(400, f"Part numbers not contiguous: {pn_list}")
        else:
            parts_to_merge.sort(key=lambda p: p.part_number)
            pn_list = [p.part_number for p in parts_to_merge]
            for i in range(len(pn_list) - 1):
                if pn_list[i + 1] != pn_list[i] + 1:
                    return self._send_error(400, f"Part numbers not contiguous: {pn_list}")

        part_numbers = [p.part_number for p in parts_to_merge]
        new_object_id = uuid.uuid4().hex

        old_meta = self.meta.get_object_meta(mp_meta.tenant_id, bucket_name, key)
        if old_meta and (not old_meta.is_multipart or old_meta.upload_id != upload_id):
            old_object_size = old_meta.size
            old_object_id = old_meta.object_id
            old_created_at = old_meta.created_at
            old_object_present = True
        else:
            old_object_size = 0
            old_object_id = None
            old_created_at = mp_meta.created_at
            old_object_present = False

        try:
            total_size, checksum = self.storage.merge_parts(
                mp_meta.tenant_id, bucket_name, upload_id, new_object_id,
                part_numbers
            )
        except Exception as e:
            if old_object_present:
                pass
            return self._send_error(500, f"Failed to merge parts: {e}")

        parts_total = sum(p.size for p in parts_to_merge)
        quota_delta = parts_total - old_object_size
        try:
            if quota_delta > 0:
                self.quota.check_and_reserve(mp_meta.tenant_id, quota_delta)
            elif quota_delta < 0:
                self.quota.release(mp_meta.tenant_id, -quota_delta)
        except QuotaError as e:
            self.storage.delete_object(mp_meta.tenant_id, bucket_name, new_object_id)
            return self._send_error(413, str(e))

        try:
            self.meta.complete_multipart(
                mp_meta.tenant_id, bucket_name, key, upload_id,
                total_size, checksum, new_object_id, old_object_size,
                acl=mp_meta.acl,
                content_type=mp_meta.content_type,
                created_at=old_created_at,
            )
        except Exception as e:
            self.storage.delete_object(mp_meta.tenant_id, bucket_name, new_object_id)
            if quota_delta > 0:
                self.quota.release(mp_meta.tenant_id, quota_delta)
            elif quota_delta < 0:
                self.quota.check_and_reserve(mp_meta.tenant_id, -quota_delta)
            return self._send_error(500, f"Metadata update failed: {e}")

        if old_object_id and old_object_id != new_object_id:
            self.storage.delete_object(mp_meta.tenant_id, bucket_name, old_object_id)

        self.storage.cleanup_parts(mp_meta.tenant_id, bucket_name, upload_id)

        self._send_json(200, {
            "key": key,
            "object_id": new_object_id,
            "size": total_size,
            "sha256": checksum,
            "parts": len(parts_to_merge),
            "part_numbers": part_numbers,
        })

    # ── HEAD ──

    def do_HEAD(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            self.send_response(401)
            self.end_headers()
            return

        try:
            bucket_name, key, query = self._parse_path()

            if not bucket_name or not key:
                self.send_response(400)
                self.end_headers()
                return

            b = self._require_bucket(tenant, bucket_name, require_owner=False)
            if not b:
                self.send_response(404)
                self.end_headers()
                return

            meta = self.meta.get_object_meta(b.tenant_id, bucket_name, key)
            if not meta:
                self.send_response(404)
                self.end_headers()
                return
            if meta.is_multipart and meta.upload_id:
                self.send_response(404)
                self.end_headers()
                return
            if not self._check_object_read(tenant, b, meta):
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", meta.content_type)
            self.send_header("Content-Length", str(meta.size))
            self.send_header("X-Object-Id", meta.object_id)
            self.send_header("X-Object-Sha256", meta.checksum_sha256)
            self.send_header("X-Object-ACL", meta.acl)
            self.send_header("X-Object-Is-Multipart", str(meta.is_multipart))
            self.send_header("X-Object-Created", str(meta.created_at))
            self.send_header("X-Object-Updated", str(meta.updated_at))
            self.end_headers()
        except Exception as e:
            traceback.print_exc()
            self.send_response(500)
            self.end_headers()
