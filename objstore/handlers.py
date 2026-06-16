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
from .models import Tenant, Bucket, ObjectMeta, MultipartPart


class ObjStoreHandler(BaseHTTPRequestHandler):
    meta: MetadataStore = None
    storage: DataStore = None
    quota: QuotaManager = None

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

    def _require_bucket(self, tenant: Tenant, bucket_name: str) -> Bucket:
        b = self.meta.get_bucket(tenant.tenant_id, bucket_name)
        if not b:
            self._send_error(404, f"Bucket '{bucket_name}' not found")
            return None
        return b

    def _check_acl_read(self, tenant: Tenant, bucket_or_obj) -> bool:
        if bucket_or_obj.acl == "public-read":
            return True
        return bucket_or_obj.tenant_id == tenant.tenant_id

    def _check_acl_write(self, tenant: Tenant, bucket_or_obj) -> bool:
        return bucket_or_obj.tenant_id == tenant.tenant_id

    # ── GET ──

    def do_GET(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            return self._send_error(401, str(e))

        bucket_name, key, query = self._parse_path()

        if not bucket_name:
            return self._handle_list_buckets(tenant)

        if key == "":
            return self._handle_list_objects(tenant, bucket_name, query)

        if "uploadId" in query:
            return self._handle_list_parts(tenant, bucket_name, key, query)

        if "quota" in query:
            return self._handle_get_quota(tenant)

        return self._handle_get_object(tenant, bucket_name, key)

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

    def _handle_list_objects(self, tenant: Tenant, bucket_name: str, query: dict):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        prefix = query.get("prefix", [""])[0]
        objects = self.meta.list_objects(tenant.tenant_id, bucket_name, prefix)
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
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        meta = self.meta.get_object_meta(tenant.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if not self._check_acl_read(tenant, meta):
            return self._send_error(403, "Access denied")
        data = self.storage.read_object(tenant.tenant_id, bucket_name, meta.object_id)
        if data is None:
            return self._send_error(404, "Object data not found on disk")
        self._send_data(200, data, meta.content_type, meta)

    def _handle_get_quota(self, tenant: Tenant):
        try:
            usage = self.quota.get_usage(tenant.tenant_id)
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

    def _handle_put_object(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if not self._check_acl_write(tenant, b):
            return self._send_error(403, "Access denied")

        content_length = int(self.headers.get("Content-Length", 0))
        content_type = self.headers.get("Content-Type", "application/octet-stream")
        acl = self.headers.get("X-Object-ACL", "private")

        old_meta = self.meta.get_object_meta(tenant.tenant_id, bucket_name, key)

        try:
            if old_meta:
                self.quota.replace_object(tenant.tenant_id, old_meta.size, content_length)
            else:
                self.quota.check_and_reserve(tenant.tenant_id, content_length)
        except QuotaError as e:
            self._drain_body()
            return self._send_error(413, str(e))

        object_id = uuid.uuid4().hex
        try:
            size, checksum = self.storage.write_object_stream(
                tenant.tenant_id, bucket_name, object_id,
                self.rfile, content_length
            )
        except Exception as e:
            self.quota.release(tenant.tenant_id, content_length)
            if old_meta:
                self.quota.check_and_reserve(tenant.tenant_id, old_meta.size)
            return self._send_error(500, f"Failed to write object: {e}")

        if old_meta and size != content_length:
            self.quota.release(tenant.tenant_id, content_length - old_meta.size)

        now = time.time()
        obj = ObjectMeta(
            tenant_id=tenant.tenant_id,
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

        try:
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

        part = MultipartPart(
            upload_id=upload_id,
            part_number=part_number,
            tenant_id=tenant.tenant_id,
            bucket_name=bucket_name,
            object_key=key,
            size=size,
            etag=etag,
        )
        self.meta.add_part(part)
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

            if key:
                return self._handle_delete_object(tenant, bucket_name, key)

            if "uploadId" in query or "abort" in query:
                upload_id = query.get("uploadId", query.get("abort", [""]))[0]
                if upload_id:
                    return self._handle_abort_multipart(tenant, bucket_name, "", upload_id)

            return self._handle_delete_bucket(tenant, bucket_name)
        except Exception as e:
            traceback.print_exc()
            self._send_error(500, f"Internal error: {e}")

    def _handle_delete_bucket(self, tenant: Tenant, bucket_name: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if not self._check_acl_write(tenant, b):
            return self._send_error(403, "Access denied")
        deleted = self.meta.delete_bucket(tenant.tenant_id, bucket_name)
        if not deleted:
            return self._send_error(409, "Bucket is not empty")
        self.storage.delete_bucket_dir(tenant.tenant_id, bucket_name)
        self._send_json(204, {"deleted": bucket_name})

    def _handle_delete_object(self, tenant: Tenant, bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        meta = self.meta.get_object_meta(tenant.tenant_id, bucket_name, key)
        if not meta:
            return self._send_error(404, f"Object '{key}' not found")
        if not self._check_acl_write(tenant, meta):
            return self._send_error(403, "Access denied")

        old_size = meta.size
        deleted = self.meta.delete_object_meta(tenant.tenant_id, bucket_name, key)
        if deleted:
            self.quota.release(tenant.tenant_id, old_size)
            self.storage.delete_object(tenant.tenant_id, bucket_name, meta.object_id)

        self._send_json(204, {"deleted": key})

    def _handle_abort_multipart(self, tenant: Tenant, bucket_name: str,
                                key: str, upload_id: str):
        mp_meta = self.meta.get_multipart_meta(upload_id)
        if not mp_meta or mp_meta.tenant_id != tenant.tenant_id:
            return self._send_error(404, "Multipart upload not found")
        total_part_size = self.meta.abort_multipart(
            tenant.tenant_id, bucket_name, mp_meta.object_key, upload_id
        )
        self.quota.release(tenant.tenant_id, total_part_size)
        self.storage.cleanup_parts(tenant.tenant_id, bucket_name, upload_id)
        self._send_json(204, {"aborted": upload_id})

    # ── POST (multipart: initiate / complete) ──

    def do_POST(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            return self._send_error(401, str(e))

        try:
            bucket_name, key, query = self._parse_path()

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

    def _handle_initiate_multipart(self, tenant: Tenant,
                                   bucket_name: str, key: str):
        b = self._require_bucket(tenant, bucket_name)
        if not b:
            return
        if not self._check_acl_write(tenant, b):
            return self._send_error(403, "Access denied")

        upload_id = uuid.uuid4().hex
        object_id = uuid.uuid4().hex
        now = time.time()
        content_type = self.headers.get("Content-Type", "application/octet-stream")
        acl = self.headers.get("X-Object-ACL", "private")

        obj = ObjectMeta(
            tenant_id=tenant.tenant_id,
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

        parts = self.meta.list_parts(upload_id)
        if not parts:
            return self._send_error(400, "No parts uploaded")

        part_numbers = sorted([p.part_number for p in parts])
        object_id = mp_meta.object_id

        try:
            total_size, checksum = self.storage.merge_parts(
                tenant.tenant_id, bucket_name, upload_id, object_id, part_numbers
            )
        except Exception as e:
            return self._send_error(500, f"Failed to merge parts: {e}")

        self.meta.complete_multipart(
            tenant.tenant_id, bucket_name, key, upload_id,
            total_size, checksum, object_id
        )

        self._send_json(200, {
            "key": key,
            "object_id": object_id,
            "size": total_size,
            "sha256": checksum,
            "parts": len(parts),
        })

    # ── HEAD ──

    def do_HEAD(self):
        try:
            tenant = self._get_tenant()
        except AuthError as e:
            self.send_response(401)
            self.end_headers()
            return

        bucket_name, key, query = self._parse_path()

        if not bucket_name or not key:
            self.send_response(400)
            self.end_headers()
            return

        meta = self.meta.get_object_meta(tenant.tenant_id, bucket_name, key)
        if not meta:
            self.send_response(404)
            self.end_headers()
            return
        if not self._check_acl_read(tenant, meta):
            self.send_response(403)
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
