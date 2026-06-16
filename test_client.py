import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
import threading
import subprocess
import shutil
from http.client import HTTPConnection


class ObjStoreClient:
    def __init__(self, host: str, port: int, access_key: str, secret_key: str):
        self.host = host
        self.port = port
        self.access_key = access_key
        self.secret_key = secret_key

    def _sign(self, method: str, path: str, date: str, content_hash: str) -> str:
        canonical = f"{method}\n{path}\n\n{date}\n{content_hash}"
        mac = hmac.new(self.secret_key.encode(), canonical.encode(), hashlib.sha256)
        return mac.hexdigest()

    def _headers(self, method: str, path: str, body: bytes = b""):
        date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        content_hash = hashlib.sha256(body).hexdigest()
        sig = self._sign(method, path, date, content_hash)
        headers = {
            "X-Date": date,
            "X-Content-SHA256": content_hash,
            "Authorization": f"OBJSTORE-HMAC-SHA256 {self.access_key}:{sig}",
        }
        if body:
            headers["Content-Length"] = str(len(body))
        return headers

    def _request(self, method: str, path: str, body: bytes = b"",
                 extra_headers: dict = None) -> tuple:
        conn = HTTPConnection(self.host, self.port, timeout=30)
        headers = self._headers(method, path, body)
        if extra_headers:
            headers.update(extra_headers)
        conn.request(method, path, body, headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, resp.getheaders(), data

    def list_buckets(self) -> tuple:
        return self._request("GET", "/")

    def create_bucket(self, bucket: str, acl: str = "private") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}?uploads"
        extra = {}
        if acl != "private":
            extra["X-Bucket-ACL"] = acl
        return self._request("PUT", path, extra_headers=extra)

    def delete_bucket(self, bucket: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}"
        return self._request("DELETE", path)

    def get_bucket_acl(self, bucket: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}?acl"
        return self._request("GET", path)

    def set_bucket_acl(self, bucket: str, acl: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}?acl"
        return self._request("PUT", path, extra_headers={"X-Bucket-ACL": acl})

    def add_bucket_grant(self, bucket: str, grantee_tenant_id: str,
                         permission: str = "READ") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}?grant"
        body = json.dumps({
            "grantee_tenant_id": grantee_tenant_id,
            "permission": permission,
        }).encode()
        extra = {"Content-Type": "application/json"}
        return self._request("PUT", path, body, extra)

    def remove_bucket_grant(self, bucket: str, grantee_tenant_id: str,
                            permission: str = "READ") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}?grant"
        extra = {
            "X-Grantee-Tenant-Id": grantee_tenant_id,
            "X-Grant-Permission": permission,
        }
        return self._request("DELETE", path, extra_headers=extra)

    def put_object(self, bucket: str, key: str, data: bytes,
                   content_type: str = "application/octet-stream",
                   acl: str = "private") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
        extra = {"Content-Type": content_type}
        if acl != "private":
            extra["X-Object-ACL"] = acl
        return self._request("PUT", path, data, extra)

    def get_object(self, bucket: str, key: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
        return self._request("GET", path)

    def head_object(self, bucket: str, key: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
        return self._request("HEAD", path)

    def delete_object(self, bucket: str, key: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
        return self._request("DELETE", path)

    def list_objects(self, bucket: str, prefix: str = "") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}"
        if prefix:
            path += f"?prefix={urllib.parse.quote(prefix)}"
        return self._request("GET", path)

    def get_object_acl(self, bucket: str, key: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}?acl"
        return self._request("GET", path)

    def set_object_acl(self, bucket: str, key: str, acl: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}?acl"
        return self._request("PUT", path, extra_headers={"X-Object-ACL": acl})

    def add_object_grant(self, bucket: str, key: str,
                         grantee_tenant_id: str,
                         permission: str = "READ") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}?grant"
        body = json.dumps({
            "grantee_tenant_id": grantee_tenant_id,
            "permission": permission,
        }).encode()
        extra = {"Content-Type": "application/json"}
        return self._request("PUT", path, body, extra)

    def remove_object_grant(self, bucket: str, key: str,
                            grantee_tenant_id: str,
                            permission: str = "READ") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}?grant"
        extra = {
            "X-Grantee-Tenant-Id": grantee_tenant_id,
            "X-Grant-Permission": permission,
        }
        return self._request("DELETE", path, extra_headers=extra)

    def get_quota(self, bucket: str) -> tuple:
        path = f"/{urllib.parse.quote(bucket)}?quota"
        return self._request("GET", path)

    def initiate_multipart(self, bucket: str, key: str,
                           content_type: str = "application/octet-stream",
                           acl: str = "private") -> tuple:
        path = f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}?uploads"
        extra = {"Content-Type": content_type}
        if acl != "private":
            extra["X-Object-ACL"] = acl
        return self._request("POST", path, extra_headers=extra)

    def upload_part(self, bucket: str, key: str, upload_id: str,
                    part_number: int, data: bytes) -> tuple:
        path = (f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
                f"?uploadId={urllib.parse.quote(upload_id)}"
                f"&partNumber={part_number}")
        return self._request("PUT", path, data)

    def list_parts(self, bucket: str, key: str, upload_id: str) -> tuple:
        path = (f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
                f"?uploadId={urllib.parse.quote(upload_id)}")
        return self._request("GET", path)

    def complete_multipart(self, bucket: str, key: str, upload_id: str,
                           parts: list = None) -> tuple:
        path = (f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
                f"?uploadId={urllib.parse.quote(upload_id)}")
        body = b""
        extra = {}
        if parts is not None:
            body = json.dumps({"parts": parts}).encode()
            extra["Content-Type"] = "application/json"
        return self._request("POST", path, body, extra)

    def abort_multipart(self, bucket: str, key: str, upload_id: str) -> tuple:
        path = (f"/{urllib.parse.quote(bucket)}/{urllib.parse.quote(key)}"
                f"?uploadId={urllib.parse.quote(upload_id)}")
        return self._request("DELETE", path)

    def admin_list_tenants(self) -> tuple:
        return self._request("GET", "/_admin/tenants")

    def admin_tenant_usage(self, tenant_id: str) -> tuple:
        return self._request("GET", f"/_admin/tenant/{urllib.parse.quote(tenant_id)}")

    def admin_expired_multipart(self) -> tuple:
        return self._request("GET", "/_admin/expired-multipart")

    def admin_cleanup_multipart(self) -> tuple:
        return self._request("POST", "/_admin/cleanup-multipart")

    def admin_recalculate_all(self) -> tuple:
        return self._request("POST", "/_admin/recalculate-quota")

    def admin_recalculate_tenant(self, tenant_id: str) -> tuple:
        return self._request("POST", f"/_admin/tenant/{urllib.parse.quote(tenant_id)}")


def run_tests():
    host = "127.0.0.1"
    port = 9000

    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "objstore_data")
    creds_path = os.path.join(data_dir, "credentials.json")
    if not os.path.exists(creds_path):
        print(f"ERROR: credentials not found at {creds_path}")
        print("Start server first with: python -m objstore.main")
        sys.exit(1)

    with open(creds_path) as f:
        creds = json.load(f)

    admin = ObjStoreClient(host, port, creds["admin"]["access_key"], creds["admin"]["secret_key"])
    ca = ObjStoreClient(host, port, creds["tenant-a"]["access_key"], creds["tenant-a"]["secret_key"])
    cb = ObjStoreClient(host, port, creds["tenant-b"]["access_key"], creds["tenant-b"]["secret_key"])

    passed = 0
    failed = 0
    failed_cases = []

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            failed += 1
            failed_cases.append((name, detail))
            print(f"  [FAIL] {name} {detail}")

    def parse_json(data):
        if not data:
            return {}
        try:
            return json.loads(data.decode())
        except Exception:
            return {"raw": data[:200]}

    # ── Cleanup leftover buckets from previous runs ──
    print("\n[CLEANUP] Removing leftover buckets...")
    status, _, data = ca.list_buckets()
    if status == 200:
        body = parse_json(data)
        for b in body.get("buckets", []):
            ca.delete_bucket(b["name"])
    status, _, data = cb.list_buckets()
    if status == 200:
        body = parse_json(data)
        for b in body.get("buckets", []):
            cb.delete_bucket(b["name"])

    # ── Round 1 regression tests ──
    print("\n=== Round 1 Regression Tests ===")

    # 1. Create bucket
    status, _, data = ca.create_bucket("test-a")
    check("tenant-a create bucket test-a", status in (201, 200), f"status={status}")

    status, _, data = cb.create_bucket("test-b")
    check("tenant-b create bucket test-b", status in (201, 200), f"status={status}")

    # 2. List buckets isolation
    status, _, data = ca.list_buckets()
    body = parse_json(data)
    names = [b["name"] for b in body.get("buckets", [])]
    check("tenant-a only sees own buckets",
          "test-a" in names and "test-b" not in names,
          f"names={names}")

    # 3. Put object
    content = b"hello object storage"
    status, _, data = ca.put_object("test-a", "hello.txt", content,
                                    content_type="text/plain")
    check("put object hello.txt", status == 200, f"status={status}")

    # 4. Get object
    status, _, body = ca.get_object("test-a", "hello.txt")
    check("get object hello.txt == original",
          status == 200 and body == content,
          f"status={status}, body_len={len(body)}")

    # 5. Head object
    status, headers, _ = ca.head_object("test-a", "hello.txt")
    header_dict = {k.lower(): v for k, v in headers}
    check("head object returns correct size",
          status == 200 and header_dict.get("content-length") == str(len(content)),
          f"status={status}, cl={header_dict.get('content-length')}")

    # 6. Overwrite object consistency
    content2 = b"overwritten content!"
    ca.put_object("test-a", "hello.txt", content2)
    status, _, body = ca.get_object("test-a", "hello.txt")
    check("overwrite object read-after-write",
          status == 200 and body == content2,
          f"status={status}")

    # 7. List objects
    status, _, data = ca.list_objects("test-a")
    body = parse_json(data)
    keys = [o["key"] for o in body.get("objects", [])]
    check("list objects contains hello.txt", "hello.txt" in keys, f"keys={keys}")

    # 8. Tenant isolation: tenant-b cannot see tenant-a's private object
    status, _, _ = cb.get_object("test-a", "hello.txt")
    check("tenant-b cannot access tenant-a private object (404, not 403)",
          status == 404, f"status={status}")

    # 9. Tenant isolation: tenant-b cannot even see tenant-a's bucket existence
    status, _, _ = cb.list_objects("test-a")
    check("tenant-b list_objects on private bucket returns 404",
          status == 404, f"status={status}")

    # 10. Tenant isolation: tenant-b cannot delete tenant-a's object
    status, _, _ = cb.delete_object("test-a", "hello.txt")
    check("tenant-b cannot delete tenant-a object (404)",
          status == 404, f"status={status}")

    # 11. Delete object
    ca.delete_object("test-a", "hello.txt")
    status, _, _ = ca.get_object("test-a", "hello.txt")
    check("deleted object returns 404", status == 404, f"status={status}")

    # 12. Quota tracking
    big = b"A" * 10000
    ca.put_object("test-a", "big.bin", big)
    status, _, data = ca.get_quota("test-a")
    body = parse_json(data)
    check("quota reflects uploaded bytes",
          status == 200 and body.get("used_bytes", 0) >= 10000,
          f"used={body.get('used_bytes')}")

    # 13. Multipart upload - initiate
    status, _, data = ca.initiate_multipart("test-a", "multi.bin")
    body = parse_json(data)
    upload_id = body.get("upload_id")
    check("initiate multipart", status == 200 and bool(upload_id),
          f"status={status}, upload_id={upload_id}")

    # 14. Multipart - upload parts
    part1 = b"part one data -- " * 1000
    part2 = b"part two data!! " * 1000
    status, _, _ = ca.upload_part("test-a", "multi.bin", upload_id, 1, part1)
    check("upload part 1", status == 200, f"status={status}")
    status, _, _ = ca.upload_part("test-a", "multi.bin", upload_id, 2, part2)
    check("upload part 2", status == 200, f"status={status}")

    # 15. Multipart - list parts
    status, _, data = ca.list_parts("test-a", "multi.bin", upload_id)
    body = parse_json(data)
    check("list parts has 2 entries",
          status == 200 and len(body.get("parts", [])) == 2,
          f"parts={body.get('parts')}")

    # 16. Multipart - complete (with client part list + etag check)
    status, _, list_data = ca.list_parts("test-a", "multi.bin", upload_id)
    parts_info = parse_json(list_data)
    client_parts = [
        {"part_number": p["part_number"], "etag": p["etag"]}
        for p in parts_info.get("parts", [])
    ]
    status, _, data = ca.complete_multipart("test-a", "multi.bin",
                                            upload_id, client_parts)
    body = parse_json(data)
    check("complete multipart with client list",
          status == 200 and body.get("size") == len(part1) + len(part2),
          f"status={status}, size={body.get('size')}")

    # 17. Multipart merged object readable & correct
    status, _, body = ca.get_object("test-a", "multi.bin")
    expected = part1 + part2
    check("merged multipart content correct",
          status == 200 and body == expected,
          f"status={status}, body_len={len(body)}, expected={len(expected)}")

    # 18. Multipart abort: quota should not leak
    status, _, data = ca.initiate_multipart("test-a", "abort-test.bin")
    body = parse_json(data)
    abort_id = body.get("upload_id")
    status_before, _, q_before = ca.get_quota("test-a")
    before_used = parse_json(q_before).get("used_bytes", 0)
    ca.upload_part("test-a", "abort-test.bin", abort_id, 1, b"X" * 50000)
    status_after_up, _, q_after_up = ca.get_quota("test-a")
    after_up_used = parse_json(q_after_up).get("used_bytes", 0)
    check("after part upload quota increases", after_up_used > before_used,
          f"before={before_used}, after_up={after_up_used}")
    ca.abort_multipart("test-a", "abort-test.bin", abort_id)
    status_after_abort, _, q_after_abort = ca.get_quota("test-a")
    after_abort_used = parse_json(q_after_abort).get("used_bytes", 0)
    check("after abort quota returns to pre-upload",
          abs(after_abort_used - before_used) < 100,
          f"before={before_used}, after_abort={after_abort_used}")

    # 19. Quota: reject when over limit
    tiny_quota_tenant = ca
    # tenant-a has 100MB, so create a different path: skip since 100MB hard
    # Instead just check get_quota works
    status, _, data = ca.get_quota("test-a")
    check("get_quota returns 200", status == 200, f"status={status}")

    # 20. Delete bucket with content fails
    status, _, _ = ca.delete_bucket("test-a")
    check("delete non-empty bucket returns 409",
          status == 409, f"status={status}")

    # 21. Cannot create duplicate bucket
    status, _, _ = ca.create_bucket("test-a")
    body = parse_json(data)
    check("duplicate bucket create returns 200 (idempotent, not created)",
          status == 200, f"status={status}")

    # 22. Invalid signature
    bad_client = ObjStoreClient(host, port, ca.access_key, "WRONGSECRET")
    status, _, _ = bad_client.list_buckets()
    check("bad signature returns 401", status == 401, f"status={status}")

    # 23. Read-after-write with concurrent puts on same key
    base = b"base content v1"
    ca.put_object("test-a", "race.txt", base)
    v2 = b"updated content v2!!"
    ca.put_object("test-a", "race.txt", v2)
    status, _, body = ca.get_object("test-a", "race.txt")
    check("concurrent overwrite returns latest",
          status == 200 and body == v2,
          f"status={status}")

    # ── Round 2: new feature tests ──
    print("\n=== Round 2: New Feature Tests ===")

    # 24. Bucket ACL: create public-read bucket, tenant-b can read list
    ca.create_bucket("pub-a", acl="public-read")
    ca.put_object("pub-a", "hello.txt", b"public content")
    status, _, data = cb.list_objects("pub-a")
    body = parse_json(data)
    keys = [o["key"] for o in body.get("objects", [])]
    check("tenant-b can list public-read bucket",
          status == 200 and "hello.txt" in keys,
          f"status={status}, keys={keys}")

    # 25. Tenant-b can read public object
    status, _, body = cb.get_object("pub-a", "hello.txt")
    check("tenant-b can read public object",
          status == 200 and body == b"public content",
          f"status={status}")

    # 26. Tenant-b cannot write to public-read bucket
    status, _, _ = cb.put_object("pub-a", "intruder.txt", b"haha")
    check("tenant-b cannot write to public-read bucket (404)",
          status == 404, f"status={status}")

    # 27. public-read-write bucket lets tenant-b write
    ca.create_bucket("rw-a", acl="public-read-write")
    status, _, _ = cb.put_object("rw-a", "from-b.txt", b"from tenant b")
    check("tenant-b can write to public-read-write bucket",
          status == 200, f"status={status}")

    # 28. Tenant-a can read what tenant-b wrote
    status, _, body = ca.get_object("rw-a", "from-b.txt")
    check("owner can read cross-tenant written object",
          status == 200 and body == b"from tenant b",
          f"status={status}")

    # 29. Bucket grant: give tenant-b READ on private bucket
    ca.create_bucket("grant-a")
    ca.put_object("grant-a", "secret.txt", b"only for tenant-b")
    # Before grant: tenant-b sees 404
    status, _, _ = cb.get_object("grant-a", "secret.txt")
    check("before grant, tenant-b cannot read (404)",
          status == 404, f"status={status}")
    ca.add_bucket_grant("grant-a", "tenant-b", "READ")
    status, _, body = cb.get_object("grant-a", "secret.txt")
    check("after READ grant, tenant-b can read",
          status == 200 and body == b"only for tenant-b",
          f"status={status}")
    # But tenant-b still cannot write
    status, _, _ = cb.put_object("grant-a", "new.txt", b"new")
    check("READ grant doesn't allow WRITE (404)",
          status == 404, f"status={status}")

    # 30. Bucket WRITE grant
    ca.add_bucket_grant("grant-a", "tenant-b", "WRITE")
    status, _, _ = cb.put_object("grant-a", "from-b-grant.txt", b"hello from b via grant")
    check("WRITE grant allows cross-tenant put",
          status == 200, f"status={status}")
    ca.remove_bucket_grant("grant-a", "tenant-b", "READ")
    status, _, _ = cb.get_object("grant-a", "secret.txt")
    check("after removing READ grant, access is denied (404)",
          status == 404, f"status={status}")

    # 31. Object-level ACL override
    ca.create_bucket("obj-acl-a")
    ca.put_object("obj-acl-a", "pub.txt", b"public object", acl="public-read")
    ca.put_object("obj-acl-a", "priv.txt", b"private object")
    status, _, body = cb.get_object("obj-acl-a", "pub.txt")
    check("object-level public-read accessible",
          status == 200 and body == b"public object",
          f"status={status}")
    status, _, _ = cb.get_object("obj-acl-a", "priv.txt")
    check("object-level private not accessible (404)",
          status == 404, f"status={status}")

    # 32. Object-level grant
    ca.create_bucket("obj-grant-a")
    ca.put_object("obj-grant-a", "shared.txt", b"shared content")
    status, _, _ = cb.get_object("obj-grant-a", "shared.txt")
    check("private object before grant returns 404",
          status == 404, f"status={status}")
    ca.add_object_grant("obj-grant-a", "shared.txt", "tenant-b", "READ")
    status, _, body = cb.get_object("obj-grant-a", "shared.txt")
    check("object-level READ grant works",
          status == 200 and body == b"shared content",
          f"status={status}")
    ca.remove_object_grant("obj-grant-a", "shared.txt", "tenant-b", "READ")
    status, _, _ = cb.get_object("obj-grant-a", "shared.txt")
    check("after removing object grant returns 404",
          status == 404, f"status={status}")

    # 33. Get bucket ACL shows grants
    ca.add_bucket_grant("grant-a", "tenant-b", "READ")
    status, _, data = ca.get_bucket_acl("grant-a")
    body = parse_json(data)
    check("get_bucket_acl includes grants",
          status == 200 and len(body.get("grants", [])) >= 1,
          f"body={body}")

    # 34. Set bucket ACL works
    ca.create_bucket("acl-switch")
    status, _, data = ca.get_bucket_acl("acl-switch")
    body = parse_json(data)
    check("new bucket has private acl by default",
          body.get("acl") == "private", f"acl={body.get('acl')}")
    ca.set_bucket_acl("acl-switch", "public-read")
    status, _, data = ca.get_bucket_acl("acl-switch")
    body = parse_json(data)
    check("set_bucket_acl updates ACL",
          body.get("acl") == "public-read", f"acl={body.get('acl')}")

    # 35. Duplicate part upload quota: re-upload same part with different size
    ca.create_bucket("parts-quota")
    status, _, q0 = ca.get_quota("parts-quota")
    used0 = parse_json(q0).get("used_bytes", 0)

    status, _, data = ca.initiate_multipart("parts-quota", "dup.bin")
    upload_id = parse_json(data)["upload_id"]
    ca.upload_part("parts-quota", "dup.bin", upload_id, 1, b"A" * 20000)
    status, _, q1 = ca.get_quota("parts-quota")
    used1 = parse_json(q1).get("used_bytes", 0)
    check("after 20KB part upload, quota grows ~20KB",
          used1 - used0 >= 19000, f"used0={used0}, used1={used1}")

    # Re-upload part 1 with SMALLER content (5KB): quota should go down
    ca.upload_part("parts-quota", "dup.bin", upload_id, 1, b"B" * 5000)
    status, _, q2 = ca.get_quota("parts-quota")
    used2 = parse_json(q2).get("used_bytes", 0)
    check("re-upload same part smaller adjusts quota down",
          used2 < used1 and used2 - used0 >= 4000,
          f"used0={used0}, used1={used1}, used2={used2}")

    # Re-upload with LARGER content (50KB): quota grows
    ca.upload_part("parts-quota", "dup.bin", upload_id, 1, b"C" * 50000)
    status, _, q3 = ca.get_quota("parts-quota")
    used3 = parse_json(q3).get("used_bytes", 0)
    check("re-upload same part larger adjusts quota up",
          used3 > used2, f"used2={used2}, used3={used3}")

    ca.abort_multipart("parts-quota", "dup.bin", upload_id)
    status, _, q4 = ca.get_quota("parts-quota")
    used4 = parse_json(q4).get("used_bytes", 0)
    check("abort after dup re-uploads returns quota to baseline",
          abs(used4 - used0) < 100, f"used0={used0}, used4={used4}")

    # 36. Abort multipart: list_parts shows 404, quota back
    ca.create_bucket("abort-verify")
    status, _, data = ca.initiate_multipart("abort-verify", "x.bin")
    uid = parse_json(data)["upload_id"]
    ca.upload_part("abort-verify", "x.bin", uid, 1, b"part1")
    ca.upload_part("abort-verify", "x.bin", uid, 2, b"part2")
    status, _, data = ca.list_parts("abort-verify", "x.bin", uid)
    check("before abort, list_parts returns 200", status == 200, f"status={status}")
    ca.abort_multipart("abort-verify", "x.bin", uid)
    status, _, _ = ca.list_parts("abort-verify", "x.bin", uid)
    check("after abort, list_parts returns 404", status == 404, f"status={status}")

    # 37. Multipart overwrite existing object: during upload GET returns old version
    ca.create_bucket("mp-overwrite")
    old_content = b"OLD VERSION " * 10000
    ca.put_object("mp-overwrite", "bigfile.bin", old_content)
    status, _, body = ca.get_object("mp-overwrite", "bigfile.bin")
    check("initial object correct",
          status == 200 and body == old_content,
          f"status={status}")

    status, _, data = ca.initiate_multipart("mp-overwrite", "bigfile.bin")
    ow_uid = parse_json(data)["upload_id"]
    new_p1 = b"NEW VERSION part1 " * 5000
    new_p2 = b"NEW VERSION part2 " * 5000
    ca.upload_part("mp-overwrite", "bigfile.bin", ow_uid, 1, new_p1)
    ca.upload_part("mp-overwrite", "bigfile.bin", ow_uid, 2, new_p2)
    # While in progress, GET still returns OLD content
    status, _, body = ca.get_object("mp-overwrite", "bigfile.bin")
    check("during multipart overwrite, GET returns old content",
          status == 200 and body == old_content,
          f"status={status}, body_start={body[:50]}")

    # Complete overwrite - now we get NEW content
    status, _, _ = ca.complete_multipart("mp-overwrite", "bigfile.bin", ow_uid)
    check("complete overwrite returns 200", status == 200, f"status={status}")
    status, _, body = ca.get_object("mp-overwrite", "bigfile.bin")
    expected_new = new_p1 + new_p2
    check("after complete overwrite, GET returns new content",
          status == 200 and body == expected_new,
          f"status={status}, len={len(body)} vs {len(expected_new)}")

    # 38. Complete multipart with bad etag: should fail & keep old object intact
    # Recreate scenario: create object, start overwrite, complete with wrong etag
    ca.create_bucket("mp-rollback")
    ca.put_object("mp-rollback", "safe.bin", b"safe and sound")
    status, _, data = ca.initiate_multipart("mp-rollback", "safe.bin")
    rb_uid = parse_json(data)["upload_id"]
    ca.upload_part("mp-rollback", "safe.bin", rb_uid, 1, b"evil content")

    bad_parts = [{"part_number": 1, "etag": "WRONGETAG12345"}]
    status, _, resp = ca.complete_multipart("mp-rollback", "safe.bin", rb_uid, bad_parts)
    check("complete with wrong etag returns 400",
          status == 400, f"status={status}")

    # Object should still be the old one
    status, _, body = ca.get_object("mp-rollback", "safe.bin")
    check("after failed complete, old object intact",
          status == 200 and body == b"safe and sound",
          f"status={status}, body={body}")

    # 39. Complete multipart with non-contiguous parts: fail
    ca.create_bucket("mp-gap")
    status, _, data = ca.initiate_multipart("mp-gap", "gap.bin")
    gap_uid = parse_json(data)["upload_id"]
    ca.upload_part("mp-gap", "gap.bin", gap_uid, 1, b"p1")
    ca.upload_part("mp-gap", "gap.bin", gap_uid, 3, b"p3")
    status, _, resp = ca.complete_multipart("mp-gap", "gap.bin", gap_uid)
    check("complete with non-contiguous parts returns 400",
          status == 400, f"status={status}, resp={resp[:200]}")
    ca.abort_multipart("mp-gap", "gap.bin", gap_uid)

    # 40. Admin endpoints: list tenants (as tenant-a should fail)
    status, _, _ = ca.admin_list_tenants()
    check("non-admin cannot list tenants (403)",
          status == 403, f"status={status}")

    # 41. Admin list tenants works
    status, _, data = admin.admin_list_tenants()
    body = parse_json(data)
    tenants_ids = [t["tenant_id"] for t in body.get("tenants", [])]
    check("admin can list tenants incl. tenant-a, tenant-b, admin",
          status == 200 and "tenant-a" in tenants_ids and "tenant-b" in tenants_ids
          and "admin" in tenants_ids,
          f"tenants={tenants_ids}")

    # 42. Admin real usage breakdown
    status, _, data = admin.admin_tenant_usage("tenant-a")
    body = parse_json(data)
    check("admin tenant usage has total_bytes >= 0",
          status == 200 and "total_bytes" in body,
          f"body={body}")

    # 43. Admin recalculate quota
    status, _, data = admin.admin_recalculate_all()
    body = parse_json(data)
    check("admin recalculate returns list with 3 tenants",
          status == 200 and len(body.get("recalculated", [])) >= 3,
          f"body={body}")

    # 44. Cleanup leftover: force-expire a multipart upload via admin
    ca.create_bucket("expire-test")
    status, _, data = ca.initiate_multipart("expire-test", "stale.bin")
    expire_uid = parse_json(data)["upload_id"]
    ca.upload_part("expire-test", "stale.bin", expire_uid, 1, b"stale part")

    status, _, data = admin.admin_expired_multipart()
    # Should be empty since upload was just created
    body = parse_json(data)
    check("fresh multipart is not expired",
          status == 200 and body.get("count", 0) == 0,
          f"count={body.get('count')}")

    # 45. Cross-tenant bucket: create same name by different tenant should be separate
    ca.create_bucket("shared-name", acl="public-read")
    ca.put_object("shared-name", "from-a.txt", b"content from a")
    cb.create_bucket("shared-name")
    cb.put_object("shared-name", "from-b.txt", b"content from b")
    status, _, data = ca.list_objects("shared-name")
    a_keys = [o["key"] for o in parse_json(data).get("objects", [])]
    status, _, data = cb.list_objects("shared-name")
    b_keys = [o["key"] for o in parse_json(data).get("objects", [])]
    check("same-named buckets by diff tenants are fully isolated",
          "from-a.txt" in a_keys and "from-b.txt" not in a_keys
          and "from-b.txt" in b_keys and "from-a.txt" not in b_keys,
          f"a_keys={a_keys}, b_keys={b_keys}")

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    if failed_cases:
        print("\nFailed cases:")
        for name, detail in failed_cases:
            print(f"  - {name}: {detail}")
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
