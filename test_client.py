import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error


class ObjStoreClient:
    ALGORITHM = "OBJSTORE-HMAC-SHA256"

    def __init__(self, endpoint: str, access_key: str, secret_key: str):
        self._endpoint = endpoint.rstrip("/")
        self._access_key = access_key
        self._secret_key = secret_key

    def _sign(self, method: str, path: str, body: bytes = b""):
        date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        content_hash = hashlib.sha256(body).hexdigest()
        canonical = f"{method}\n{path}\n\n{date}\n{content_hash}"
        sig = hmac.new(
            self._secret_key.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {
            "Authorization": f"{self.ALGORITHM} {self._access_key}:{sig}",
            "X-ObjStore-Date": date,
            "X-ObjStore-Content-Sha256": content_hash,
        }

    def _request(self, method: str, path: str, data: bytes = None,
                 headers: dict = None):
        url = f"{self._endpoint}{path}"
        body = data if data else b""
        auth_headers = self._sign(method, path, body)
        req_headers = {}
        if headers:
            req_headers.update(headers)
        req_headers.update(auth_headers)
        if data is not None:
            req_headers["Content-Length"] = str(len(data))
        req = urllib.request.Request(url, data=body, headers=req_headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                resp_body = resp.read()
                try:
                    return resp.status, json.loads(resp_body)
                except Exception:
                    return resp.status, resp_body
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            try:
                return e.code, json.loads(resp_body)
            except Exception:
                return e.code, resp_body.decode("utf-8", errors="replace")

    def create_bucket(self, name: str):
        return self._request("PUT", f"/{name}?uploads")

    def list_buckets(self):
        return self._request("GET", "/")

    def delete_bucket(self, name: str):
        return self._request("DELETE", f"/{name}")

    def put_object(self, bucket: str, key: str, data: bytes,
                   content_type: str = "application/octet-stream"):
        headers = {
            "Content-Type": content_type,
        }
        return self._request("PUT", f"/{bucket}/{key}", data, headers)

    def get_object(self, bucket: str, key: str):
        return self._request("GET", f"/{bucket}/{key}")

    def head_object(self, bucket: str, key: str):
        url = f"{self._endpoint}/{bucket}/{key}"
        body = b""
        auth_headers = self._sign("HEAD", f"/{bucket}/{key}", body)
        req = urllib.request.Request(url, method="HEAD", headers=auth_headers)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)

    def delete_object(self, bucket: str, key: str):
        return self._request("DELETE", f"/{bucket}/{key}")

    def initiate_multipart(self, bucket: str, key: str):
        return self._request("POST", f"/{bucket}/{key}?uploads")

    def upload_part(self, bucket: str, key: str, upload_id: str,
                    part_number: int, data: bytes):
        path = f"/{bucket}/{key}?uploadId={upload_id}&partNumber={part_number}"
        return self._request("PUT", path, data)

    def complete_multipart(self, bucket: str, key: str, upload_id: str):
        path = f"/{bucket}/{key}?uploadId={upload_id}"
        return self._request("POST", path)

    def abort_multipart(self, bucket: str, key: str, upload_id: str):
        path = f"/{bucket}/{key}?uploadId={upload_id}"
        return self._request("DELETE", path)

    def list_parts(self, bucket: str, key: str, upload_id: str):
        path = f"/{bucket}/{key}?uploadId={upload_id}"
        return self._request("GET", path)

    def get_quota(self, bucket: str):
        return self._request("GET", f"/{bucket}?quota")


def run_tests(endpoint: str):
    print("=" * 60)
    print("Object Store Integration Tests")
    print("=" * 60)

    cred_path = os.path.join(os.path.dirname(__file__), "objstore_data",
                             "credentials.json")
    if not os.path.exists(cred_path):
        print(f"Credentials file not found at {cred_path}")
        print("Please start the server first.")
        sys.exit(1)

    with open(cred_path) as f:
        creds = json.load(f)

    tenant_a = creds["tenant-a"]
    tenant_b = creds["tenant-b"]

    client_a = ObjStoreClient(endpoint, tenant_a["access_key"],
                              tenant_a["secret_key"])
    client_b = ObjStoreClient(endpoint, tenant_b["access_key"],
                              tenant_b["secret_key"])

    passed = 0
    failed = 0

    def test(name: str, condition: bool, detail: str = ""):
        nonlocal passed, failed
        status = "PASS" if condition else "FAIL"
        if condition:
            passed += 1
        else:
            failed += 1
        msg = f"  [{status}] {name}"
        if detail:
            msg += f" - {detail}"
        print(msg)

    # ── 1. Bucket CRUD ──
    print("\n--- Bucket CRUD ---")

    code, body = client_a.create_bucket("test-bucket")
    test("Create bucket", code in (200, 201), f"code={code}")

    code, body = client_a.list_buckets()
    test("List buckets", code == 200, f"code={code}")
    bucket_names = [b["name"] for b in body.get("buckets", [])]
    test("Bucket in list", "test-bucket" in bucket_names)

    # ── 2. Tenant Isolation ──
    print("\n--- Tenant Isolation ---")

    code, body = client_b.list_buckets()
    test("Tenant B cannot see A's buckets",
         "test-bucket" not in [b["name"] for b in body.get("buckets", [])])

    code, body = client_a.put_object("test-bucket", "secret.txt",
                                     b"tenant-a data")
    test("Tenant A can write to own bucket", code == 200, f"code={code}")

    code, body = client_b.get_object("test-bucket", "secret.txt")
    test("Tenant B cannot read A's object", code in (403, 404),
         f"code={code}")

    code, body = client_b.put_object("test-bucket", "hack.txt",
                                     b"hack attempt")
    test("Tenant B cannot write to A's bucket", code in (403, 404),
         f"code={code}")

    # ── 3. Object CRUD ──
    print("\n--- Object CRUD ---")

    code, body = client_a.put_object("test-bucket", "hello.txt",
                                     b"Hello, World!")
    test("Put object", code == 200, f"code={code}")
    if code == 200:
        test("Object has sha256", len(body.get("sha256", "")) == 64)
        test("Object size correct", body.get("size") == 13)

    code, body = client_a.get_object("test-bucket", "hello.txt")
    test("Get object", code == 200, f"code={code}")
    if code == 200 and isinstance(body, bytes):
        test("Content matches", body == b"Hello, World!")

    code, headers = client_a.head_object("test-bucket", "hello.txt")
    test("Head object", code == 200, f"code={code}")

    # ── 4. Object Overwrite (metadata + data consistency) ──
    print("\n--- Object Overwrite ---")

    code, body = client_a.put_object("test-bucket", "hello.txt",
                                     b"Updated content!")
    test("Overwrite object", code == 200, f"code={code}")

    code, body = client_a.get_object("test-bucket", "hello.txt")
    test("Read after write consistency",
         code == 200 and isinstance(body, bytes) and body == b"Updated content!",
         f"code={code}")

    # ── 5. Multipart Upload ──
    print("\n--- Multipart Upload ---")

    code, body = client_a.initiate_multipart("test-bucket", "large.bin")
    test("Initiate multipart", code == 200, f"code={code}")
    upload_id = body.get("upload_id", "")

    part1_data = b"A" * (1024 * 100)
    part2_data = b"B" * (1024 * 200)
    part3_data = b"C" * (1024 * 50)

    code, body = client_a.upload_part("test-bucket", "large.bin",
                                      upload_id, 1, part1_data)
    test("Upload part 1", code == 200, f"code={code}")
    if code == 200:
        test("Part 1 has etag", len(body.get("etag", "")) == 32)

    code, body = client_a.upload_part("test-bucket", "large.bin",
                                      upload_id, 2, part2_data)
    test("Upload part 2", code == 200, f"code={code}")

    code, body = client_a.upload_part("test-bucket", "large.bin",
                                      upload_id, 3, part3_data)
    test("Upload part 3", code == 200, f"code={code}")

    code, body = client_a.complete_multipart("test-bucket", "large.bin",
                                             upload_id)
    test("Complete multipart", code == 200, f"code={code}")
    if code == 200:
        expected_size = len(part1_data) + len(part2_data) + len(part3_data)
        test("Merged size correct", body.get("size") == expected_size,
             f"got={body.get('size')}, expected={expected_size}")
        test("Merged has checksum", len(body.get("sha256", "")) == 64)

    code, body = client_a.get_object("test-bucket", "large.bin")
    test("Get merged object", code == 200, f"code={code}")
    if code == 200 and isinstance(body, bytes):
        expected = part1_data + part2_data + part3_data
        test("Merged content correct", body == expected)

    # ── 6. Multipart Abort ──
    print("\n--- Multipart Abort ---")

    code, body = client_a.initiate_multipart("test-bucket", "abort-test.bin")
    upload_id2 = body.get("upload_id", "")
    client_a.upload_part("test-bucket", "abort-test.bin", upload_id2, 1,
                         b"will be aborted")
    code, body = client_a.abort_multipart("test-bucket", "abort-test.bin",
                                          upload_id2)
    test("Abort multipart", code == 204, f"code={code}")

    # ── 7. Quota Enforcement ──
    print("\n--- Quota Enforcement ---")

    client_a.create_bucket("quota-bucket")
    chunk = 10 * 1024 * 1024

    code, body = client_a.put_object("quota-bucket", "big1.bin",
                                     b"X" * chunk)
    test("Upload within quota", code == 200, f"code={code}")

    code2, body2 = client_a.put_object("quota-bucket", "big2.bin",
                                       b"Y" * chunk)
    test("Second upload within quota", code2 == 200, f"code={code2}")

    code3, body3 = client_a.put_object("quota-bucket", "big3.bin",
                                       b"Z" * chunk)
    test("Third upload within quota", code3 == 200, f"code={code3}")

    code4, body4 = client_a.put_object("quota-bucket", "big4.bin",
                                       b"W" * chunk)
    test("Fourth upload within quota", code4 == 200, f"code={code4}")

    code5, body5 = client_a.put_object("quota-bucket", "big5.bin",
                                       b"V" * chunk)
    test("Fifth upload within quota", code5 == 200, f"code={code5}")

    code_over, body_over = client_a.put_object("quota-bucket", "over.bin",
                                               b"O" * (60 * 1024 * 1024))
    test("Over-quota upload rejected (100MB limit)",
         code_over == 413, f"code={code_over}")

    code, body = client_a.get_quota("quota-bucket")
    test("Get quota usage", code == 200, f"code={code}")
    if code == 200:
        print(f"    Quota: {body}")

    # ── 8. Delete objects and bucket ──
    print("\n--- Cleanup ---")

    code, body = client_a.delete_object("test-bucket", "hello.txt")
    test("Delete object", code == 204, f"code={code}")

    code, body = client_a.delete_object("test-bucket", "secret.txt")
    test("Delete second object", code == 204, f"code={code}")

    code, body = client_a.delete_object("test-bucket", "large.bin")
    test("Delete multipart object", code == 204, f"code={code}")

    code, body = client_a.get_object("test-bucket", "hello.txt")
    test("Deleted object is gone", code == 404, f"code={code}")

    code, body = client_a.delete_bucket("test-bucket")
    test("Delete empty bucket", code == 204, f"code={code}")

    # ── Summary ──
    print("\n" + "=" * 60)
    total = passed + failed
    print(f"Results: {passed}/{total} passed, {failed}/{total} failed")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9000"
    success = run_tests(endpoint)
    sys.exit(0 if success else 1)
