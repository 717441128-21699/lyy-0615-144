import argparse
import json
import os
import secrets
import sys
import threading
from http.server import HTTPServer
from socketserver import ThreadingMixIn

from .metadata import MetadataStore
from .storage import DataStore
from .quota import QuotaManager
from .handlers import ObjStoreHandler
from .models import Tenant


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_tenant(meta: MetadataStore, tenant_id: str,
                  quota_bytes: int) -> Tenant:
    existing = meta.get_tenant(tenant_id)
    if existing:
        print(f"  Tenant '{tenant_id}' already exists, access_key={existing.access_key}")
        return existing
    access_key = f"AK{secrets.token_hex(12)}"
    secret_key = secrets.token_hex(24)
    tenant = Tenant(
        tenant_id=tenant_id,
        access_key=access_key,
        secret_key=secret_key,
        quota_bytes=quota_bytes,
    )
    meta.create_tenant(tenant)
    print(f"  Tenant '{tenant_id}' created:")
    print(f"    access_key = {access_key}")
    print(f"    secret_key = {secret_key}")
    print(f"    quota      = {quota_bytes} bytes")
    return tenant


def main():
    parser = argparse.ArgumentParser(description="Multi-tenant Object Storage Service")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=9000, help="Listen port")
    parser.add_argument("--data-dir", default="./objstore_data",
                        help="Directory for object data")
    parser.add_argument("--db-path", default="./objstore_meta.db",
                        help="SQLite database path")
    args = parser.parse_args()

    os.makedirs(args.data_dir, exist_ok=True)

    meta = MetadataStore(args.db_path)
    storage = DataStore(args.data_dir)
    quota_mgr = QuotaManager(meta)

    ObjStoreHandler.meta = meta
    ObjStoreHandler.storage = storage
    ObjStoreHandler.quota = quota_mgr

    tenant1 = create_tenant(meta, "tenant-a", quota_bytes=100 * 1024 * 1024)
    tenant2 = create_tenant(meta, "tenant-b", quota_bytes=200 * 1024 * 1024)

    server = ThreadedHTTPServer((args.host, args.port), ObjStoreHandler)
    print(f"\n  Object Store server listening on {args.host}:{args.port}")
    print(f"  Data directory: {os.path.abspath(args.data_dir)}")
    print(f"  Metadata DB:    {os.path.abspath(args.db_path)}")
    print("\n  API Endpoints:")
    print("    PUT  /<bucket>?uploads          - Create bucket")
    print("    GET  /                          - List buckets")
    print("    DEL  /<bucket>                  - Delete bucket")
    print("    PUT  /<bucket>/<key>            - Put object")
    print("    GET  /<bucket>/<key>            - Get object")
    print("    HEAD /<bucket>/<key>            - Head object")
    print("    DEL  /<bucket>/<key>            - Delete object")
    print("    POST /<bucket>/<key>?uploads    - Initiate multipart upload")
    print("    PUT  /<bucket>/<key>?uploadId=X&partNumber=N - Upload part")
    print("    POST /<bucket>/<key>?uploadId=X - Complete multipart upload")
    print("    DEL  /<bucket>/<key>?uploadId=X - Abort multipart upload")
    print("    GET  /<bucket>?quota            - Get quota usage")
    print()

    credentials = {
        tenant1.tenant_id: {
            "access_key": tenant1.access_key,
            "secret_key": tenant1.secret_key,
        },
        tenant2.tenant_id: {
            "access_key": tenant2.access_key,
            "secret_key": tenant2.secret_key,
        },
    }
    cred_path = os.path.join(args.data_dir, "credentials.json")
    with open(cred_path, "w") as f:
        json.dump(credentials, f, indent=2)
    print(f"  Credentials saved to {os.path.abspath(cred_path)}\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()
        meta.close()


if __name__ == "__main__":
    main()
