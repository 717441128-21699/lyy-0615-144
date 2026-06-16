import sqlite3
import threading
import time
from typing import Optional, List
from .models import Tenant, Bucket, ObjectMeta, MultipartPart


class MetadataStore:
    def __init__(self, db_path: str):
        self._local = threading.local()
        self._db_path = db_path
        self._init_lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(self._db_path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (
                tenant_id   TEXT PRIMARY KEY,
                access_key  TEXT UNIQUE NOT NULL,
                secret_key  TEXT NOT NULL,
                quota_bytes INTEGER NOT NULL DEFAULT 0,
                used_bytes  INTEGER NOT NULL DEFAULT 0,
                created_at  REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS buckets (
                tenant_id    TEXT NOT NULL,
                bucket_name  TEXT NOT NULL,
                acl          TEXT NOT NULL DEFAULT 'private',
                created_at   REAL NOT NULL,
                PRIMARY KEY (tenant_id, bucket_name),
                FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
            );

            CREATE TABLE IF NOT EXISTS objects (
                tenant_id      TEXT NOT NULL,
                bucket_name    TEXT NOT NULL,
                object_key     TEXT NOT NULL,
                object_id      TEXT NOT NULL,
                size           INTEGER NOT NULL DEFAULT 0,
                checksum_sha256 TEXT NOT NULL DEFAULT '',
                content_type   TEXT NOT NULL DEFAULT 'application/octet-stream',
                acl            TEXT NOT NULL DEFAULT 'private',
                is_multipart   INTEGER NOT NULL DEFAULT 0,
                upload_id      TEXT,
                created_at     REAL NOT NULL,
                updated_at     REAL NOT NULL,
                PRIMARY KEY (tenant_id, bucket_name, object_key),
                FOREIGN KEY (tenant_id, bucket_name) REFERENCES buckets(tenant_id, bucket_name)
            );

            CREATE TABLE IF NOT EXISTS multipart_parts (
                upload_id   TEXT NOT NULL,
                part_number INTEGER NOT NULL,
                tenant_id   TEXT NOT NULL,
                bucket_name TEXT NOT NULL,
                object_key  TEXT NOT NULL,
                size        INTEGER NOT NULL DEFAULT 0,
                etag        TEXT NOT NULL DEFAULT '',
                created_at  REAL NOT NULL,
                PRIMARY KEY (upload_id, part_number)
            );

            CREATE INDEX IF NOT EXISTS idx_objects_upload
                ON objects(upload_id) WHERE upload_id IS NOT NULL;
        """)
        conn.commit()

    def close(self):
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ── Tenant operations ──

    def create_tenant(self, tenant: Tenant) -> Tenant:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO tenants (tenant_id, access_key, secret_key, quota_bytes, used_bytes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (tenant.tenant_id, tenant.access_key, tenant.secret_key,
             tenant.quota_bytes, tenant.used_bytes, tenant.created_at)
        )
        conn.commit()
        return tenant

    def get_tenant_by_access_key(self, access_key: str) -> Optional[Tenant]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM tenants WHERE access_key = ?", (access_key,)
        ).fetchone()
        if not row:
            return None
        return Tenant(**dict(row))

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if not row:
            return None
        return Tenant(**dict(row))

    def update_tenant_quota(self, tenant_id: str, quota_bytes: int):
        conn = self._get_conn()
        conn.execute(
            "UPDATE tenants SET quota_bytes = ? WHERE tenant_id = ?",
            (quota_bytes, tenant_id)
        )
        conn.commit()

    def add_used_bytes(self, tenant_id: str, delta: int) -> bool:
        conn = self._get_conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT quota_bytes, used_bytes FROM tenants WHERE tenant_id = ?",
                (tenant_id,)
            ).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                return False
            new_used = row["used_bytes"] + delta
            if delta > 0 and new_used > row["quota_bytes"]:
                conn.execute("ROLLBACK")
                return False
            conn.execute(
                "UPDATE tenants SET used_bytes = ? WHERE tenant_id = ?",
                (new_used, tenant_id)
            )
            conn.execute("COMMIT")
            return True
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # ── Bucket operations ──

    def create_bucket(self, bucket: Bucket) -> Bucket:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO buckets (tenant_id, bucket_name, acl, created_at) VALUES (?, ?, ?, ?)",
            (bucket.tenant_id, bucket.bucket_name, bucket.acl, bucket.created_at)
        )
        conn.commit()
        return bucket

    def get_bucket(self, tenant_id: str, bucket_name: str) -> Optional[Bucket]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM buckets WHERE tenant_id = ? AND bucket_name = ?",
            (tenant_id, bucket_name)
        ).fetchone()
        if not row:
            return None
        return Bucket(**dict(row))

    def list_buckets(self, tenant_id: str) -> List[Bucket]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM buckets WHERE tenant_id = ? ORDER BY bucket_name",
            (tenant_id,)
        ).fetchall()
        return [Bucket(**dict(r)) for r in rows]

    def delete_bucket(self, tenant_id: str, bucket_name: str) -> bool:
        conn = self._get_conn()
        obj_count = conn.execute(
            "SELECT COUNT(*) FROM objects WHERE tenant_id = ? AND bucket_name = ?",
            (tenant_id, bucket_name)
        ).fetchone()[0]
        if obj_count > 0:
            return False
        conn.execute(
            "DELETE FROM buckets WHERE tenant_id = ? AND bucket_name = ?",
            (tenant_id, bucket_name)
        )
        conn.commit()
        return True

    # ── Object operations ──

    def put_object_meta(self, obj: ObjectMeta) -> ObjectMeta:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO objects (tenant_id, bucket_name, object_key, object_id, size, "
            "checksum_sha256, content_type, acl, is_multipart, upload_id, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(tenant_id, bucket_name, object_key) DO UPDATE SET "
            "object_id=excluded.object_id, size=excluded.size, "
            "checksum_sha256=excluded.checksum_sha256, content_type=excluded.content_type, "
            "acl=excluded.acl, is_multipart=excluded.is_multipart, "
            "upload_id=excluded.upload_id, updated_at=excluded.updated_at",
            (obj.tenant_id, obj.bucket_name, obj.object_key, obj.object_id,
             obj.size, obj.checksum_sha256, obj.content_type, obj.acl,
             int(obj.is_multipart), obj.upload_id, obj.created_at, obj.updated_at)
        )
        conn.commit()
        return obj

    def get_object_meta(self, tenant_id: str, bucket_name: str, object_key: str) -> Optional[ObjectMeta]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM objects WHERE tenant_id = ? AND bucket_name = ? AND object_key = ?",
            (tenant_id, bucket_name, object_key)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["is_multipart"] = bool(d["is_multipart"])
        return ObjectMeta(**d)

    def list_objects(self, tenant_id: str, bucket_name: str, prefix: str = "") -> List[ObjectMeta]:
        conn = self._get_conn()
        if prefix:
            rows = conn.execute(
                "SELECT * FROM objects WHERE tenant_id = ? AND bucket_name = ? "
                "AND object_key LIKE ? ORDER BY object_key",
                (tenant_id, bucket_name, prefix + "%")
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM objects WHERE tenant_id = ? AND bucket_name = ? ORDER BY object_key",
                (tenant_id, bucket_name)
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["is_multipart"] = bool(d["is_multipart"])
            result.append(ObjectMeta(**d))
        return result

    def delete_object_meta(self, tenant_id: str, bucket_name: str, object_key: str) -> bool:
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM objects WHERE tenant_id = ? AND bucket_name = ? AND object_key = ?",
            (tenant_id, bucket_name, object_key)
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_object_size(self, tenant_id: str, bucket_name: str, object_key: str) -> Optional[int]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT size FROM objects WHERE tenant_id = ? AND bucket_name = ? AND object_key = ?",
            (tenant_id, bucket_name, object_key)
        ).fetchone()
        return row["size"] if row else None

    # ── Multipart upload operations ──

    def create_multipart_upload(self, obj: ObjectMeta) -> ObjectMeta:
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO objects (tenant_id, bucket_name, object_key, object_id, size, "
            "checksum_sha256, content_type, acl, is_multipart, upload_id, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (obj.tenant_id, obj.bucket_name, obj.object_key, obj.object_id,
             0, "", obj.content_type, obj.acl, 1, obj.upload_id,
             obj.created_at, obj.updated_at)
        )
        conn.commit()
        return obj

    def add_part(self, part: MultipartPart):
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO multipart_parts "
            "(upload_id, part_number, tenant_id, bucket_name, object_key, size, etag, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (part.upload_id, part.part_number, part.tenant_id,
             part.bucket_name, part.object_key, part.size, part.etag, part.created_at)
        )
        conn.commit()

    def list_parts(self, upload_id: str) -> List[MultipartPart]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM multipart_parts WHERE upload_id = ? ORDER BY part_number",
            (upload_id,)
        ).fetchall()
        return [MultipartPart(**dict(r)) for r in rows]

    def complete_multipart(self, tenant_id: str, bucket_name: str,
                           object_key: str, upload_id: str,
                           total_size: int, checksum: str, object_id: str):
        conn = self._get_conn()
        now = time.time()
        conn.execute(
            "UPDATE objects SET size = ?, checksum_sha256 = ?, object_id = ?, "
            "upload_id = NULL, updated_at = ? "
            "WHERE tenant_id = ? AND bucket_name = ? AND object_key = ? AND upload_id = ?",
            (total_size, checksum, object_id, now,
             tenant_id, bucket_name, object_key, upload_id)
        )
        conn.execute(
            "DELETE FROM multipart_parts WHERE upload_id = ?", (upload_id,)
        )
        conn.commit()

    def abort_multipart(self, tenant_id: str, bucket_name: str,
                        object_key: str, upload_id: str) -> int:
        conn = self._get_conn()
        parts = conn.execute(
            "SELECT size FROM multipart_parts WHERE upload_id = ?", (upload_id,)
        ).fetchall()
        total_part_size = sum(r["size"] for r in parts)
        conn.execute(
            "DELETE FROM multipart_parts WHERE upload_id = ?", (upload_id,)
        )
        conn.execute(
            "DELETE FROM objects WHERE tenant_id = ? AND bucket_name = ? "
            "AND object_key = ? AND upload_id = ?",
            (tenant_id, bucket_name, object_key, upload_id)
        )
        conn.commit()
        return total_part_size

    def get_multipart_meta(self, upload_id: str) -> Optional[ObjectMeta]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM objects WHERE upload_id = ?", (upload_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["is_multipart"] = bool(d["is_multipart"])
        return ObjectMeta(**d)
