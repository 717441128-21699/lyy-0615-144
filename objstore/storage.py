import hashlib
import os
import shutil
import tempfile
from typing import Optional, BinaryIO, Tuple
from .models import ObjectMeta


class DataStore:
    def __init__(self, data_dir: str):
        self._data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

    def _object_path(self, tenant_id: str, bucket_name: str, object_id: str) -> str:
        d = os.path.join(self._data_dir, tenant_id, bucket_name)
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, object_id)

    def _part_path(self, tenant_id: str, bucket_name: str,
                   upload_id: str, part_number: int) -> str:
        d = os.path.join(self._data_dir, tenant_id, bucket_name, "_uploads", upload_id)
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, f"{part_number:05d}")

    def _temp_path(self, tenant_id: str, bucket_name: str, object_id: str) -> str:
        d = os.path.join(self._data_dir, tenant_id, bucket_name, "_tmp")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, object_id + ".tmp")

    def write_object(self, tenant_id: str, bucket_name: str,
                     object_id: str, data: bytes) -> Tuple[int, str]:
        final_path = self._object_path(tenant_id, bucket_name, object_id)
        tmp_path = self._temp_path(tenant_id, bucket_name, object_id)
        sha256 = hashlib.sha256()
        with open(tmp_path, "wb") as f:
            sha256.update(data)
            f.write(data)
        os.replace(tmp_path, final_path)
        return len(data), sha256.hexdigest()

    def write_object_stream(self, tenant_id: str, bucket_name: str,
                            object_id: str, stream: BinaryIO,
                            content_length: int) -> Tuple[int, str]:
        final_path = self._object_path(tenant_id, bucket_name, object_id)
        tmp_path = self._temp_path(tenant_id, bucket_name, object_id)
        sha256 = hashlib.sha256()
        written = 0
        with open(tmp_path, "wb") as f:
            while written < content_length:
                chunk = stream.read(min(65536, content_length - written))
                if not chunk:
                    break
                sha256.update(chunk)
                f.write(chunk)
                written += len(chunk)
        os.replace(tmp_path, final_path)
        return written, sha256.hexdigest()

    def read_object(self, tenant_id: str, bucket_name: str,
                    object_id: str) -> Optional[bytes]:
        path = self._object_path(tenant_id, bucket_name, object_id)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def open_object(self, tenant_id: str, bucket_name: str,
                    object_id: str) -> Optional[Tuple[BinaryIO, int]]:
        path = self._object_path(tenant_id, bucket_name, object_id)
        if not os.path.exists(path):
            return None
        size = os.path.getsize(path)
        f = open(path, "rb")
        return f, size

    def delete_object(self, tenant_id: str, bucket_name: str, object_id: str) -> bool:
        path = self._object_path(tenant_id, bucket_name, object_id)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False

    def write_part(self, tenant_id: str, bucket_name: str,
                   upload_id: str, part_number: int,
                   data: bytes) -> Tuple[int, str]:
        path = self._part_path(tenant_id, bucket_name, upload_id, part_number)
        tmp_path = path + ".tmp"
        md5 = hashlib.md5()
        md5.update(data)
        with open(tmp_path, "wb") as f:
            f.write(data)
        os.replace(tmp_path, path)
        return len(data), md5.hexdigest()

    def write_part_stream(self, tenant_id: str, bucket_name: str,
                          upload_id: str, part_number: int,
                          stream: BinaryIO,
                          content_length: int) -> Tuple[int, str]:
        path = self._part_path(tenant_id, bucket_name, upload_id, part_number)
        tmp_path = path + ".tmp"
        md5 = hashlib.md5()
        written = 0
        with open(tmp_path, "wb") as f:
            while written < content_length:
                chunk = stream.read(min(65536, content_length - written))
                if not chunk:
                    break
                md5.update(chunk)
                f.write(chunk)
                written += len(chunk)
        os.replace(tmp_path, path)
        return written, md5.hexdigest()

    def merge_parts(self, tenant_id: str, bucket_name: str,
                    upload_id: str, object_id: str,
                    part_numbers: list) -> Tuple[int, str]:
        final_path = self._object_path(tenant_id, bucket_name, object_id)
        tmp_path = self._temp_path(tenant_id, bucket_name, object_id)
        upload_dir = os.path.join(self._data_dir, tenant_id, bucket_name,
                                  "_uploads", upload_id)
        sha256 = hashlib.sha256()
        total_size = 0
        with open(tmp_path, "wb") as out:
            for pn in part_numbers:
                part_file = os.path.join(upload_dir, f"{pn:05d}")
                with open(part_file, "rb") as pf:
                    while True:
                        chunk = pf.read(65536)
                        if not chunk:
                            break
                        sha256.update(chunk)
                        out.write(chunk)
                        total_size += len(chunk)
        os.replace(tmp_path, final_path)
        shutil.rmtree(upload_dir, ignore_errors=True)
        return total_size, sha256.hexdigest()

    def cleanup_parts(self, tenant_id: str, bucket_name: str, upload_id: str):
        upload_dir = os.path.join(self._data_dir, tenant_id, bucket_name,
                                  "_uploads", upload_id)
        shutil.rmtree(upload_dir, ignore_errors=True)

    def delete_bucket_dir(self, tenant_id: str, bucket_name: str):
        bucket_dir = os.path.join(self._data_dir, tenant_id, bucket_name)
        if os.path.exists(bucket_dir):
            shutil.rmtree(bucket_dir)
