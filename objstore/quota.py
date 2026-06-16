from .metadata import MetadataStore
from .models import Tenant


class QuotaError(Exception):
    pass


class QuotaManager:
    def __init__(self, meta: MetadataStore):
        self._meta = meta

    def check_and_reserve(self, tenant_id: str, size: int):
        if size <= 0:
            return
        ok = self._meta.add_used_bytes(tenant_id, size)
        if not ok:
            tenant = self._meta.get_tenant(tenant_id)
            if tenant:
                raise QuotaError(
                    f"Storage quota exceeded: used={tenant.used_bytes + size}, "
                    f"limit={tenant.quota_bytes}"
                )
            else:
                raise QuotaError(f"Tenant {tenant_id} not found")

    def release(self, tenant_id: str, size: int):
        if size <= 0:
            return
        self._meta.add_used_bytes(tenant_id, -size)

    def replace_object(self, tenant_id: str, old_size: int, new_size: int):
        if old_size == new_size:
            return
        if new_size > old_size:
            delta = new_size - old_size
            self.check_and_reserve(tenant_id, delta)
        else:
            delta = old_size - new_size
            self.release(tenant_id, delta)

    def get_usage(self, tenant_id: str) -> dict:
        tenant = self._meta.get_tenant(tenant_id)
        if not tenant:
            raise QuotaError(f"Tenant {tenant_id} not found")
        return {
            "tenant_id": tenant.tenant_id,
            "quota_bytes": tenant.quota_bytes,
            "used_bytes": tenant.used_bytes,
            "available_bytes": tenant.quota_bytes - tenant.used_bytes,
            "usage_percent": round(tenant.used_bytes / tenant.quota_bytes * 100, 2)
                if tenant.quota_bytes > 0 else 0,
        }
