import os
import hmac
import ipaddress
import logging
from hashlib import sha256
from dataclasses import dataclass
from typing import Any
from mail_controller.domain.permission.permission import Permission, PermissionAction
from mail_controller.validation.require import Require

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Identity:
    id: str
    hmac_hex: str
    allowed_cidrs: list[str]
    permissions: list[Permission]


    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Identity":
        def get_required(name: str) -> Any:
            val = data.get(name)
            Require.present(name, val)
            return val

        identity_id = get_required("id")
        allowed_cidrs = get_required("allowed_cidrs")
        raw_permissions = get_required("permissions")

        Require.type("id", identity_id, str)
        Require.match("id", identity_id, r'^[A-Za-z_0-9]+$')

        hmac_env = f"TOKEN_{str(identity_id).upper()}_HMAC"
        hmac_hex = Require.env(hmac_env)
        Require.min_len(hmac_env, os.getenv(hmac_env), 64)

        Require.type("allowed_cidrs", allowed_cidrs, list)
        for i, ip_addr in enumerate(allowed_cidrs):
            Require.ip_address(f"allowed_cidrs[{i}]", ip_addr)

        Require.type("permissions", raw_permissions, list)
        permissions = [Permission.from_string(i, perm) for i, perm in enumerate(raw_permissions)]

        return cls(identity_id, hmac_hex, allowed_cidrs, permissions)


    def is_token_valid(self, hmac_key: bytes, token: str) -> bool:
        token_hmac_hex = hmac.new(hmac_key, token.encode("UTF-8"), sha256).hexdigest()
        return hmac.compare_digest(token_hmac_hex, self.hmac_hex)


    def is_ip_allowed(self, ip_addr: str | None = None) -> bool:
        log.debug(f"Perform ip address check (ip_addr='{ip_addr}', identity='{self}')")
        
        if not ip_addr:
            return False
        
        try:
            ip_obj = ipaddress.ip_address(ip_addr)
        except ValueError: # Invalid ip_addr format
            return False
        
        for cidr in self.allowed_cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            if ip_obj in network:
                return True
            
        return False


    def allows(self, domain: str, action: PermissionAction) -> bool:
        return any(p.allows(domain, action) for p in self.permissions)


    def __str__(self) -> str:
        return self.id
