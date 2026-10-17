"""Build the shared ``ConfigurationHistory`` from a collector config snapshot.

A snapshot is a point-in-time description (``run_collect.py snapshot``). It tells us which
security groups an ENI has AT SNAPSHOT TIME, not when they were attached, unless the ENI
carries an ``Attachment.AttachTime``. Missing or malformed sections yield fewer entries,
never an exception.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Union

from src.shared.models import ConfigurationHistory, SecurityGroupAttachment


def _dt(value: Any, default: datetime) -> datetime:
    if not value:
        return default
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return default
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def build_configuration_history(snapshot: Mapping[str, Any]) -> ConfigurationHistory:
    taken_at = _dt(snapshot.get("taken_at"), datetime.fromtimestamp(0, tz=timezone.utc))
    attachments, eni_ips = [], {}  # type: list, Dict[str, list]
    seen = set()
    for inst in snapshot.get("instances") or []:
        for eni in (inst or {}).get("NetworkInterfaces") or []:
            eni_id = eni.get("NetworkInterfaceId")
            if not eni_id:
                continue
            attached_at = _dt((eni.get("Attachment") or {}).get("AttachTime"), taken_at)
            for grp in eni.get("Groups") or []:
                sg = grp.get("GroupId")
                if sg and (eni_id, sg) not in seen:
                    seen.add((eni_id, sg))
                    attachments.append(SecurityGroupAttachment(
                        resource_id=eni_id, security_group_id=sg, attached_at=attached_at))
            ips = []
            for addr in eni.get("PrivateIpAddresses") or []:
                ips.append(addr.get("PrivateIpAddress"))
                ips.append((addr.get("Association") or {}).get("PublicIp"))
            ips += [eni.get("PrivateIpAddress"), (eni.get("Association") or {}).get("PublicIp")]
            eni_ips[eni_id] = sorted({ip for ip in ips if ip})
    return ConfigurationHistory(attachments=attachments, eni_to_ip_map=eni_ips)


def load_configuration_history(path: Union[str, Path]) -> ConfigurationHistory:
    return build_configuration_history(json.loads(Path(path).read_text(encoding="utf-8")))
