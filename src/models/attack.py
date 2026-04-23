from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional


class AttackRun(BaseModel):
    id: str
    attack_type: str          # docker_socket | nsenter_escape | lateral_redis | runc_cve
    attack_label: str         # human-readable name
    status: str               # running | success | failed
    started_at: datetime
    finished_at: Optional[datetime] = None
    output: List[str] = []
    exit_code: Optional[int] = None
    duration_seconds: Optional[float] = None


class ContainerInfo(BaseModel):
    name: str
    ip: str
    status: str
    flags: List[str] = []
