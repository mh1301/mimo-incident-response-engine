"""Data classes and pattern helpers."""
from dataclasses import dataclass, asdict
from typing import Optional, List
from datetime import datetime


@dataclass
class TelemetryEvent:
    event_type: str
    source_ip: str
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    process: Optional[str] = None
    path: Optional[str] = None
    data: Optional[str] = None
    timestamp: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class Incident:
    id: int
    rule_id: str
    name: str
    severity: str
    category: str
    status: str
    description: str
    source_ips: str
    event_count: int
    created_at: str
    updated_at: str

    def to_dict(self):
        return asdict(self)


@dataclass
class IOC:
    ips: List[str]
    domains: List[str]
    processes: List[str]
    files: List[str]
    users: List[str]
