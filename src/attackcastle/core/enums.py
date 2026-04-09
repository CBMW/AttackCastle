from enum import Enum


class TargetType(str, Enum):
    SINGLE_IP = "single_ip"
    CIDR = "cidr"
    IP_RANGE = "ip_range"
    ASN = "asn"
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    URL = "url"
    HOST_PORT = "host_port"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"


class RunState(str, Enum):
    CREATED = "created"
    PLANNED = "planned"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
