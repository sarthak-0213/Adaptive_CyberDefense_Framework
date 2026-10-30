from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class AlertCreate(BaseModel):
    title: str
    violation_type: str
    severity: str = "medium"
    status: str = "active"
    description: Optional[str] = None
    evidence_path: Optional[str] = None


class AlertUpdateStatus(BaseModel):
    status: str  # active, investigating, resolved


class AlertResponse(BaseModel):
    id: int
    title: str
    timestamp: str
    rawTimestamp: float
    severity: str
    status: str
    description: Optional[str] = None
    evidence_path: Optional[str] = None

    model_config = {
        "from_attributes": True
    }

    @classmethod
    def model_validate(cls, obj, **kwargs):
        raw_ts = 0.0
        timestamp_str = "N/A"
        if isinstance(obj.timestamp, datetime):
            raw_ts = obj.timestamp.timestamp()
            timestamp_str = obj.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        elif obj.timestamp:
            timestamp_str = str(obj.timestamp)

        return cls(
            id=obj.id,
            title=obj.title,
            timestamp=timestamp_str,
            rawTimestamp=raw_ts,
            severity=obj.severity,
            status=obj.status,
            description=obj.description,
            evidence_path=obj.evidence_path
        )
