"""
Base Gateway Adapter
=====================
All gateway adapters implement this interface.
The pull() method returns a list of GatewayEvent dicts which the
risk engine converts to RiskSignal records.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class GatewayEvent:
    """
    Normalised event from any email gateway.
    Maps to a RiskSignal signal_type automatically.
    """
    email:       str
    event_type:  str       # phish | malware | bec | real_click | real_report | spam
    gateway:     str       # microsoft365 | google_workspace | proofpoint | mimecast | syslog
    occurred_at: datetime
    raw:         dict = field(default_factory=dict)   # original payload for audit
    subject:     Optional[str] = None
    sender:      Optional[str] = None
    url:         Optional[str] = None
    threat_name: Optional[str] = None

    def to_signal_type(self) -> Optional[str]:
        mapping = {
            "phish":       "gateway_phish_volume",
            "malware":     "gateway_malware",
            "bec":         "gateway_bec",
            "real_click":  "gateway_real_click",
            "real_report": "gateway_real_report",
        }
        return mapping.get(self.event_type)


class BaseGatewayAdapter(ABC):
    """
    Abstract base for all email gateway adapters.
    Implementations must override pull() to return GatewayEvent list.
    """

    name: str = "base"

    def __init__(self, config):
        """config is a models.GatewayConfig ORM instance."""
        self.config = config

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """
        Verify credentials and connectivity.
        Returns (success: bool, message: str).
        """
        ...

    @abstractmethod
    def pull(self, since: Optional[datetime] = None) -> list[GatewayEvent]:
        """
        Fetch email security events since the given datetime.
        If since is None, fetch the last 24 hours.
        Returns a list of GatewayEvent objects.
        """
        ...
