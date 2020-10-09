from typing import Sequence, ByteString
import datetime
from dataclasses import dataclass


@dataclass
class Event:
    at: datetime.datetime = datetime.datetime
    name: str = str
    data: ByteString = None


@dataclass
class Notification:
    trigger_name: str
    entity_id: str
    events: Sequence[Event] = list
