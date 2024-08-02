"""
Custom binary protocol for distributed log ingestion.

Protocol format:
  [Magic: 4 bytes] [Version: 1 byte] [Flags: 1 byte] [Length: 4 bytes] [Payload: variable]

  Payload (JSON):
    {
      "timestamp": ISO8601 string,
      "source": hostname or IP,
      "log_level": "INFO", "WARN", "ERROR", "CRITICAL",
      "service": service name,
      "message": log message,
      "fields": { "key": "value", ... }  # optional structured data
    }
"""

import json
import struct
import io
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional

MAGIC = b'SIEM'
VERSION = 1
FLAG_COMPRESSED = 0x01


@dataclass
class LogEvent:
    """Represents a single log event."""
    timestamp: datetime
    source: str
    log_level: str
    service: str
    message: str
    fields: Dict[str, Any] = None

    def __post_init__(self):
        if self.fields is None:
            self.fields = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'log_level': self.log_level,
            'service': self.service,
            'message': self.message,
            'fields': self.fields,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEvent':
        if isinstance(data['timestamp'], str):
            timestamp = datetime.fromisoformat(data['timestamp'])
        else:
            timestamp = data['timestamp']

        return cls(
            timestamp=timestamp,
            source=data['source'],
            log_level=data['log_level'],
            service=data['service'],
            message=data['message'],
            fields=data.get('fields', {}),
        )


class ProtocolEncoder:
    """Encodes LogEvent to binary protocol format."""

    @staticmethod
    def encode(event: LogEvent, flags: int = 0) -> bytes:
        """Encode a LogEvent to binary format."""
        payload = json.dumps(event.to_dict()).encode('utf-8')
        length = len(payload)

        header = struct.pack(
            '>4sBBL',
            MAGIC,
            VERSION,
            flags,
            length
        )
        return header + payload

    @staticmethod
    def encode_batch(events: list[LogEvent]) -> bytes:
        """Encode multiple events (one per frame)."""
        return b''.join(ProtocolEncoder.encode(event) for event in events)


class ProtocolDecoder:
    """Decodes binary protocol format to LogEvent."""

    MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB max payload

    @staticmethod
    def decode(data: bytes) -> tuple[LogEvent, int]:
        """
        Decode a single frame from binary data.
        Returns (LogEvent, bytes_consumed).
        Raises ValueError for invalid data.
        """
        if len(data) < 10:  # header is 10 bytes
            raise ValueError("Insufficient data for header")

        stream = io.BytesIO(data)

        # Read header
        magic = stream.read(4)
        if magic != MAGIC:
            raise ValueError(f"Invalid magic: {magic}")

        version = struct.unpack('B', stream.read(1))[0]
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        flags = struct.unpack('B', stream.read(1))[0]
        length = struct.unpack('>L', stream.read(4))[0]

        # Prevent DoS: check payload size
        if length > ProtocolDecoder.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {length} bytes (max {ProtocolDecoder.MAX_PAYLOAD_SIZE})")

        # Read payload
        payload = stream.read(length)
        if len(payload) != length:
            raise ValueError("Incomplete payload")

        # Parse JSON - will raise json.JSONDecodeError if invalid
        try:
            event_dict = json.loads(payload.decode('utf-8'))
            event = LogEvent.from_dict(event_dict)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise ValueError(f"Invalid event format: {e}")

        bytes_consumed = stream.tell()
        return event, bytes_consumed

    @staticmethod
    def decode_batch(data: bytes) -> list[LogEvent]:
        """Decode multiple frames from binary data."""
        events = []
        pos = 0
        while pos < len(data):
            try:
                event, consumed = ProtocolDecoder.decode(data[pos:])
                events.append(event)
                pos += consumed
            except ValueError:
                break
        return events
