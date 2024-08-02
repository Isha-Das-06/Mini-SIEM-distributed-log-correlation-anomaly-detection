"""
Mini-SIEM: Distributed Log Correlation and Anomaly Detection

A scaled-down Splunk/Elastic alternative demonstrating:
- Distributed log ingestion via custom binary protocol
- LSM-tree storage for efficient time-range queries
- Sliding-window correlation engine for pattern detection
- Statistical anomaly detection using EWMA and Z-score
- SPL/KQL-like query DSL
"""

from .protocol import LogEvent, ProtocolEncoder, ProtocolDecoder
from .storage import LSMStorage, SSTable, MemTable
from .correlation import CorrelationEngine, CorrelationAlert
from .anomaly import AnomalyDetector, AnomalyAlert
from .query_dsl import QueryEngine, QueryParser
from .engine import SIEMEngine
from .server import LogServer, SimpleAgent
from .cli import SIEMCLI

__all__ = [
    'LogEvent',
    'ProtocolEncoder',
    'ProtocolDecoder',
    'LSMStorage',
    'SSTable',
    'MemTable',
    'CorrelationEngine',
    'CorrelationAlert',
    'AnomalyDetector',
    'AnomalyAlert',
    'QueryEngine',
    'QueryParser',
    'SIEMEngine',
    'LogServer',
    'SimpleAgent',
    'SIEMCLI',
]
