"""
Main SIEM engine that orchestrates all components:
- Log ingestion
- Storage
- Correlation
- Anomaly detection
- Query execution
"""

from datetime import datetime
from typing import Dict, List, Any, Optional, Iterator
from threading import Lock
from .storage import LSMStorage
from .correlation import CorrelationEngine, CorrelationAlert
from .anomaly import AnomalyDetector, AnomalyAlert
from .query_dsl import QueryEngine, QueryParser
from .protocol import LogEvent


class SIEMEngine:
    """Central SIEM engine coordinating all components."""

    def __init__(self, data_dir: str = './siem_data'):
        self.storage = LSMStorage(data_dir)
        self.correlation_engine = CorrelationEngine(window_size_seconds=300)
        self.anomaly_detector = AnomalyDetector(window_size=3600, zscore_threshold=2.5)
        self.query_engine = QueryEngine(self.storage)

        self.total_events_processed = 0
        self.alerts: List[Dict[str, Any]] = []
        self._lock = Lock()  # Thread safety for concurrent ingestion

    def ingest_event(self, event: LogEvent) -> List[Dict[str, Any]]:
        """
        Ingest a log event.
        Returns list of generated alerts (if any).
        Thread-safe for concurrent ingestion.
        """
        event_dict = event.to_dict()

        # Store event (storage should handle its own concurrency)
        self.storage.write(event.timestamp, event_dict)

        generated_alerts = []

        # Check for correlations
        corr_alert = self.correlation_engine.add_event(event_dict)
        if corr_alert:
            alert = self._alert_to_dict(corr_alert, 'correlation')
            generated_alerts.append(alert)

        # Check for anomalies
        anom_alert = self.anomaly_detector.process_event(event_dict)
        if anom_alert:
            alert = self._alert_to_dict(anom_alert, 'anomaly')
            generated_alerts.append(alert)

        # Lock only for updating shared state
        with self._lock:
            self.total_events_processed += 1
            self.alerts.extend(generated_alerts)

        return generated_alerts

    def _alert_to_dict(self, alert, alert_source: str) -> Dict[str, Any]:
        """Convert alert object to dictionary."""
        if isinstance(alert, CorrelationAlert):
            return {
                'type': alert_source,
                'timestamp': alert.timestamp.isoformat(),
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'description': alert.description,
                'confidence': alert.confidence,
                'related_events_count': len(alert.related_events),
            }
        elif isinstance(alert, AnomalyAlert):
            return {
                'type': alert_source,
                'timestamp': alert.timestamp.isoformat(),
                'alert_type': alert.anomaly_type,
                'severity': alert.severity,
                'description': alert.description,
                'anomaly_score': alert.anomaly_score,
                'baseline': alert.baseline,
                'observed': alert.observed,
                'confidence': alert.confidence,
            }
        return {}

    def query(self, query: str) -> Dict[str, Any]:
        """Execute query on stored events."""
        try:
            result = self.query_engine.execute(query)
            return {
                'status': 'success',
                'query': query,
                'result': result,
            }
        except Exception as e:
            return {
                'status': 'error',
                'query': query,
                'error': str(e),
            }

    def get_events(self, start: datetime, end: datetime) -> Iterator[Dict[str, Any]]:
        """Get events within time range."""
        return self.storage.range_query(start, end)

    def get_all_events(self) -> Iterator[Dict[str, Any]]:
        """Get all stored events."""
        return self.storage.get_all()

    def get_alerts(self, alert_type: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get filtered alerts."""
        results = self.alerts

        if alert_type:
            results = [a for a in results if a.get('alert_type') == alert_type]

        if severity:
            results = [a for a in results if a.get('severity') == severity]

        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        correlation_alerts = len([a for a in self.alerts if a.get('type') == 'correlation'])
        anomaly_alerts = len([a for a in self.alerts if a.get('type') == 'anomaly'])

        critical_alerts = len([a for a in self.alerts if a.get('severity') == 'CRITICAL'])
        high_alerts = len([a for a in self.alerts if a.get('severity') == 'HIGH'])

        anomaly_summary = self.anomaly_detector.get_metric_summary()

        return {
            'total_events_processed': self.total_events_processed,
            'total_alerts': len(self.alerts),
            'correlation_alerts': correlation_alerts,
            'anomaly_alerts': anomaly_alerts,
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'anomaly_metrics': anomaly_summary,
        }

    def flush(self):
        """Flush storage to disk."""
        self.storage.flush()

    def compact(self):
        """Run storage compaction."""
        self.storage.compact()
