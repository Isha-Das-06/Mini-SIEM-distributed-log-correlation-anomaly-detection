"""
Statistical anomaly detector using EWMA (Exponentially Weighted Moving Average)
and Z-score for event rate analysis.

Detects unusual patterns in:
- Event rate per source
- Error rate per service
- Event type distribution
- Temporal anomalies
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import math


@dataclass
class AnomalyAlert:
    """Alert for detected anomaly."""
    timestamp: datetime
    anomaly_type: str
    severity: str  # "LOW", "MEDIUM", "HIGH"
    description: str
    anomaly_score: float  # 0.0 to 1.0
    baseline: float
    observed: float
    confidence: float


class TimeSeriesMetric:
    """Tracks a single metric over time with EWMA."""

    def __init__(self, alpha: float = 0.3, max_samples: int = 100):
        """
        alpha: smoothing factor (0.0-1.0), higher = more weight to recent values
        max_samples: max number of samples to keep (for variance calculation only)
        """
        self.alpha = alpha
        self.ewma: Optional[float] = None
        self.samples: List[float] = []
        self.max_samples = max_samples
        self.last_update = datetime.now()

    def update(self, value: float):
        """Update metric with new value."""
        self.samples.append(value)
        # Keep only recent samples to prevent memory bloat
        if len(self.samples) > self.max_samples:
            self.samples = self.samples[-self.max_samples:]

        if self.ewma is None:
            self.ewma = value
        else:
            self.ewma = (self.alpha * value) + ((1 - self.alpha) * self.ewma)

        self.last_update = datetime.now()

    def get_ewma(self) -> float:
        """Get current EWMA value."""
        return self.ewma or 0.0

    def get_std_dev(self) -> float:
        """Get standard deviation of samples."""
        if len(self.samples) < 2:
            return 0.0
        mean = sum(self.samples) / len(self.samples)
        # Use sample variance (N-1) not population variance (N)
        variance = sum((x - mean) ** 2 for x in self.samples) / (len(self.samples) - 1)
        return math.sqrt(variance)

    def get_zscore(self, value: float) -> float:
        """Calculate Z-score for value."""
        if self.ewma is None:
            return 0.0
        std_dev = self.get_std_dev()

        # Fallback for low variance: use simple ratio if std_dev is too small
        if std_dev < 1.0:
            # If value deviates from baseline by >5x, flag as anomaly
            # This handles cases with insufficient samples for proper zscore
            baseline = self.ewma
            if baseline > 0:
                ratio = value / baseline
                if ratio > 5.0:  # 5x increase from baseline
                    return (ratio - 1.0) * 2.0  # Scale to roughly match zscore threshold
            return 0.0

        return abs(value - self.ewma) / std_dev


class AnomalyDetector:
    """Detects anomalies in event streams using statistical methods."""

    def __init__(self, window_size: int = 3600, zscore_threshold: float = 2.5):
        """
        window_size: seconds to track metrics over (not used currently, for future)
        zscore_threshold: Z-score above which is considered anomalous
        """
        self.window_size = window_size
        self.zscore_threshold = zscore_threshold

        # Metrics per source
        self.event_rates: Dict[str, TimeSeriesMetric] = defaultdict(
            lambda: TimeSeriesMetric(alpha=0.3)
        )

        # Metrics per service
        self.error_rates: Dict[str, TimeSeriesMetric] = defaultdict(
            lambda: TimeSeriesMetric(alpha=0.3)
        )

        # Event counts for rate calculation (per minute)
        self.event_counts: Dict[str, int] = defaultdict(int)
        self.last_minute: Dict[str, int] = defaultdict(int)  # Track which minute

        # Error counts per service (per minute)
        self.error_counts: Dict[str, int] = defaultdict(int)
        self.last_error_minute: Dict[str, int] = defaultdict(int)

        self.alerts: List[AnomalyAlert] = []

    def process_event(self, event: Dict) -> Optional[AnomalyAlert]:
        """Process event and detect anomalies."""
        timestamp = event.get('timestamp')
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        source = event.get('source', 'unknown')
        service = event.get('service', 'unknown')
        log_level = event.get('log_level', 'INFO')

        # Get current minute
        current_minute = int(timestamp.timestamp()) // 60

        # Ensure metrics exist for this source/service even without minute transitions
        # This allows get_metric_summary() to return data
        _ = self.event_rates[source]
        _ = self.error_rates[service]

        alert = None

        # Check if minute changed - BEFORE incrementing count
        # This ensures we analyze the previous minute's full count
        if self.last_minute[source] != 0 and self.last_minute[source] != current_minute:
            # Calculate rate for the previous minute
            rate = self.event_counts[source]  # events in that minute

            # Check for anomaly using z-score BEFORE updating baseline
            # This way we detect against the OLD baseline, not the new spike value
            baseline = self.event_rates[source].get_ewma()
            zscore = self.event_rates[source].get_zscore(rate)

            if zscore > self.zscore_threshold:
                alert = AnomalyAlert(
                    timestamp=timestamp,
                    anomaly_type='EVENT_RATE_SPIKE',
                    severity='HIGH' if zscore > 3.5 else 'MEDIUM',
                    description=f'Unusual event rate from {source}: {rate} events/min (baseline: {baseline:.1f})',
                    anomaly_score=min(1.0, zscore / 5.0),
                    baseline=baseline,
                    observed=float(rate),
                    confidence=min(0.95, 0.6 + (zscore / 10.0))
                )
                if alert:
                    self.alerts.append(alert)

            # Now update baseline with the rate for future anomaly checks
            self.event_rates[source].update(rate)
            self.event_counts[source] = 0

        # NOW update event count for current event
        self.event_counts[source] += 1
        self.last_minute[source] = current_minute

        # Check error rate anomalies
        if log_level in ['ERROR', 'CRITICAL', 'WARN']:
            # Check if minute changed for errors BEFORE incrementing
            if self.last_error_minute[service] != 0 and self.last_error_minute[service] != current_minute:
                error_count = self.error_counts[service]

                # Check for anomaly BEFORE updating baseline
                baseline = self.error_rates[service].get_ewma()
                zscore = self.error_rates[service].get_zscore(float(error_count))

                if zscore > self.zscore_threshold:
                    anom_alert = AnomalyAlert(
                        timestamp=timestamp,
                        anomaly_type='ERROR_RATE_SPIKE',
                        severity='HIGH' if zscore > 3.5 else 'MEDIUM',
                        description=f'Unusual error rate in {service}: {error_count} errors/min (baseline: {baseline:.1f})',
                        anomaly_score=min(1.0, zscore / 5.0),
                        baseline=baseline,
                        observed=float(error_count),
                        confidence=min(0.95, 0.6 + (zscore / 10.0))
                    )
                    if anom_alert:
                        self.alerts.append(anom_alert)
                        alert = anom_alert

                # Now update baseline
                self.error_rates[service].update(float(error_count))
                self.error_counts[service] = 0

            # NOW increment and update minute
            self.error_counts[service] += 1
            self.last_error_minute[service] = current_minute

        return alert


    def get_alerts(self) -> List[AnomalyAlert]:
        """Get all anomaly alerts."""
        return self.alerts

    def clear_alerts(self):
        """Clear alert history."""
        self.alerts.clear()

    def get_metric_summary(self) -> Dict:
        """Get summary of current metrics."""
        return {
            'event_rates': {
                source: {
                    'ewma': metric.get_ewma(),
                    'std_dev': metric.get_std_dev(),
                    'samples': len(metric.samples),
                }
                for source, metric in self.event_rates.items()
            },
            'error_rates': {
                service: {
                    'ewma': metric.get_ewma(),
                    'std_dev': metric.get_std_dev(),
                    'samples': len(metric.samples),
                }
                for service, metric in self.error_rates.items()
            }
        }
