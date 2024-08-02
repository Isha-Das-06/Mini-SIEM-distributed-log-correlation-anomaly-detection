"""Unit tests for anomaly detection."""

import pytest
from datetime import datetime, timedelta
from src.anomaly import TimeSeriesMetric, AnomalyDetector


class TestTimeSeriesMetric:
    """Tests for time series metric with EWMA."""

    def test_ewma_calculation(self):
        """Test EWMA calculation."""
        metric = TimeSeriesMetric(alpha=0.3)

        # First value
        metric.update(10.0)
        assert metric.get_ewma() == 10.0

        # Second value - should blend
        metric.update(20.0)
        ewma = metric.get_ewma()
        assert 10 < ewma < 20  # Should be between the values
        assert abs(ewma - 13.0) < 0.01  # 0.3*20 + 0.7*10

    def test_zscore_calculation(self):
        """Test Z-score calculation."""
        metric = TimeSeriesMetric(alpha=0.3)

        # Add baseline values
        for i in range(10):
            metric.update(float(i))

        # Now test Z-score
        baseline = metric.get_ewma()
        zscore = metric.get_zscore(baseline)
        assert zscore == 0.0  # No deviation from baseline

        # Test with outlier
        outlier_score = metric.get_zscore(baseline + 100)
        assert outlier_score > 0

    def test_std_dev(self):
        """Test standard deviation calculation."""
        metric = TimeSeriesMetric(alpha=0.3)

        values = [10, 20, 30, 40, 50]
        for v in values:
            metric.update(float(v))

        std_dev = metric.get_std_dev()
        # Should be > 0 for varied data
        assert std_dev > 0

        # Single value should have 0 std dev
        metric2 = TimeSeriesMetric(alpha=0.3)
        metric2.update(10.0)
        assert metric2.get_std_dev() == 0.0


class TestAnomalyDetector:
    """Tests for anomaly detector."""

    def test_event_rate_baseline(self):
        """Test establishing baseline event rate."""
        detector = AnomalyDetector(window_size=3600, zscore_threshold=2.5)
        now = datetime.now()
        base_minute = int(now.timestamp()) // 60

        # Add events for minute 0
        for i in range(5):
            event = {
                'timestamp': now + timedelta(seconds=i*10),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            detector.process_event(event)

        # Move to next minute
        next_minute_time = now + timedelta(minutes=1)

        # Process event in next minute to trigger analysis of previous
        event = {
            'timestamp': next_minute_time,
            'source': 'host1',
            'log_level': 'INFO',
            'service': 'app',
            'message': 'test'
        }
        detector.process_event(event)

        # Should have recorded rate for host1
        summary = detector.get_metric_summary()
        assert 'host1' in summary['event_rates']
        assert summary['event_rates']['host1']['samples'] > 0

    def test_event_rate_spike_detection(self):
        """Test detection of event rate spikes."""
        detector = AnomalyDetector(window_size=3600, zscore_threshold=2.0)

        # Use minute boundaries to properly test anomaly detector
        base_time = datetime(2024, 1, 1, 12, 0, 0)

        # Minute 0: baseline (5 events)
        for i in range(5):
            event = {
                'timestamp': base_time + timedelta(seconds=i*10),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            detector.process_event(event)

        # Minute 1: normal (6 events)
        for i in range(6):
            event = {
                'timestamp': base_time + timedelta(minutes=1, seconds=i*9),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            detector.process_event(event)

        # Minute 2: massive spike (60 events)
        alerts = []
        for i in range(60):
            event = {
                'timestamp': base_time + timedelta(minutes=2, seconds=i*0.8),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            alert = detector.process_event(event)
            if alert:
                alerts.append(alert)

        # Minute 3: trigger analysis by adding event in next minute
        event = {
            'timestamp': base_time + timedelta(minutes=3),
            'source': 'host1',
            'log_level': 'INFO',
            'service': 'app',
            'message': 'test'
        }
        alert = detector.process_event(event)
        if alert:
            alerts.append(alert)

        # Should detect anomaly (from minute 2 spike)
        assert len(alerts) > 0
        found = any(a.anomaly_type == 'EVENT_RATE_SPIKE' for a in alerts)
        assert found

    def test_error_rate_anomaly(self):
        """Test detection of error rate anomalies."""
        detector = AnomalyDetector(window_size=3600, zscore_threshold=2.0)

        base_time = datetime(2024, 1, 1, 12, 0, 0)

        # Minute 0: normal error rate
        for i in range(2):
            event = {
                'timestamp': base_time + timedelta(seconds=i*20),
                'source': 'host1',
                'log_level': 'ERROR',
                'service': 'db',
                'message': 'query timeout'
            }
            detector.process_event(event)

        # Minute 1: normal
        for i in range(2):
            event = {
                'timestamp': base_time + timedelta(minutes=1, seconds=i*20),
                'source': 'host1',
                'log_level': 'ERROR',
                'service': 'db',
                'message': 'query timeout'
            }
            detector.process_event(event)

        # Minute 2: error spike
        alerts = []
        for i in range(40):
            event = {
                'timestamp': base_time + timedelta(minutes=2, seconds=i*1.2),
                'source': 'host1',
                'log_level': 'ERROR',
                'service': 'db',
                'message': 'query timeout'
            }
            alert = detector.process_event(event)
            if alert:
                alerts.append(alert)

        # Minute 3: trigger analysis
        event = {
            'timestamp': base_time + timedelta(minutes=3),
            'source': 'host1',
            'log_level': 'ERROR',
            'service': 'db',
            'message': 'query timeout'
        }
        alert = detector.process_event(event)
        if alert:
            alerts.append(alert)

        # Should detect error rate anomaly
        assert any(a.anomaly_type == 'ERROR_RATE_SPIKE' for a in alerts)

    def test_multiple_sources(self):
        """Test tracking anomalies for multiple sources."""
        detector = AnomalyDetector(window_size=3600, zscore_threshold=2.0)
        now = datetime.now()

        # Add events for host1 and host2
        for host in ['host1', 'host2']:
            for i in range(5):
                event = {
                    'timestamp': now + timedelta(seconds=i*10),
                    'source': host,
                    'log_level': 'INFO',
                    'service': 'app',
                    'message': 'test'
                }
                detector.process_event(event)

        # Check metrics for both
        summary = detector.get_metric_summary()
        assert 'host1' in summary['event_rates']
        assert 'host2' in summary['event_rates']

    def test_alert_storage(self):
        """Test that alerts are stored."""
        detector = AnomalyDetector(window_size=3600, zscore_threshold=2.0)

        base_time = datetime(2024, 1, 1, 12, 0, 0)

        # Generate baseline
        for i in range(5):
            event = {
                'timestamp': base_time + timedelta(seconds=i*10),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            detector.process_event(event)

        # Spike in minute 1
        for i in range(60):
            event = {
                'timestamp': base_time + timedelta(minutes=1, seconds=i*0.8),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            detector.process_event(event)

        # Trigger analysis in minute 2
        event = {
            'timestamp': base_time + timedelta(minutes=2),
            'source': 'host1',
            'log_level': 'INFO',
            'service': 'app',
            'message': 'test'
        }
        detector.process_event(event)

        alerts = detector.get_alerts()
        assert len(alerts) > 0

    def test_alert_clearing(self):
        """Test clearing alerts."""
        detector = AnomalyDetector(window_size=3600, zscore_threshold=2.0)

        base_time = datetime(2024, 1, 1, 12, 0, 0)

        # Generate baseline
        for i in range(5):
            event = {
                'timestamp': base_time + timedelta(seconds=i*10),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            detector.process_event(event)

        # Spike in minute 1
        for i in range(60):
            event = {
                'timestamp': base_time + timedelta(minutes=1, seconds=i*0.8),
                'source': 'host1',
                'log_level': 'INFO',
                'service': 'app',
                'message': 'test'
            }
            detector.process_event(event)

        # Trigger analysis in minute 2
        event = {
            'timestamp': base_time + timedelta(minutes=2),
            'source': 'host1',
            'log_level': 'INFO',
            'service': 'app',
            'message': 'test'
        }
        detector.process_event(event)

        assert len(detector.get_alerts()) > 0
        detector.clear_alerts()
        assert len(detector.get_alerts()) == 0
