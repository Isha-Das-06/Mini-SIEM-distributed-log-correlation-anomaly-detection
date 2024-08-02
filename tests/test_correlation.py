"""Unit tests for correlation engine."""

import pytest
from datetime import datetime, timedelta
from src.correlation import CorrelationEngine, EventWindow, CorrelationAlert


class TestEventWindow:
    """Tests for sliding event window."""

    def test_add_event(self):
        """Test adding events to window."""
        window = EventWindow(timedelta(minutes=5))
        event = {
            'timestamp': datetime.now(),
            'source': 'host1',
            'message': 'test',
            'log_level': 'INFO',
            'service': 'app'
        }
        window.add(event)
        assert len(window.events) == 1

    def test_window_pruning(self):
        """Test that old events are pruned from window."""
        window = EventWindow(timedelta(minutes=5))
        now = datetime.now()

        # Add old event
        old_event = {
            'timestamp': now - timedelta(minutes=10),
            'source': 'host1',
            'message': 'old',
            'log_level': 'INFO',
            'service': 'app'
        }
        window.add(old_event)

        # Add recent event
        recent_event = {
            'timestamp': now,
            'source': 'host1',
            'message': 'recent',
            'log_level': 'INFO',
            'service': 'app'
        }
        window.add(recent_event)

        # Only recent event should remain
        assert len(window.events) == 1
        assert window.events[0]['message'] == 'recent'

    def test_get_events_filter_source(self):
        """Test filtering events by source."""
        window = EventWindow(timedelta(minutes=5))
        now = datetime.now()

        for i in range(3):
            event = {
                'timestamp': now + timedelta(seconds=i),
                'source': f'host{i % 2}',
                'message': f'event{i}',
                'log_level': 'INFO',
                'service': 'app'
            }
            window.add(event)

        host0_events = window.get_events(source='host0')
        assert len(host0_events) == 2


class TestCorrelationEngine:
    """Tests for correlation engine."""

    def test_brute_force_detection(self):
        """Test brute force attack detection."""
        engine = CorrelationEngine(window_size_seconds=300)
        now = datetime.now()
        source = '192.168.1.100'

        # Add 5 failed login attempts
        for i in range(5):
            event = {
                'timestamp': now + timedelta(seconds=i),
                'source': source,
                'service': 'auth_service',
                'log_level': 'WARN',
                'message': f'Failed login attempt {i}: invalid password',
                'fields': {'username': 'admin'}
            }
            engine.add_event(event)

        # Successful login should trigger alert
        success_event = {
            'timestamp': now + timedelta(seconds=10),
            'source': source,
            'service': 'auth_service',
            'log_level': 'INFO',
            'message': 'Successful login for admin',
            'fields': {'username': 'admin'}
        }
        alert = engine.add_event(success_event)

        assert alert is not None
        assert alert.alert_type == 'BRUTE_FORCE_ATTACK'
        assert alert.severity == 'HIGH'
        assert len(alert.related_events) >= 5

    def test_no_alert_insufficient_failures(self):
        """Test that insufficient failed attempts don't trigger alert."""
        engine = CorrelationEngine(window_size_seconds=300)
        now = datetime.now()
        source = '192.168.1.100'

        # Add only 2 failed login attempts (below threshold)
        for i in range(2):
            event = {
                'timestamp': now + timedelta(seconds=i),
                'source': source,
                'service': 'auth_service',
                'log_level': 'WARN',
                'message': f'Failed login attempt {i}',
                'fields': {}
            }
            engine.add_event(event)

        # Success should not trigger (below 3 failures)
        success_event = {
            'timestamp': now + timedelta(seconds=10),
            'source': source,
            'service': 'auth_service',
            'log_level': 'INFO',
            'message': 'Successful login',
            'fields': {}
        }
        alert = engine.add_event(success_event)
        assert alert is None

    def test_privilege_escalation_detection(self):
        """Test privilege escalation detection."""
        engine = CorrelationEngine(window_size_seconds=300)
        now = datetime.now()
        source = '192.168.1.100'

        # Normal user activity
        normal_event = {
            'timestamp': now,
            'source': source,
            'service': 'app',
            'log_level': 'INFO',
            'message': 'User login',
            'fields': {}
        }
        engine.add_event(normal_event)

        # Sudo attempt (elevated)
        sudo_event = {
            'timestamp': now + timedelta(seconds=5),
            'source': source,
            'service': 'app',
            'log_level': 'ERROR',
            'message': 'sudo access attempted',
            'fields': {}
        }
        alert = engine.add_event(sudo_event)

        assert alert is not None
        assert alert.alert_type == 'PRIVILEGE_ESCALATION'
        assert alert.severity == 'CRITICAL'

    def test_lateral_movement_detection(self):
        """Test lateral movement detection."""
        engine = CorrelationEngine(window_size_seconds=300)
        now = datetime.now()

        # Failed auth attempts on multiple services
        services = ['webserver', 'database', 'cache']
        for i, service in enumerate(services):
            event = {
                'timestamp': now + timedelta(seconds=i),
                'source': '192.168.1.50',
                'service': service,
                'log_level': 'WARN',
                'message': 'Failed authentication',
                'fields': {'target_host': f'host{i}'}
            }
            engine.add_event(event)

        # Should detect lateral movement (3+ different targets)
        latest_event = {
            'timestamp': now + timedelta(seconds=10),
            'source': '192.168.1.50',
            'service': 'monitoring',
            'log_level': 'WARN',
            'message': 'Failed access',
            'fields': {}
        }
        alert = engine.add_event(latest_event)

        assert alert is not None
        assert alert.alert_type == 'LATERAL_MOVEMENT'
        assert alert.severity == 'HIGH'

    def test_alert_storage(self):
        """Test that alerts are stored in engine."""
        engine = CorrelationEngine(window_size_seconds=300)
        now = datetime.now()

        # Trigger brute force alert
        for i in range(5):
            event = {
                'timestamp': now + timedelta(seconds=i),
                'source': '192.168.1.100',
                'service': 'auth_service',
                'log_level': 'WARN',
                'message': 'Failed login',
                'fields': {}
            }
            engine.add_event(event)

        success_event = {
            'timestamp': now + timedelta(seconds=10),
            'source': '192.168.1.100',
            'service': 'auth_service',
            'log_level': 'INFO',
            'message': 'Successful login',
            'fields': {}
        }
        engine.add_event(success_event)

        alerts = engine.get_alerts()
        assert len(alerts) == 1
        assert alerts[0].alert_type == 'BRUTE_FORCE_ATTACK'

    def test_alert_clearing(self):
        """Test clearing alerts."""
        engine = CorrelationEngine(window_size_seconds=300)
        now = datetime.now()

        # Trigger alert
        for i in range(5):
            event = {
                'timestamp': now + timedelta(seconds=i),
                'source': '192.168.1.100',
                'service': 'auth_service',
                'log_level': 'WARN',
                'message': 'Failed login',
                'fields': {}
            }
            engine.add_event(event)

        success_event = {
            'timestamp': now + timedelta(seconds=10),
            'source': '192.168.1.100',
            'service': 'auth_service',
            'log_level': 'INFO',
            'message': 'Successful login',
            'fields': {}
        }
        engine.add_event(success_event)

        assert len(engine.get_alerts()) == 1
        engine.clear_alerts()
        assert len(engine.get_alerts()) == 0
