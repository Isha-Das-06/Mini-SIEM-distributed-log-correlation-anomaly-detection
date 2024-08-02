"""
Main entry point for Mini-SIEM.

Usage:
  python main.py server     # Start TCP server
  python main.py cli        # Start interactive CLI
  python main.py test       # Run demo with test data
"""

import sys
import argparse
import threading
from src.engine import SIEMEngine
from src.server import LogServer
from src.cli import SIEMCLI


def main():
    parser = argparse.ArgumentParser(description='Mini-SIEM Engine')
    parser.add_argument(
        'mode',
        choices=['server', 'cli', 'test'],
        help='Run mode'
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Server host (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5140,
        help='Server port (default: 5140)'
    )
    parser.add_argument(
        '--data-dir',
        default='./siem_data',
        help='Data directory (default: ./siem_data)'
    )

    args = parser.parse_args()

    if args.mode == 'server':
        run_server(args)
    elif args.mode == 'cli':
        run_cli(args)
    elif args.mode == 'test':
        run_test(args)


def run_server(args):
    """Run TCP server for log ingestion."""
    engine = SIEMEngine(data_dir=args.data_dir)
    server = LogServer(engine, host=args.host, port=args.port)

    print("=" * 60)
    print("Mini-SIEM Log Server")
    print("=" * 60)
    print(f"Listening on {args.host}:{args.port}")
    print("Agents can connect and send logs")
    print("Press Ctrl+C to stop")
    print()

    server.start()


def run_cli(args):
    """Run interactive CLI."""
    engine = SIEMEngine(data_dir=args.data_dir)
    cli = SIEMCLI(engine)
    cli.run()


def run_test(args):
    """Run demo with synthetic events."""
    from src.protocol import LogEvent
    from datetime import datetime
    import random

    engine = SIEMEngine(data_dir=args.data_dir)

    print("=" * 60)
    print("Mini-SIEM Demo: Synthetic Event Simulation")
    print("=" * 60)
    print()

    # Demo 1: Brute force detection
    print("[*] Demo 1: Brute Force Attack Detection")
    print("-" * 40)

    print("Simulating 5 failed login attempts...")
    for i in range(5):
        event = LogEvent(
            timestamp=datetime.now(),
            source='192.168.1.50',
            log_level='WARN',
            service='auth_service',
            message=f'Failed login attempt for admin (attempt {i+1}): invalid password',
            fields={'username': 'admin', 'attempt': i+1}
        )
        alerts = engine.ingest_event(event)

    print("Simulating successful login after failed attempts...")
    event = LogEvent(
        timestamp=datetime.now(),
        source='192.168.1.50',
        log_level='INFO',
        service='auth_service',
        message='Successful login for admin',
        fields={'username': 'admin'}
    )
    alerts = engine.ingest_event(event)

    if alerts:
        for alert in alerts:
            print(f"\n[!] ALERT TRIGGERED:")
            print(f"   Type: {alert['alert_type']}")
            print(f"   Severity: {alert['severity']}")
            print(f"   Description: {alert['description']}")
            print(f"   Confidence: {alert.get('confidence', 0):.1%}")
    else:
        print("\n[OK] Brute force pattern detected (check via 'siem> alerts' in CLI)")

    print()
    print("[*] Demo 2: Anomaly Detection (Event Rate Spike)")
    print("-" * 40)
    print("Generating events over 4 minutes with spike in minute 3...")
    print("(Using fixed timestamps to properly test minute boundaries)")
    print()

    from datetime import timedelta

    # Use fixed base time to ensure minute boundaries work correctly
    base_time = datetime(2024, 1, 1, 12, 0, 0)

    # Minute 0: establish baseline (12 events)
    print("Minute 0: Baseline rate (12 events)...")
    for i in range(12):
        event = LogEvent(
            timestamp=base_time + timedelta(seconds=i*4),
            source='192.168.1.100',
            log_level='INFO',
            service='webserver',
            message=f'Request {i} processed',
            fields={'response_time': random.randint(50, 200)}
        )
        engine.ingest_event(event)

    # Minute 1: normal rate (12 events)
    print("Minute 1: Normal rate (12 events)...")
    for i in range(12):
        event = LogEvent(
            timestamp=base_time + timedelta(minutes=1, seconds=i*4),
            source='192.168.1.100',
            log_level='INFO',
            service='webserver',
            message=f'Request {i} processed',
            fields={'response_time': random.randint(50, 200)}
        )
        engine.ingest_event(event)

    # Minute 2: normal rate (13 events)
    print("Minute 2: Normal rate (13 events)...")
    for i in range(13):
        event = LogEvent(
            timestamp=base_time + timedelta(minutes=2, seconds=int(i*4.6)),
            source='192.168.1.100',
            log_level='INFO',
            service='webserver',
            message=f'Request {i} processed',
            fields={'response_time': random.randint(50, 200)}
        )
        engine.ingest_event(event)

    # Minute 3: massive spike (120 events/min) - extreme anomaly signal (10x+ baseline)
    print("Minute 3: MASSIVE SPIKE (120 events - 10x+ baseline)...")
    spike_alerts = []
    for i in range(120):
        event = LogEvent(
            timestamp=base_time + timedelta(minutes=3, seconds=i*0.45),
            source='192.168.1.100',
            log_level='INFO',
            service='webserver',
            message=f'Request {i} processed',
            fields={'response_time': random.randint(50, 200)}
        )
        alerts = engine.ingest_event(event)
        if alerts:
            spike_alerts.extend(alerts)

    # Minute 4: return to normal (7 events)
    print("Minute 4: Back to normal (7 events)...")
    for i in range(7):
        event = LogEvent(
            timestamp=base_time + timedelta(minutes=4, seconds=i*7),
            source='192.168.1.100',
            log_level='INFO',
            service='webserver',
            message=f'Request {i} processed',
            fields={'response_time': random.randint(50, 200)}
        )
        alerts = engine.ingest_event(event)
        if alerts:
            spike_alerts.extend(alerts)

    # Minute 5: add one more event to trigger minute-boundary analysis of minute 4
    print("Minute 5: Triggering analysis (1 event)...")
    event = LogEvent(
        timestamp=base_time + timedelta(minutes=5, seconds=0),
        source='192.168.1.100',
        log_level='INFO',
        service='webserver',
        message='Trigger analysis',
        fields={'response_time': random.randint(50, 200)}
    )
    alerts = engine.ingest_event(event)
    if alerts:
        spike_alerts.extend(alerts)

    if spike_alerts:
        print("\n[!] ANOMALY ALERTS DETECTED:")
        for alert in spike_alerts:
            print(f"   Type: {alert['alert_type']}")
            print(f"   Severity: {alert['severity']}")
            print(f"   Description: {alert['description']}")
            print(f"   Anomaly Score: {alert.get('anomaly_score', 0):.2f}")
    else:
        print("\n[!] WARNING: No anomaly alerts (spike detection requires sufficient statistical variance)")

    print()
    print("[*] Demo 3: Query Examples")
    print("-" * 40)

    # Generate some diverse events
    print("Generating test events...")
    for _ in range(100):
        sources = ['web-01', 'web-02', 'db-01', 'auth-01']
        services = ['http', 'postgres', 'authentication', 'cache']
        levels = ['INFO', 'INFO', 'INFO', 'WARN', 'ERROR']

        event = LogEvent(
            timestamp=datetime.now(),
            source=random.choice(sources),
            log_level=random.choice(levels),
            service=random.choice(services),
            message='Sample log message',
            fields={}
        )
        engine.ingest_event(event)

    # Run queries
    queries = [
        ('service="http"', 'All HTTP events'),
        ('log_level="ERROR"', 'All error events'),
        ('service="http" | stats count by source', 'HTTP request count by source'),
        ('log_level="ERROR" | stats count', 'Total error count'),
    ]

    for query, description in queries:
        print(f"\nQuery: {description}")
        print(f"DSL: {query}")
        result = engine.query(query)
        if result['status'] == 'success':
            data = result['result']
            if 'events' in data:
                print(f"Result: {len(data['events'])} events")
            elif 'results' in data:
                for row in data['results'][:3]:
                    print(f"  {row}")

    print()
    print("[*] Engine Statistics")
    print("-" * 40)
    stats = engine.get_stats()
    print(f"Total events processed: {stats['total_events_processed']}")
    print(f"Total alerts generated: {stats['total_alerts']}")
    print(f"  - Correlation alerts: {stats['correlation_alerts']}")
    print(f"  - Anomaly alerts: {stats['anomaly_alerts']}")
    print(f"  - Critical severity: {stats['critical_alerts']}")
    print(f"  - High severity: {stats['high_alerts']}")

    print()
    print("=" * 60)
    print("Demo completed successfully!")
    print("Run 'python main.py cli' to explore the interactive interface")
    print("=" * 60)


if __name__ == '__main__':
    main()
