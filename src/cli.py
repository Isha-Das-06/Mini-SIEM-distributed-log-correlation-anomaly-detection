"""
Interactive CLI for SIEM engine.

Commands:
  query <DSL>             Execute SPL/KQL-like query
  alerts [type] [severity]  Show alerts
  stats                   Show engine statistics
  flush                   Flush storage to disk
  compact                 Run compaction
  test                    Run test scenarios
  help                    Show help
  exit                    Exit CLI
"""

import sys
import json
from datetime import datetime, timedelta
from .engine import SIEMEngine
from .protocol import LogEvent


class SIEMCLI:
    """Interactive CLI for SIEM."""

    def __init__(self, engine: SIEMEngine):
        self.engine = engine
        self.running = True

    def run(self):
        """Start interactive CLI."""
        print("=" * 60)
        print("Mini-SIEM Engine - Interactive Console")
        print("=" * 60)
        print("Type 'help' for commands\n")

        while self.running:
            try:
                cmd = input("siem> ").strip()
                if cmd:
                    self.execute(cmd)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                break

    def execute(self, cmd: str):
        """Execute CLI command."""
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ''

        if command == 'help':
            self.show_help()
        elif command == 'query':
            self.handle_query(args)
        elif command == 'alerts':
            self.handle_alerts(args)
        elif command == 'stats':
            self.handle_stats()
        elif command == 'flush':
            self.handle_flush()
        elif command == 'compact':
            self.handle_compact()
        elif command == 'test':
            self.handle_test()
        elif command == 'exit':
            self.running = False
            print("Goodbye!")
        else:
            print(f"Unknown command: {command}. Type 'help' for commands.")

    def show_help(self):
        """Show help message."""
        print("""
Commands:
  query <DSL>                  Execute query (SPL/KQL-like)
    Examples:
      query service="auth" log_level="ERROR"
      query source="webserver*" | stats count by service
      query earliest=2024-01-01T00:00:00 latest=2024-01-02T00:00:00 | stats count

  alerts [type] [severity]    Show alerts (optionally filtered)
    Examples:
      alerts                                  (show all)
      alerts BRUTE_FORCE_ATTACK              (by type)
      alerts "" HIGH                         (by severity)

  stats                       Show engine statistics

  flush                       Flush storage to disk

  compact                     Run storage compaction

  test                        Run demo with synthetic events

  help                        Show this help

  exit                        Exit CLI
        """)

    def handle_query(self, query: str):
        """Execute a query."""
        if not query:
            print("Usage: query <DSL>")
            return

        result = self.engine.query(query)

        if result['status'] == 'success':
            data = result['result']
            if 'events' in data:
                print(f"Found {len(data['events'])} events:")
                for event in data['events'][:10]:  # Show first 10
                    print(f"  {event['timestamp']} | {event['source']} | {event['service']} | {event['message']}")
                if len(data['events']) > 10:
                    print(f"  ... and {len(data['events']) - 10} more")
            elif 'results' in data:
                print("Aggregation results:")
                for row in data['results']:
                    print(f"  {json.dumps(row)}")
            else:
                print(f"Result: {json.dumps(data, indent=2)}")
        else:
            print(f"Query error: {result['error']}")

    def handle_alerts(self, args: str):
        """Show alerts."""
        parts = args.split() if args else []
        alert_type = parts[0] if len(parts) > 0 and parts[0] else None
        severity = parts[1] if len(parts) > 1 else None

        alerts = self.engine.get_alerts(alert_type=alert_type, severity=severity)

        if not alerts:
            print("No alerts")
            return

        print(f"Total alerts: {len(alerts)}\n")
        for alert in alerts[-20:]:  # Show last 20
            print(f"  [{alert.get('timestamp')}] {alert.get('severity'):8} | {alert.get('alert_type')}")
            print(f"    {alert.get('description')}")

    def handle_stats(self):
        """Show statistics."""
        stats = self.engine.get_stats()
        print(json.dumps(stats, indent=2))

    def handle_flush(self):
        """Flush storage."""
        self.engine.flush()
        print("Storage flushed to disk")

    def handle_compact(self):
        """Run compaction."""
        self.engine.compact()
        print("Compaction completed")

    def handle_test(self):
        """Run test scenario with synthetic events."""
        print("Running demo scenario...")
        print()

        # Simulate successful login sequence
        print("Step 1: Simulating failed login attempts...")
        for i in range(5):
            event = LogEvent(
                timestamp=datetime.now(),
                source='192.168.1.100',
                log_level='WARN',
                service='auth_service',
                message=f'Failed login attempt for user admin (attempt {i+1})',
                fields={'username': 'admin', 'attempt': i+1}
            )
            alerts = self.engine.ingest_event(event)
            if alerts:
                print(f"  ALERT: {alerts[0]['alert_type']} - {alerts[0]['description']}")

        # Successful login
        print("\nStep 2: Simulating successful login...")
        event = LogEvent(
            timestamp=datetime.now(),
            source='192.168.1.100',
            log_level='INFO',
            service='auth_service',
            message='Successful login for user admin',
            fields={'username': 'admin'}
        )
        alerts = self.engine.ingest_event(event)
        if alerts:
            for alert in alerts:
                print(f"  ALERT: {alert['alert_type']} - {alert['description']}")
                print(f"    Confidence: {alert.get('confidence', 0):.2%}")

        # Normal activity
        print("\nStep 3: Simulating normal activity...")
        for i in range(15):
            event = LogEvent(
                timestamp=datetime.now(),
                source='192.168.1.101',
                log_level='INFO',
                service='web_service',
                message=f'Request processed (response_time={100+i*10}ms)',
                fields={'response_time': 100+i*10}
            )
            self.engine.ingest_event(event)

        # Sudden spike
        print("\nStep 4: Simulating spike (potential anomaly)...")
        for i in range(20):
            event = LogEvent(
                timestamp=datetime.now(),
                source='192.168.1.101',
                log_level='INFO',
                service='web_service',
                message=f'Request processed (response_time={2000+i*100}ms)',
                fields={'response_time': 2000+i*100}
            )
            alerts = self.engine.ingest_event(event)
            if alerts:
                print(f"  ALERT: {alerts[0]['alert_type']}")

        print("\nDemo complete. Use 'stats' to see summary.")


def main():
    """Entry point for CLI."""
    engine = SIEMEngine()
    cli = SIEMCLI(engine)
    cli.run()


if __name__ == '__main__':
    main()
