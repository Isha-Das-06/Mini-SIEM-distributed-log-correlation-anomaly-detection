"""
Example log agents that simulate real-world distributed systems.

These agents generate realistic log events and send them to the SIEM engine
via the custom binary protocol.
"""

import time
import sys
import random
import os
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.server import SimpleAgent


class WebServerAgent:
    """Simulates a web server generating HTTP access logs."""

    def __init__(self, host='localhost', port=5140, server_id='web-01'):
        self.agent = SimpleAgent(host=host, port=port, source=server_id)
        self.server_id = server_id
        self.request_count = 0

    def generate_logs(self, duration_seconds=60):
        """Generate logs for duration."""
        start = time.time()

        while time.time() - start < duration_seconds:
            # Normal requests
            if random.random() < 0.9:
                response_time = random.randint(50, 300)
                status = random.choices(['200', '200', '200', '304', '404'], weights=[70, 10, 10, 5, 5])[0]

                self.agent.send_event(
                    log_level='INFO',
                    service='http',
                    message=f'GET /api/users HTTP/1.1 - {status} - {response_time}ms',
                    fields={
                        'method': 'GET',
                        'path': '/api/users',
                        'status': status,
                        'response_time': response_time,
                    }
                )

            # Occasional errors
            else:
                self.agent.send_event(
                    log_level='ERROR',
                    service='http',
                    message='Connection timeout while processing request',
                    fields={'error': 'timeout'}
                )

            self.request_count += 1
            time.sleep(random.uniform(0.1, 0.5))

        print(f"[{self.server_id}] Sent {self.request_count} log events")
        self.agent.disconnect()


class AuthServiceAgent:
    """Simulates an authentication service."""

    def __init__(self, host='localhost', port=5140, server_id='auth-01'):
        self.agent = SimpleAgent(host=host, port=port, source=server_id)
        self.server_id = server_id
        self.login_attempts = 0

    def simulate_normal_logins(self, count=5):
        """Simulate successful login sequence."""
        for i in range(count):
            self.agent.send_event(
                log_level='INFO',
                service='authentication',
                message=f'User login successful for user{i}@example.com',
                fields={
                    'username': f'user{i}@example.com',
                    'ip': f'192.168.1.{100+i}',
                    'method': 'password',
                }
            )
            self.login_attempts += 1
            time.sleep(0.5)

    def simulate_brute_force(self, target_user='admin', attempts=5):
        """Simulate brute force attack."""
        source_ip = '192.168.10.50'

        for i in range(attempts):
            self.agent.send_event(
                log_level='WARN',
                service='authentication',
                message=f'Failed login attempt for {target_user} from {source_ip} (attempt {i+1})',
                fields={
                    'username': target_user,
                    'ip': source_ip,
                    'reason': 'invalid_password',
                    'attempt': i+1,
                }
            )
            self.login_attempts += 1
            time.sleep(0.2)

        # Success after failed attempts
        self.agent.send_event(
            log_level='INFO',
            service='authentication',
            message=f'User login successful for {target_user} from {source_ip}',
            fields={
                'username': target_user,
                'ip': source_ip,
                'method': 'password',
            }
        )
        self.login_attempts += 1

    def generate_logs(self, duration_seconds=30):
        """Generate auth logs for duration."""
        start = time.time()

        while time.time() - start < duration_seconds:
            if random.random() < 0.7:
                # Normal login
                self.agent.send_event(
                    log_level='INFO',
                    service='authentication',
                    message=f'User login successful',
                    fields={'username': f'user{random.randint(1, 50)}'}
                )
            else:
                # Failed login
                self.agent.send_event(
                    log_level='WARN',
                    service='authentication',
                    message='Failed login attempt',
                    fields={'reason': 'invalid_password'}
                )

            self.login_attempts += 1
            time.sleep(random.uniform(0.5, 2.0))

        print(f"[{self.server_id}] Sent {self.login_attempts} auth events")
        self.agent.disconnect()


class DatabaseAgent:
    """Simulates a database service."""

    def __init__(self, host='localhost', port=5140, server_id='db-01'):
        self.agent = SimpleAgent(host=host, port=port, source=server_id)
        self.server_id = server_id
        self.query_count = 0

    def generate_logs(self, duration_seconds=60):
        """Generate database logs."""
        start = time.time()

        while time.time() - start < duration_seconds:
            if random.random() < 0.95:
                # Normal query
                duration = random.randint(5, 500)
                self.agent.send_event(
                    log_level='INFO',
                    service='postgres',
                    message=f'Query executed in {duration}ms',
                    fields={
                        'query_type': random.choice(['SELECT', 'INSERT', 'UPDATE']),
                        'duration_ms': duration,
                        'rows_affected': random.randint(1, 1000),
                    }
                )
            else:
                # Slow query
                duration = random.randint(2000, 10000)
                self.agent.send_event(
                    log_level='WARN',
                    service='postgres',
                    message=f'Slow query warning: {duration}ms',
                    fields={
                        'query_type': 'SELECT',
                        'duration_ms': duration,
                    }
                )

            self.query_count += 1
            time.sleep(random.uniform(0.1, 0.3))

        print(f"[{self.server_id}] Sent {self.query_count} database events")
        self.agent.disconnect()


def run_agents_demo(host='localhost', port=5140, duration=30):
    """Run multiple agents in parallel."""
    import threading

    print(f"Starting agents (connecting to {host}:{port})...")
    print()

    # Create agents
    web = WebServerAgent(host=host, port=port, server_id='web-server-01')
    auth = AuthServiceAgent(host=host, port=port, server_id='auth-service-01')
    db = DatabaseAgent(host=host, port=port, server_id='database-01')

    # Start normal operation
    threads = [
        threading.Thread(target=web.generate_logs, args=(duration,)),
        threading.Thread(target=db.generate_logs, args=(duration,)),
    ]

    for t in threads:
        t.start()

    # Simulate brute force attack after 5 seconds
    time.sleep(5)
    print("\n[+] Simulating brute force attack...")
    auth.simulate_brute_force(target_user='admin', attempts=5)

    # Generate normal auth logs
    auth.generate_logs(duration - 5)

    # Wait for all agents
    for t in threads:
        t.join()

    print("\nAll agents stopped")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Run example log agents')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=5140, help='Server port')
    parser.add_argument('--duration', type=int, default=30, help='Duration in seconds')

    args = parser.parse_args()

    try:
        run_agents_demo(host=args.host, port=args.port, duration=args.duration)
    except KeyboardInterrupt:
        print("\nInterrupted")
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server at {args.host}:{args.port}")
        print("Make sure the SIEM server is running: python -m src.cli")
