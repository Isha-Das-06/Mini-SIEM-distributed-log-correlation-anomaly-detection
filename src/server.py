"""
TCP server for distributed log ingestion.

Agents connect and send log events using the custom binary protocol.
Server processes events through the SIEM engine in real-time.
"""

import socket
import threading
import logging
from datetime import datetime
from typing import Optional
from .protocol import ProtocolDecoder, LogEvent
from .engine import SIEMEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LogServer:
    """TCP server accepting log events from distributed agents."""

    def __init__(self, engine: SIEMEngine, host: str = '0.0.0.0', port: int = 5140):
        self.engine = engine
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.client_threads = []

    def start(self):
        """Start the server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(30)  # 30s accept timeout
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        self.running = True
        logger.info(f"Log server started on {self.host}:{self.port}")

        try:
            while self.running:
                try:
                    client_socket, client_addr = self.server_socket.accept()
                    logger.info(f"Client connected from {client_addr}")

                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_addr),
                        daemon=True
                    )
                    thread.start()
                    self.client_threads.append(thread)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logger.error(f"Error accepting client: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Log server stopped")

    def _handle_client(self, client_socket: socket.socket, client_addr: tuple):
        """Handle a connected client."""
        client_socket.settimeout(60)  # 60s read timeout per message
        MAX_BUFFER = 10 * 1024 * 1024  # 10MB max buffer

        try:
            buffer = b''
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    buffer += data

                    # Prevent DoS: buffer size limit
                    if len(buffer) > MAX_BUFFER:
                        logger.error(f"Buffer overflow from {client_addr}, disconnecting")
                        break

                    # Try to decode messages
                    while len(buffer) >= 10:  # Minimum header size
                        try:
                            event, consumed = ProtocolDecoder.decode(buffer)
                            buffer = buffer[consumed:]

                            # Process event
                            alerts = self.engine.ingest_event(event)

                            if alerts:
                                for alert in alerts:
                                    logger.warning(f"ALERT: {alert['alert_type']} (severity: {alert['severity']})")

                        except ValueError:
                            # Incomplete message, wait for more data
                            break

                except socket.timeout:
                    logger.info(f"Client {client_addr} timeout")
                    break
                except Exception as e:
                    logger.error(f"Error reading from client {client_addr}: {e}")
                    break

        finally:
            client_socket.close()
            logger.info(f"Client disconnected from {client_addr}")


class SimpleAgent:
    """Test agent that sends log events to server."""

    def __init__(self, host: str = 'localhost', port: int = 5140, source: str = 'test-host'):
        self.host = host
        self.port = port
        self.source = source
        self.socket: Optional[socket.socket] = None

    def connect(self):
        """Connect to server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        logger.info(f"Connected to server at {self.host}:{self.port}")

    def send_event(self, log_level: str, service: str, message: str, fields: dict = None):
        """Send log event to server."""
        if not self.socket:
            self.connect()

        event = LogEvent(
            timestamp=datetime.now(),
            source=self.source,
            log_level=log_level,
            service=service,
            message=message,
            fields=fields or {},
        )

        from .protocol import ProtocolEncoder
        data = ProtocolEncoder.encode(event)
        self.socket.send(data)

    def disconnect(self):
        """Disconnect from server."""
        if self.socket:
            self.socket.close()
            self.socket = None
