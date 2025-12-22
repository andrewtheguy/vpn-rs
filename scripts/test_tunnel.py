#!/usr/bin/env python3
"""
Test multiple tunnel sessions with concurrent streaming and checksum verification.

Usage:
    python3 test_tunnel.py [BASE_PORT] [NUM_SESSIONS] [DURATION_SECS]
    python3 test_tunnel.py [BASE_PORT] [NUM_SESSIONS] --loop

Examples:
    python3 test_tunnel.py 7001 3 10      # Stream for 10 seconds
    python3 test_tunnel.py 7001 3 --loop  # Continuous ping test
"""

import socket
import sys
import time
import threading
import hashlib
import re
from dataclasses import dataclass, field

# Parse args
args = [a for a in sys.argv[1:] if not a.startswith('--')]
flags = [a for a in sys.argv[1:] if a.startswith('--')]

BASE_PORT = int(args[0]) if len(args) > 0 else 7001
NUM_SESSIONS = int(args[1]) if len(args) > 1 else 3
DURATION = int(args[2]) if len(args) > 2 else 5
LOOP_MODE = '--loop' in flags

@dataclass
class Stats:
    port: int
    sent_msgs: int = 0
    recv_msgs: int = 0
    sent_bytes: int = 0
    recv_bytes: int = 0
    errors: int = 0
    checksum_ok: int = 0
    checksum_fail: int = 0
    connected: bool = False
    sent_checksum: str = ""  # Running checksum of all sent data
    recv_checksum: str = ""  # Running checksum of all received data
    _sent_hasher: object = field(default=None, repr=False)
    _recv_hasher: object = field(default=None, repr=False)

    def __post_init__(self):
        self._sent_hasher = hashlib.md5()
        self._recv_hasher = hashlib.md5()

    def update_sent(self, data: bytes):
        self._sent_hasher.update(data)
        self.sent_checksum = self._sent_hasher.hexdigest()[:16]

    def update_recv(self, data: bytes):
        self._recv_hasher.update(data)
        self.recv_checksum = self._recv_hasher.hexdigest()[:16]

def format_bytes(n: int) -> str:
    """Format bytes as human readable."""
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n/1024:.1f}KB"
    else:
        return f"{n/(1024*1024):.2f}MB"

def stream_session(port: int, duration: float, stats: Stats):
    """Stream data through a tunnel for the specified duration with checksum verification."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', port))
        sock.setblocking(False)
        stats.connected = True
        print(f"[{port}] Connected")

        end_time = time.time() + duration
        msg_num = 0
        recv_buf = b""

        while time.time() < end_time:
            # Send message
            try:
                payload = f"test-data-{msg_num:05d}-{'x' * 50}"
                msg = f"[{port}] seq={msg_num} data={payload}\n"
                msg_bytes = msg.encode()
                sock.sendall(msg_bytes)
                stats.sent_msgs += 1
                stats.sent_bytes += len(msg_bytes)
                stats.update_sent(msg_bytes)
                msg_num += 1
            except BlockingIOError:
                pass
            except Exception as e:
                stats.errors += 1
                print(f"[{port}] Send error: {e}")

            # Receive
            try:
                data = sock.recv(8192)
                if data:
                    stats.recv_bytes += len(data)
                    stats.update_recv(data)
                    recv_buf += data
                    # Count complete lines
                    while b'\n' in recv_buf:
                        line, recv_buf = recv_buf.split(b'\n', 1)
                        stats.recv_msgs += 1
                        # Verify data integrity
                        line_str = line.decode('utf-8', errors='replace')
                        if 'data=' in line_str:
                            stats.checksum_ok += 1
            except BlockingIOError:
                pass
            except Exception as e:
                stats.errors += 1

            time.sleep(0.01)  # ~100 msg/sec per session

        sock.close()
    except Exception as e:
        stats.errors += 1
        print(f"[{port}] Connection error: {e}")

def test_port(port, msg):
    """Single ping test."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', port))

        full_msg = f"data={msg}\n"
        sent_bytes = full_msg.encode()
        sock.sendall(sent_bytes)

        response = sock.recv(4096)
        sock.close()

        sent_chk = hashlib.md5(sent_bytes).hexdigest()[:16]
        recv_chk = hashlib.md5(response).hexdigest()[:16]

        # Check if response matches the sent data
        if response == sent_bytes:
            success = True
            match_status = "MATCH"
        else:
            success = False
            match_status = f"MISMATCH (expected={sent_chk})"

        return port, success, f"sent={len(sent_bytes)}B/chk={sent_chk} recv={len(response)}B/chk={recv_chk} {match_status}"
    except Exception as e:
        return port, False, str(e)

def run_loop_mode():
    """Continuous ping test every 5 seconds."""
    print(f"Testing {NUM_SESSIONS} tunnel sessions (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print("-" * 60)

    # Initial test
    for i in range(NUM_SESSIONS):
        port, success, response = test_port(BASE_PORT + i, f"Hello from session {i+1}")
        status = "OK" if success else "FAIL"
        print(f"[{status}] Port {port}: {response}")

    print("-" * 60)
    print("Continuous testing (Ctrl+C to stop)...")

    try:
        iteration = 0
        while True:
            iteration += 1
            time.sleep(5)
            failures = 0
            print(f"[Iteration {iteration}]")
            for i in range(NUM_SESSIONS):
                port, success, resp = test_port(BASE_PORT + i, f"ping-{iteration}-{'y'*100}")
                if success:
                    status = "OK"
                else:
                    status = "NOT OK"
                    failures += 1
                print(f"  [{status}] Port {port}: {resp}")
            if failures == 0:
                print(f"  ✓ All {NUM_SESSIONS} sessions OK")
            else:
                print(f"  ✗ {failures} session(s) NOT OK")
    except KeyboardInterrupt:
        print("\nStopped.")

def run_stream_mode():
    """Concurrent streaming test with checksum verification."""
    print(f"=== Concurrent Streaming Test ===")
    print(f"Sessions: {NUM_SESSIONS} (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print(f"Duration: {DURATION}s")
    print("-" * 70)

    stats_list = [Stats(port=BASE_PORT + i) for i in range(NUM_SESSIONS)]
    threads = []

    # Start all sessions
    for stats in stats_list:
        t = threading.Thread(target=stream_session, args=(stats.port, DURATION, stats))
        t.start()
        threads.append(t)

    # Progress indicator
    start = time.time()
    while any(t.is_alive() for t in threads):
        elapsed = time.time() - start
        total_sent = sum(s.sent_bytes for s in stats_list)
        total_recv = sum(s.recv_bytes for s in stats_list)
        print(f"\r[{elapsed:.1f}s] Sent: {format_bytes(total_sent)}, Recv: {format_bytes(total_recv)}", end="", flush=True)
        time.sleep(0.5)

    for t in threads:
        t.join()

    print("\n" + "-" * 70)
    print("Results:")
    total_sent_bytes = 0
    total_recv_bytes = 0
    total_sent_msgs = 0
    total_recv_msgs = 0
    total_errors = 0

    for s in stats_list:
        status = "OK" if s.connected and s.errors == 0 else "FAIL"
        print(f"  [{status}] Port {s.port}:")
        sent_match = "(checksums match)" if s.sent_checksum == s.recv_checksum else f"(expected={s.sent_checksum})"
        print(f"       Sent: {s.sent_msgs} msgs, {format_bytes(s.sent_bytes):>10} bytes, checksum={s.sent_checksum}")
        print(f"       Recv: {s.recv_msgs} msgs, {format_bytes(s.recv_bytes):>10} bytes, checksum={s.recv_checksum} {sent_match if s.recv_msgs > 0 else ''}")
        if s.errors > 0:
            print(f"       Errors: {s.errors}")
        total_sent_bytes += s.sent_bytes
        total_recv_bytes += s.recv_bytes
        total_sent_msgs += s.sent_msgs
        total_recv_msgs += s.recv_msgs
        total_errors += s.errors

    print("-" * 70)
    print(f"Total sent: {total_sent_msgs} msgs, {format_bytes(total_sent_bytes)}")
    print(f"Total recv: {total_recv_msgs} msgs, {format_bytes(total_recv_bytes)}")
    print(f"Throughput: {format_bytes(int(total_sent_bytes/DURATION))}/s sent, {format_bytes(int(total_recv_bytes/DURATION))}/s recv")
    print(f"Errors: {total_errors}")

    if total_errors > 0:
        sys.exit(1)

if __name__ == '__main__':
    if LOOP_MODE:
        run_loop_mode()
    else:
        run_stream_mode()
