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
    sent: int = 0
    received: int = 0
    errors: int = 0
    checksum_ok: int = 0
    checksum_fail: int = 0
    connected: bool = False
    sent_checksums: dict = field(default_factory=dict)  # msg_num -> checksum

def compute_checksum(data: bytes) -> str:
    """Compute MD5 checksum of data."""
    return hashlib.md5(data).hexdigest()[:8]

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
            # Send message with checksum
            try:
                # Format: [port] seq=N chk=XXXXXXXX data=<random padding>
                payload = f"test-data-{msg_num:05d}-{'x' * 50}"
                chk = compute_checksum(payload.encode())
                msg = f"[{port}] seq={msg_num} chk={chk} data={payload}\n"
                sock.sendall(msg.encode())
                stats.sent_checksums[msg_num] = (chk, payload)
                stats.sent += 1
                msg_num += 1
            except BlockingIOError:
                pass
            except Exception as e:
                stats.errors += 1
                print(f"[{port}] Send error: {e}")

            # Receive and verify
            try:
                data = sock.recv(8192)
                if data:
                    recv_buf += data
                    # Process complete lines
                    while b'\n' in recv_buf:
                        line, recv_buf = recv_buf.split(b'\n', 1)
                        stats.received += 1
                        line_str = line.decode('utf-8', errors='replace')

                        # Extract seq and checksum from echoed response
                        # Echo server returns: [Cxxx@time] ECHO: [port] seq=N chk=X data=...
                        seq_match = re.search(r'seq=(\d+)', line_str)
                        chk_match = re.search(r'chk=([a-f0-9]+)', line_str)
                        data_match = re.search(r'data=(.+)$', line_str)

                        if seq_match and chk_match and data_match:
                            seq = int(seq_match.group(1))
                            recv_chk = chk_match.group(1)
                            recv_data = data_match.group(1)

                            # Verify checksum
                            expected_chk = compute_checksum(recv_data.encode())
                            if recv_chk == expected_chk:
                                stats.checksum_ok += 1
                            else:
                                stats.checksum_fail += 1
                                print(f"[{port}] CHECKSUM MISMATCH seq={seq}: sent={recv_chk} computed={expected_chk}")
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
    """Single ping test with checksum."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', port))

        chk = compute_checksum(msg.encode())
        full_msg = f"chk={chk} data={msg}\n"
        sock.sendall(full_msg.encode())

        response = sock.recv(4096).decode().strip()
        sock.close()

        # Verify checksum in response
        data_match = re.search(r'data=(.+)$', response)
        if data_match:
            recv_data = data_match.group(1)
            recv_chk = compute_checksum(recv_data.encode())
            if recv_chk == chk:
                return port, True, f"{response[:50]} [CHK OK]"
            else:
                return port, False, f"{response[:50]} [CHK FAIL]"

        return port, True, response[:60]
    except Exception as e:
        return port, False, str(e)

def run_loop_mode():
    """Continuous ping test every 5 seconds."""
    print(f"Testing {NUM_SESSIONS} tunnel sessions (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print("-" * 50)

    # Initial test
    for i in range(NUM_SESSIONS):
        port, success, response = test_port(BASE_PORT + i, f"Hello from session {i+1}")
        status = "OK" if success else "FAIL"
        print(f"[{status}] Port {port}: {response}")

    print("-" * 50)
    print("Continuous testing (Ctrl+C to stop)...")

    try:
        iteration = 0
        while True:
            iteration += 1
            time.sleep(5)
            failures = 0
            for i in range(NUM_SESSIONS):
                port, success, resp = test_port(BASE_PORT + i, f"ping-{iteration}")
                if not success or "CHK FAIL" in resp:
                    failures += 1
                    print(f"[FAIL] Port {port} at iteration {iteration}: {resp}")
            if failures == 0:
                print(f"[{iteration}] All {NUM_SESSIONS} sessions OK (checksums verified)")
    except KeyboardInterrupt:
        print("\nStopped.")

def run_stream_mode():
    """Concurrent streaming test with checksum verification."""
    print(f"=== Concurrent Streaming Test (with checksums) ===")
    print(f"Sessions: {NUM_SESSIONS} (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print(f"Duration: {DURATION}s")
    print("-" * 50)

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
        total_sent = sum(s.sent for s in stats_list)
        total_recv = sum(s.received for s in stats_list)
        total_ok = sum(s.checksum_ok for s in stats_list)
        total_fail = sum(s.checksum_fail for s in stats_list)
        print(f"\r[{elapsed:.1f}s] Sent: {total_sent}, Recv: {total_recv}, ChkOK: {total_ok}, ChkFail: {total_fail}", end="", flush=True)
        time.sleep(0.5)

    for t in threads:
        t.join()

    print("\n" + "-" * 50)
    print("Results:")
    total_sent = 0
    total_recv = 0
    total_errors = 0
    total_chk_ok = 0
    total_chk_fail = 0

    for s in stats_list:
        chk_status = "CHK OK" if s.checksum_fail == 0 and s.checksum_ok > 0 else "CHK FAIL" if s.checksum_fail > 0 else "NO CHK"
        status = "OK" if s.connected and s.errors == 0 and s.checksum_fail == 0 else "FAIL"
        print(f"  [{status}] Port {s.port}: sent={s.sent}, recv={s.received}, chk_ok={s.checksum_ok}, chk_fail={s.checksum_fail}, errors={s.errors} [{chk_status}]")
        total_sent += s.sent
        total_recv += s.received
        total_errors += s.errors
        total_chk_ok += s.checksum_ok
        total_chk_fail += s.checksum_fail

    print("-" * 50)
    print(f"Total: sent={total_sent}, recv={total_recv}, errors={total_errors}")
    print(f"Checksums: {total_chk_ok} OK, {total_chk_fail} FAILED")
    print(f"Throughput: ~{total_sent/DURATION:.0f} msg/sec sent, ~{total_recv/DURATION:.0f} msg/sec recv")

    if total_chk_fail > 0:
        print("\n*** DATA INTEGRITY ERRORS DETECTED ***")
        sys.exit(1)
    elif total_chk_ok > 0:
        print("\n*** ALL CHECKSUMS VERIFIED ***")

    if total_errors > 0:
        sys.exit(1)

if __name__ == '__main__':
    if LOOP_MODE:
        run_loop_mode()
    else:
        run_stream_mode()
