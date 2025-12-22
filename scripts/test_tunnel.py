#!/usr/bin/env python3
"""
Test multiple tunnel sessions with ping or streaming modes.

Usage:
    python3 test_tunnel.py NUM [OPTIONS]

Options:
    --port PORT      Base port (default: 7001)
    --stream SECS    Stream for SECS seconds (default: ping mode)
    --loop           Repeat continuously

Examples:
    python3 test_tunnel.py 3              # Ping 3 ports (7001-7003)
    python3 test_tunnel.py 3 --loop       # Ping every 5s
    python3 test_tunnel.py 3 --stream 10  # Stream for 10s
    python3 test_tunnel.py 3 --stream 10 --loop  # Stream 10s repeatedly
"""

import socket
import sys
import time
import threading
import hashlib
from dataclasses import dataclass, field

def parse_args():
    args = sys.argv[1:]
    if not args or args[0] in ['-h', '--help']:
        print(__doc__)
        sys.exit(0)

    # First positional arg is number of sessions
    num_sessions = int(args[0]) if args and not args[0].startswith('--') else 3

    # Parse flags
    loop = '--loop' in args

    base_port = 7001
    if '--port' in args:
        idx = args.index('--port')
        if idx + 1 < len(args):
            base_port = int(args[idx + 1])

    stream_duration = None
    if '--stream' in args:
        idx = args.index('--stream')
        if idx + 1 < len(args) and not args[idx + 1].startswith('--'):
            stream_duration = int(args[idx + 1])
        else:
            stream_duration = 5  # default

    return base_port, num_sessions, stream_duration, loop

BASE_PORT, NUM_SESSIONS, STREAM_DURATION, LOOP_MODE = parse_args()

@dataclass
class Stats:
    port: int
    sent_msgs: int = 0
    recv_msgs: int = 0
    sent_bytes: int = 0
    recv_bytes: int = 0
    errors: int = 0
    verified: int = 0
    corrupted: int = 0
    connected: bool = False
    sent_checksum: str = ""
    recv_checksum: str = ""
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
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n/1024:.1f}KB"
    else:
        return f"{n/(1024*1024):.2f}MB"

first_connect_lock = threading.Lock()
first_connect_done = False

def stream_session(port: int, duration: float, stats: Stats):
    """Stream data through a tunnel for the specified duration."""
    global first_connect_done
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', port))
        sock.setblocking(False)
        stats.connected = True
        with first_connect_lock:
            if not first_connect_done:
                print(f"\n[{port}] Connected")
                first_connect_done = True
            else:
                print(f"[{port}] Connected")

        end_time = time.time() + duration
        msg_num = 0
        recv_buf = b""
        pending_payloads = {}

        while time.time() < end_time:
            try:
                payload = f"SEQ{msg_num:06d}DATA{'x' * 40}"
                msg = f"{payload}\n"
                msg_bytes = msg.encode()
                sock.sendall(msg_bytes)
                pending_payloads[msg_num] = payload
                stats.sent_msgs += 1
                stats.sent_bytes += len(msg_bytes)
                stats.update_sent(msg_bytes)
                msg_num += 1
            except BlockingIOError:
                pass
            except Exception:
                stats.errors += 1

            try:
                data = sock.recv(8192)
                if data:
                    stats.recv_bytes += len(data)
                    stats.update_recv(data)
                    recv_buf += data
                    while b'\n' in recv_buf:
                        line, recv_buf = recv_buf.split(b'\n', 1)
                        stats.recv_msgs += 1
                        line_str = line.decode('utf-8', errors='replace')
                        found = False
                        for seq, payload in list(pending_payloads.items()):
                            if payload in line_str:
                                stats.verified += 1
                                del pending_payloads[seq]
                                found = True
                                break
                        if not found and 'SEQ' in line_str:
                            stats.corrupted += 1
            except BlockingIOError:
                pass
            except Exception:
                stats.errors += 1

            time.sleep(0.01)

        sock.close()
    except Exception as e:
        stats.errors += 1
        print(f"[{port}] Error: {e}")

def test_port(port, iteration):
    """Single ping test - verify payload roundtrip."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', port))

        payload = f"PING{iteration:04d}PORT{port}TEST{'z' * 50}"
        sock.sendall(f"{payload}\n".encode())
        sent_bytes = len(payload) + 1

        response = sock.recv(4096).decode('utf-8', errors='replace').strip()
        sock.close()
        recv_bytes = len(response)

        if payload in response:
            return port, True, f"sent={sent_bytes}B recv={recv_bytes}B OK"
        else:
            preview = response[:60] if len(response) > 60 else response
            return port, False, f"recv={recv_bytes}B got: {repr(preview)}"
    except Exception as e:
        return port, False, str(e)

def run_ping_once():
    """Single ping test."""
    print(f"Pinging {NUM_SESSIONS} sessions (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print("-" * 60)
    failures = 0
    for i in range(NUM_SESSIONS):
        port, success, response = test_port(BASE_PORT + i, 0)
        status = "OK" if success else "FAIL"
        print(f"[{status}] Port {port}: {response}")
        if not success:
            failures += 1
    print("-" * 60)
    if failures == 0:
        print(f"✓ All {NUM_SESSIONS} sessions OK")
    else:
        print(f"✗ {failures}/{NUM_SESSIONS} session(s) failed")
        sys.exit(1)

def run_ping_loop():
    """Continuous ping test every 5 seconds."""
    run_ping_once()
    print("\nContinuous testing (Ctrl+C to stop)...")
    try:
        iteration = 0
        while True:
            iteration += 1
            time.sleep(5)
            failures = 0
            print(f"[Iteration {iteration}]")
            for i in range(NUM_SESSIONS):
                port, success, resp = test_port(BASE_PORT + i, iteration)
                status = "OK" if success else "FAIL"
                print(f"  [{status}] Port {port}: {resp}")
                if not success:
                    failures += 1
            if failures == 0:
                print(f"  ✓ All {NUM_SESSIONS} sessions OK")
            else:
                print(f"  ✗ {failures} session(s) failed")
    except KeyboardInterrupt:
        print("\nStopped.")

def run_stream_once():
    """Single streaming test."""
    global first_connect_done
    first_connect_done = False
    print(f"=== Streaming Test ({STREAM_DURATION}s) ===")
    print(f"Sessions: {NUM_SESSIONS} (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print("-" * 70)

    stats_list = [Stats(port=BASE_PORT + i) for i in range(NUM_SESSIONS)]
    threads = []

    for stats in stats_list:
        t = threading.Thread(target=stream_session, args=(stats.port, STREAM_DURATION, stats))
        t.start()
        threads.append(t)

    start = time.time()
    while any(t.is_alive() for t in threads):
        elapsed = time.time() - start
        total_sent = sum(s.sent_bytes for s in stats_list)
        total_recv = sum(s.recv_bytes for s in stats_list)
        total_verified = sum(s.verified for s in stats_list)
        print(f"\r[{elapsed:.1f}s] Sent: {format_bytes(total_sent)}, Recv: {format_bytes(total_recv)}, Verified: {total_verified}", end="", flush=True)
        time.sleep(0.5)

    for t in threads:
        t.join()

    print("\n" + "-" * 70)
    print("Results:")
    total_sent_bytes = 0
    total_recv_bytes = 0
    total_verified = 0
    total_corrupted = 0
    total_errors = 0

    for s in stats_list:
        status = "OK" if s.connected and s.errors == 0 and s.corrupted == 0 else "FAIL"
        print(f"  [{status}] Port {s.port}: {format_bytes(s.sent_bytes)}↑ {format_bytes(s.recv_bytes)}↓ msgs={s.sent_msgs}/{s.recv_msgs} verified={s.verified} err={s.errors}")
        total_sent_bytes += s.sent_bytes
        total_recv_bytes += s.recv_bytes
        total_verified += s.verified
        total_corrupted += s.corrupted
        total_errors += s.errors

    print("-" * 70)
    print(f"Total: {format_bytes(total_sent_bytes)} sent, {format_bytes(total_recv_bytes)} recv, {total_verified} verified")
    print(f"Throughput: {format_bytes(int(total_sent_bytes/STREAM_DURATION))}/s")

    if total_corrupted > 0 or total_errors > 0:
        print("*** ERRORS DETECTED ***")
        return False
    else:
        print("*** ALL OK ***")
        return True

def run_stream_loop():
    """Continuous streaming test."""
    print(f"Streaming {STREAM_DURATION}s every round (Ctrl+C to stop)...\n")
    try:
        iteration = 0
        while True:
            iteration += 1
            print(f"\n{'='*70}")
            print(f"Round {iteration}")
            print(f"{'='*70}")
            success = run_stream_once()
            if not success:
                print("Continuing despite errors...")
            print(f"\nWaiting 3s before next round...")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == '__main__':
    if STREAM_DURATION:
        if LOOP_MODE:
            run_stream_loop()
        else:
            run_stream_once()
    else:
        if LOOP_MODE:
            run_ping_loop()
        else:
            run_ping_once()
