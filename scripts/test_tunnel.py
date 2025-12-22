#!/usr/bin/env python3
"""
Test multiple tunnel sessions by sending data through each.

Usage:
    python3 test_tunnel.py [BASE_PORT] [NUM_SESSIONS]

Example:
    python3 test_tunnel.py 7001 3
    # Tests ports 7001, 7002, 7003
"""

import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7001
NUM_SESSIONS = int(sys.argv[2]) if len(sys.argv) > 2 else 3
TIMEOUT = 10

def test_port(port, msg):
    """Send a message through the tunnel and check response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect(('127.0.0.1', port))
        sock.sendall(f"{msg}\n".encode())
        response = sock.recv(4096).decode().strip()
        sock.close()
        return port, True, response
    except Exception as e:
        return port, False, str(e)

def main():
    print(f"Testing {NUM_SESSIONS} tunnel sessions (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print("-" * 50)

    results = []
    with ThreadPoolExecutor(max_workers=NUM_SESSIONS) as executor:
        futures = {
            executor.submit(test_port, BASE_PORT + i, f"Hello from session {i+1}"): i
            for i in range(NUM_SESSIONS)
        }
        for future in as_completed(futures):
            port, success, response = future.result()
            results.append((port, success, response))
            status = "OK" if success else "FAIL"
            print(f"[{status}] Port {port}: {response[:60]}")

    print("-" * 50)
    passed = sum(1 for _, s, _ in results if s)
    print(f"Results: {passed}/{NUM_SESSIONS} sessions working")

    # Continuous test mode
    if "--loop" in sys.argv:
        print("\nContinuous testing (Ctrl+C to stop)...")
        iteration = 0
        while True:
            iteration += 1
            time.sleep(5)
            failures = 0
            for i in range(NUM_SESSIONS):
                port, success, _ = test_port(BASE_PORT + i, f"ping-{iteration}")
                if not success:
                    failures += 1
                    print(f"[FAIL] Port {port} at iteration {iteration}")
            if failures == 0:
                print(f"[{iteration}] All {NUM_SESSIONS} sessions OK")

if __name__ == '__main__':
    main()
