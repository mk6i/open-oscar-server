#!/usr/bin/env python3
"""
Reproduces a zombie session bug in the TOC server.

The bug: there is a race window between RegisterBOSSession (which creates a
session and makes it visible to concurrent logins) and the OnSessionClose
callback registration. If a second login evicts the session during this window,
the default no-op OnSessionClose runs, RemoveSession is never called, the
session slot's `removed` channel is never closed, and the user is permanently
locked out until server restart.

Prerequisites:
  - Server running on 127.0.0.1:9898 (TOC) and 127.0.0.1:8080 (API)
  - User "toctest1" exists (create via: curl -X POST
    http://127.0.0.1:8080/user -d '{"screen_name":"toctest1","password":"testpass1"}')

Usage:
  python3 scripts/repro_zombie_session.py
"""

import json
import socket
import struct
import subprocess
import sys
import threading
import time

HOST = "127.0.0.1"
TOC_PORT = 9898
API_PORT = 8080
USER = "toctest1"
PASS = "testpass1"
ROAST = "Tic/Toc"


def roast_password(password):
    result = []
    for i, ch in enumerate(password):
        xored = ord(ch) ^ ord(ROAST[i % len(ROAST)])
        result.append(f"{xored:02x}")
    return "0x" + "".join(result)


def send_flap(sock, frame_type, seq, payload):
    data = payload.encode("ascii") if isinstance(payload, str) else payload
    if frame_type == 2:
        data += b"\x00"
    header = struct.pack("!BBHH", 0x2A, frame_type, seq, len(data))
    sock.sendall(header + data)
    return seq + 1


def recv_flap(sock, timeout=5):
    sock.settimeout(timeout)
    header = b""
    while len(header) < 6:
        chunk = sock.recv(6 - len(header))
        if not chunk:
            raise ConnectionError("connection closed")
        header += chunk
    _, frame_type, seq, length = struct.unpack("!BBHH", header)
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise ConnectionError("connection closed")
        payload += chunk
    return frame_type, seq, payload


def recv_all(sock, timeout=2):
    msgs = []
    while True:
        try:
            ft, _, payload = recv_flap(sock, timeout=timeout)
            if ft == 2:
                msgs.append(payload.decode("ascii", errors="replace").rstrip("\x00"))
        except (socket.timeout, ConnectionError, OSError):
            break
    return msgs


def toc_login(user, pw):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, TOC_PORT))
    sock.settimeout(5)
    sock.sendall(b"FLAPON\r\n\r\n")
    recv_flap(sock)
    sn = user.lower().replace(" ", "").encode("ascii")
    signon_payload = struct.pack("!IHH", 1, 1, len(sn)) + sn
    seq = send_flap(sock, 1, 0, signon_payload)
    roasted = roast_password(pw)
    cmd = f'toc_signon login.oscar.aol.com 5190 {user} {roasted} english "TIC:Test"'
    seq = send_flap(sock, 2, seq, cmd)
    msgs = recv_all(sock, timeout=2)
    return sock, seq, msgs


def check_sessions():
    r = subprocess.run(
        ["curl", "-s", f"http://{HOST}:{API_PORT}/session"],
        capture_output=True,
        text=True,
    )
    return json.loads(r.stdout)


def main():
    print("=" * 60)
    print("Zombie Session Reproduction Script")
    print("=" * 60)
    print()

    # Verify server is reachable
    try:
        s = socket.create_connection((HOST, TOC_PORT), timeout=2)
        s.close()
    except OSError:
        print(f"ERROR: Cannot connect to TOC server at {HOST}:{TOC_PORT}")
        print("Start the server first: make run")
        sys.exit(1)

    # Verify user exists
    sessions = check_sessions()
    print(f"Server reachable. Active sessions: {sessions['count']}")
    print()

    # Step 1: Establish a fully-initialized session
    print("[Step 1] Login as toctest1, fully initialize session...")
    sock_a, seq_a, msgs_a = toc_login(USER, PASS)
    sign_on = any(m.startswith("SIGN_ON:") for m in msgs_a)
    if not sign_on:
        print(f"  ERROR: Login failed. Response: {msgs_a}")
        print("  Make sure user 'toctest1' exists with password 'testpass1'.")
        sys.exit(1)
    seq_a = send_flap(sock_a, 2, seq_a, "toc_add_buddy toctest2")
    seq_a = send_flap(sock_a, 2, seq_a, "toc_init_done")
    time.sleep(2)
    recv_all(sock_a, timeout=1)

    sessions = check_sessions()
    print(f"  Session A online. Active sessions: {sessions['count']}")
    print()

    # Step 2: Abruptly close the socket (no SIGNOFF frame)
    print("[Step 2] Abruptly closing socket (no SIGNOFF frame)...")
    sock_a.close()
    print("  Socket closed.")
    print()

    # Step 3: Immediately launch two parallel logins
    print("[Step 3] Launching two parallel logins for the same user...")
    print("  (Login B and Login C race to evict the stale session)")
    results = {}

    def login_worker(name):
        try:
            sock, seq, msgs = toc_login(USER, PASS)
            results[name] = ("ok", msgs)
            sock.close()
        except Exception as e:
            results[name] = ("error", str(e))

    t_b = threading.Thread(target=login_worker, args=("B",))
    t_c = threading.Thread(target=login_worker, args=("C",))
    t_b.start()
    t_c.start()
    t_b.join(timeout=15)
    t_c.join(timeout=15)

    for name in sorted(results):
        status, data = results[name]
        if status == "error":
            print(f"  Login {name}: ERROR - {data}")
        else:
            got_sign_on = any(m.startswith("SIGN_ON:") for m in data)
            print(f"  Login {name}: {'SIGN_ON' if got_sign_on else 'empty/failed'} - {[m[:50] for m in data]}")
    print()

    # Step 4: Wait for any cleanup, then verify the zombie
    print("[Step 4] Waiting 3 seconds for any pending cleanup...")
    time.sleep(3)
    sessions = check_sessions()
    print(f"  Active sessions: {sessions['count']}")
    print()

    # Step 5: Try a fresh login — if the bug was triggered, this will fail
    print("[Step 5] Attempting a fresh login (should succeed if no zombie)...")
    try:
        sock, seq, msgs = toc_login(USER, PASS)
        sign_on = any(m.startswith("SIGN_ON:") for m in msgs)
        if sign_on:
            print(f"  Login succeeded: {[m[:50] for m in msgs]}")
            print()
            print("  RESULT: Bug NOT triggered this run (race was won by the")
            print("  correct ordering). Re-run the script to try again.")
            sock.close()
        else:
            print(f"  Login returned empty/error: {msgs}")
            print()
            # Confirm it's permanent
            print("[Step 6] Waiting 10 seconds and trying once more...")
            time.sleep(10)
            sock2, _, msgs2 = toc_login(USER, PASS)
            sign_on2 = any(m.startswith("SIGN_ON:") for m in msgs2)
            if sign_on2:
                print(f"  Second attempt succeeded (cleanup was slow but finished)")
                sock2.close()
            else:
                print(f"  Second attempt also failed: {msgs2}")
                print()
                print("  *** ZOMBIE SESSION CONFIRMED ***")
                print()
                print("  The user 'toctest1' is permanently locked out.")
                print("  The /session endpoint shows 0 sessions, but AddSession")
                print("  keeps finding a stale session slot whose `removed`")
                print("  channel will never close.")
                print()
                print("  Root cause: Login C evicted Login B's session before B")
                print("  registered its OnSessionClose callback. The default")
                print("  no-op ran, RemoveSession was never called, and the")
                print("  session slot is stuck forever.")
                print()
                print("  Only a server restart will fix this.")
                sock2.close()
    except Exception as e:
        print(f"  Login attempt failed with exception: {e}")
        print()
        print("  *** ZOMBIE SESSION CONFIRMED ***")

    print()
    print("Check the server log for [DEBUG-RACE] lines (if using the")
    print("instrumented build) or 'context deadline exceeded' errors.")


if __name__ == "__main__":
    main()
