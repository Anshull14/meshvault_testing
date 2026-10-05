"""
MeshVault - ECDH Handshake + Encrypted Share Transfer Test
===========================================================
Device A (receiver/server): python handshake_test.py --receive --port 9100
Device B (sender/client):   python handshake_test.py --send --host 10.19.22.1 --port 9100
"""
from __future__ import annotations
import argparse, socket, sys, threading, time
from crypto.sss import split_secret, reconstruct_secret
from network.transfer import send_encrypted_share, receive_encrypted_share

SECRET = b"MeshVault-Test-Secret-1234567890"  # 32-byte demo secret

def run_receiver(port: int) -> None:
    print("[RECEIVER] Listening on port", port)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print("[RECEIVER] Waiting for sender to connect...")
    conn, addr = srv.accept()
    print("[RECEIVER] Connected from", addr)
    try:
        share = receive_encrypted_share(conn)
        print("[RECEIVER] ECDH handshake OK + share received!")
        print("[RECEIVER]   Share index (x):", share[0])
        print("[RECEIVER]   Share bytes (hex):", share[1].hex())
    finally:
        conn.close()
        srv.close()

def run_sender(host: str, port: int) -> None:
    print("[SENDER] Splitting secret into 2-of-2 shares...")
    shares = split_secret(SECRET, n=2, k=2)
    print("[SENDER] Share 0 (x={})  hex: {}".format(shares[0][0], shares[0][1].hex()))
    print("[SENDER] Share 1 (x={})  hex: {}".format(shares[1][0], shares[1][1].hex()))
    print("[SENDER] Sending share 1 to", host, "port", port, "via ECDH...")
    try:
        send_encrypted_share(host, port, shares[1])
        print("[SENDER] ECDH handshake OK + encrypted share sent!")
        print("[SENDER] Keeping share 0 locally (x={})".format(shares[0][0]))
        print("[SENDER] To reconstruct: combine share 0 + share 1 from receiver")
    except Exception as e:
        print("[SENDER] ERROR:", e)
        sys.exit(1)

def main() -> None:
    parser = argparse.ArgumentParser(description="MeshVault ECDH + Share Transfer Test")
    parser.add_argument("--receive", action="store_true", help="Run as receiver (server)")
    parser.add_argument("--send", action="store_true", help="Run as sender (client)")
    parser.add_argument("--host", default="", help="Receiver IP (sender mode)")
    parser.add_argument("--port", type=int, default=9100, help="TCP port (default: 9100)")
    args = parser.parse_args()

    if not args.receive and not args.send:
        parser.print_help()
        sys.exit(1)

    print("=" * 55)
    print("  MeshVault ECDH + Share Transfer Test")
    print("=" * 55)

    if args.receive:
        run_receiver(args.port)
    else:
        if not args.host:
            print("[ERROR] --host required in sender mode")
            sys.exit(1)
        run_sender(args.host, args.port)

if __name__ == "__main__":
    main()