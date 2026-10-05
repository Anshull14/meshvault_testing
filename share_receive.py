"""
MeshVault - Share Receiver (Peer/Client)
=========================================
1. Advertises itself on LAN so the host can discover it
2. Opens a TCP port and waits for the host to connect
3. Does ECDH handshake automatically
4. Decrypts and saves the received share

Usage:
    python share_receive.py
    python share_receive.py --name DeviceB --port 9400
"""
from __future__ import annotations
import argparse, socket, sys
from network.discovery import PeerDiscovery, _get_local_ip
from network.transfer import receive_encrypted_share


def main():
    parser = argparse.ArgumentParser(description="MeshVault Share Receiver")
    parser.add_argument("--name",    default=socket.gethostname(), help="Name to advertise on LAN")
    parser.add_argument("--port",    type=int, default=9400,       help="TCP port to listen on")
    args = parser.parse_args()

    print("=" * 54)
    print("  MeshVault - Share Receiver (Peer)")
    print("=" * 54)

    local_ip = _get_local_ip()
    print(f"\n[PEER] Device name : {args.name}")
    print(f"[PEER] Local IP    : {local_ip}")
    print(f"[PEER] Listening on: port {args.port}")

    # ── Advertise on LAN ──────────────────────────────────────
    pd = PeerDiscovery()
    try:
        pd.advertise_service(
            name=args.name,
            port=args.port,
            metadata={"version": "0.1", "device": socket.gethostname()},
        )
        print(f"[PEER] Advertising on LAN as '{args.name}'...")
    except KeyboardInterrupt:
        pd.stop()
        print("\n[MeshVault] Shutting down cleanly.")
        sys.exit(0)

    # ── Open TCP listener ─────────────────────────────────────
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)
    srv.settimeout(1.0)
    print("[PEER] Waiting for host to connect and send share... (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                conn, addr = srv.accept()
                break
            except socket.timeout:
                continue

        print(f"[PEER] Host connected from {addr[0]}")
        print("[PEER] Performing ECDH handshake and receiving encrypted share...")

        x, share_bytes = receive_encrypted_share(conn)
        conn.close()

        print(f"\n[PEER] Share received successfully!")
        print(f"       Share index (x)  : {x}")
        print(f"       Share size       : {len(share_bytes)} bytes")
        print(f"       Share data (hex) : {share_bytes.hex()}")

        # Save share to file
        filename = f"share_{x}_{args.name}.bin"
        with open(filename, "wb") as f:
            import struct
            f.write(struct.pack(">I", x))   # 4-byte x value
            f.write(share_bytes)
        print(f"\n[PEER] Share saved to: {filename}")
        print("[PEER] Keep this file safe! It is your piece of the secret.")

    except KeyboardInterrupt:
        print("\n[PEER] Shutting down cleanly.")
    except Exception as e:
        print(f"[PEER] Error: {e}")
        sys.exit(1)
    finally:
        srv.close()
        pd.stop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[MeshVault] Shutting down cleanly.")
        sys.exit(0)