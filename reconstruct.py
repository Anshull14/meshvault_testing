"""
MeshVault - Reconstruct Secret (Host)
======================================
1. Host enters the threshold (k) needed to reconstruct.
2. Host advertises a recovery service on LAN.
3. Host waits for `k` peers to connect and send their shares.
4. Once `k` shares are received, the secret is reconstructed.
"""
from __future__ import annotations
import argparse, socket, sys
from network.discovery import PeerDiscovery, _get_local_ip
from network.transfer import receive_encrypted_share
from crypto.sss import reconstruct_secret

def main():
    parser = argparse.ArgumentParser(description="MeshVault Secret Reconstructor")
    parser.add_argument("--name", default="RecoveryHost", help="Name to advertise")
    parser.add_argument("--port", type=int, default=9500, help="TCP port to listen on")
    args = parser.parse_args()

    print("=" * 54)
    print("  MeshVault - Reconstruct Secret (Host)")
    print("=" * 54)

    try:
        k = int(input("\nEnter threshold (k) needed to recover the secret: ").strip())
        if k < 1:
            raise ValueError
    except ValueError:
        print("[ERROR] k must be a positive integer.")
        sys.exit(1)

    local_ip = _get_local_ip()
    print(f"\n[RECOVER] Local IP    : {local_ip}")
    print(f"[RECOVER] Listening on: port {args.port}")

    pd = PeerDiscovery()
    try:
        # Advertise a special recovery service name so peers know where to send
        pd.advertise_service(
            name=args.name,
            port=args.port,
            metadata={"version": "0.1", "device": socket.gethostname(), "type": "recovery"},
        )
        print(f"[RECOVER] Advertising on LAN as '{args.name}'...")
    except KeyboardInterrupt:
        pd.stop()
        sys.exit(0)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(5)
    srv.settimeout(1.0)
    print(f"[RECOVER] Waiting for {k} peers to send their shares... (Ctrl+C to stop)\n")

    shares = []
    try:
        while len(shares) < k:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue

            print(f"[RECOVER] Peer connected from {addr[0]}...")
            try:
                x, share_bytes = receive_encrypted_share(conn)
                shares.append((x, share_bytes))
                print(f"          -> Received share x={x} ({len(shares)}/{k})")
            except Exception as e:
                print(f"          -> [ERROR] Failed to receive share: {e}")
            finally:
                conn.close()

        print("\n[RECOVER] Required number of shares received!")
        print("[RECOVER] Reconstructing secret...")
        
        secret = reconstruct_secret(shares)
        
        print("\n" + "=" * 54)
        print(f"  RECOVERED SECRET: {secret.decode('utf-8', errors='replace')}")
        print("=" * 54 + "\n")

    except KeyboardInterrupt:
        print("\n[RECOVER] Cancelled.")
    except Exception as e:
        print(f"\n[RECOVER] Error during reconstruction: {e}")
    finally:
        srv.close()
        pd.stop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)