"""
MeshVault - Share Sender (Host)
================================
1. Enter your secret password
2. Enter n (total shares) and k (threshold)
3. Discovers peers on LAN who are advertising (running share_receive.py)
4. Does ECDH handshake with each peer
5. Encrypts each share with AES-256-GCM and sends it

Usage:
    python share_send.py
    python share_send.py --port 9400 --timeout 10
"""
from __future__ import annotations
import argparse, socket, sys
from network.discovery import PeerDiscovery, _get_local_ip
from network.transfer import send_encrypted_share
from crypto.sss import split_secret


def discover_peers(timeout: int) -> list[dict]:
    local_ip = _get_local_ip()
    print(f"[DISCOVER] Local IP: {local_ip}")
    print(f"[DISCOVER] Scanning LAN for peers ({timeout}s)...")
    pd    = PeerDiscovery()
    peers = pd.find_peers(timeout_seconds=timeout)
    pd.stop()
    return peers


def main():
    parser = argparse.ArgumentParser(description="MeshVault Share Sender")
    parser.add_argument("--timeout", type=int, default=10, help="Discovery scan timeout (seconds)")
    args = parser.parse_args()

    print("=" * 54)
    print("  MeshVault - Secret Share Sender (Host)")
    print("=" * 54)

    # ── Step 1: Get secret ────────────────────────────────────
    secret_str = input("\nEnter the secret password to share (visible): ").strip()
    if not secret_str:
        print("[ERROR] Secret cannot be empty.")
        sys.exit(1)
    secret_bytes = secret_str.encode("utf-8")

    # ── Step 2: Get n and k ───────────────────────────────────
    try:
        n = int(input("Enter total number of shares (n): ").strip())
        k = int(input("Enter threshold to reconstruct (k): ").strip())
    except ValueError:
        print("[ERROR] n and k must be integers.")
        sys.exit(1)

    if not (1 <= k <= n <= 255):
        print("[ERROR] Must satisfy: 1 <= k <= n <= 255")
        sys.exit(1)

    # ── Step 3: Split secret ──────────────────────────────────
    print(f"\n[SPLIT] Splitting secret into {n} shares (threshold: {k})...")
    shares = split_secret(secret_bytes, n, k)
    print(f"[SPLIT] Done. Generated {len(shares)} shares.")

    # ── Step 4: Discover peers ────────────────────────────────
    peers = discover_peers(args.timeout)

    if not peers:
        print("\n[ERROR] No peers found on LAN.")
        print("        Make sure peers are running: python share_receive.py")
        sys.exit(1)

    print(f"\n[DISCOVER] Found {len(peers)} peer(s):")
    for i, p in enumerate(peers):
        name   = p["name"].split(".")[0]
        device = p["properties"].get("device", "?")
        print(f"  [{i}]  {name}  ->  {p['host']}:{p['port']}  ({device})")

    if len(peers) < n:
        print(f"\n[WARN] Only {len(peers)} peer(s) found but n={n}.")
        print(f"       Will send {len(peers)} share(s) only.")
        n = len(peers)
        shares = shares[:n]

    # ── Step 5: Send shares ───────────────────────────────────
    print(f"\n[SEND] Sending {n} encrypted share(s)...\n")
    for i, (share, peer) in enumerate(zip(shares, peers)):
        name = peer["name"].split(".")[0]
        host = peer["host"]
        port = peer["port"]
        x, data = share
        print(f"  -> Peer [{i}] '{name}' ({host}:{port})  |  share index x={x}  |  {len(data)} bytes")
        try:
            send_encrypted_share(host, port, share)
            print(f"     [OK] Share sent successfully.")
        except Exception as e:
            print(f"     [FAIL] {e}")

    print("\n[DONE] All shares distributed.")
    print(f"[INFO] Any {k} of {n} peers can reconstruct the secret.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[MeshVault] Cancelled.")
        sys.exit(0)