"""
MeshVault - Return Share (Peer)
================================
1. Finds local share (.bin) files on the device.
2. Discovers the Recovery Host on the LAN.
3. Encrypts and sends the share back to the host.
"""
from __future__ import annotations
import argparse, glob, socket, struct, sys, time
from network.discovery import PeerDiscovery, _get_local_ip
from network.transfer import send_encrypted_share

def discover_recovery_host(timeout: int) -> dict | None:
    local_ip = _get_local_ip()
    print(f"[DISCOVER] Local IP: {local_ip}")
    print(f"[DISCOVER] Scanning LAN for Recovery Host ({timeout}s)...")
    
    pd = PeerDiscovery()
    peers = pd.find_peers(timeout_seconds=timeout)
    pd.stop()
    
    # Filter for peers that advertised as recovery
    for p in peers:
        if p["properties"].get("type") == "recovery" or "RecoveryHost" in p["name"]:
            return p
    return None

def load_share(filepath: str) -> tuple[int, bytes]:
    with open(filepath, "rb") as f:
        x_data = f.read(4)
        if len(x_data) != 4:
            raise ValueError("Invalid share file format")
        x = struct.unpack(">I", x_data)[0]
        share_bytes = f.read()
        return (x, share_bytes)

def main():
    parser = argparse.ArgumentParser(description="MeshVault Return Share")
    parser.add_argument("--timeout", type=int, default=10, help="Discovery timeout")
    args = parser.parse_args()

    print("=" * 54)
    print("  MeshVault - Return Share (Peer)")
    print("=" * 54)

    # 1. Find local shares
    share_files = glob.glob("share_*.bin")
    if not share_files:
        print("[ERROR] No share files (*.bin) found in the current directory.")
        sys.exit(1)

    if len(share_files) == 1:
        filepath = share_files[0]
        print(f"[PEER] Found share: {filepath}")
    else:
        print("[PEER] Found multiple shares:")
        for i, f in enumerate(share_files):
            print(f"  [{i}] {f}")
        idx = int(input("Select share number to send: ").strip())
        filepath = share_files[idx]

    try:
        share = load_share(filepath)
    except Exception as e:
        print(f"[ERROR] Failed to load share: {e}")
        sys.exit(1)

    # 2. Discover Host
    host = discover_recovery_host(args.timeout)
    if not host:
        print("\n[ERROR] Recovery Host not found on LAN.")
        print("        Make sure the host is running 'python reconstruct.py'.")
        sys.exit(1)

    host_ip = host["host"]
    host_port = host["port"]
    host_name = host["name"].split(".")[0]
    
    print(f"\n[PEER] Found Recovery Host '{host_name}' at {host_ip}:{host_port}")
    print("[PEER] Connecting and sending share via ECDH + AES-GCM...")

    # 3. Send Share
    try:
        send_encrypted_share(host_ip, host_port, share)
        print("[PEER] SUCCESS: Share securely delivered to the host!")
    except ConnectionRefusedError:
        print("[ERROR] Connection refused. The host might not be accepting shares yet.")
    except Exception as e:
        print(f"[ERROR] Failed to send share: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[MeshVault] Cancelled.")
        sys.exit(0)