"""
MeshVault - ECDH Handshake Test
================================
Option 1: python ecdh_test.py --server --name DeviceA --port 9300 [--verbose]
Option 2: python ecdh_test.py --client [--verbose]
"""
from __future__ import annotations
import argparse, base64, socket, sys
from cryptography.hazmat.primitives import serialization
from network.discovery import PeerDiscovery, _get_local_ip
from network.transfer import send_message, receive_message
from crypto.channel import SecureChannel

def _print_crypto_details(channel: SecureChannel, peer_pub_bytes: bytes, shared_key: bytes):
    priv_bytes = channel.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = channel.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    print("\n--- [VERBOSE] Cryptographic Keys ---")
    print("My Private Key (hex): ", priv_bytes.hex())
    print("My Public Key (hex): ", pub_bytes.hex())
    print("Peer's Public Key (hex): ", peer_pub_bytes.hex())
    print("Computed Shared Key (hex):", shared_key.hex())
    print("------------------------------------\n")

def run_server(name, port, verbose):
    local_ip = _get_local_ip()
    print("[SERVER] Advertising as", repr(name), "on", local_ip, "port", port)

    pd = PeerDiscovery()
    try:
        pd.advertise_service(name=name, port=port, metadata={"version": "0.1", "device": socket.gethostname()})
    except KeyboardInterrupt:
        pd.stop()
        print("\n[MeshVault] Shutting down cleanly.")
        sys.exit(0)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(1.0)
    print("[SERVER] Listening for ECDH handshake... (Ctrl+C to stop)\n")

    try:
        conn = None
        while True:
            try:
                conn, addr = srv.accept()
                break
            except socket.timeout:
                continue
                
        print("[SERVER] Peer connected from", addr[0])
        
        channel = SecureChannel()
        my_pub = channel.generate_key_pair()
        
        msg = receive_message(conn)
        peer_pub = base64.b64decode(msg['public_key'])
        
        send_message(conn, {'type': 'KEY_EXCHANGE', 'public_key': base64.b64encode(my_pub).decode()})
        
        shared = channel.compute_shared_secret(peer_pub)
        
        if verbose:
            _print_crypto_details(channel, peer_pub, shared)
            
        fingerprint = shared[:8].hex()
        print("[SERVER] ECDH Handshake complete!")
        print("[SERVER] Shared key fingerprint:", fingerprint)
        print("[SERVER] >>> Both devices must show the SAME fingerprint <<<")
        conn.close()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
    finally:
        srv.close()
        pd.stop()


def discover_and_pick(timeout):
    local_ip = _get_local_ip()
    print("[DISCOVER] Local IP:", local_ip)
    print("[DISCOVER] Scanning LAN for peers (" + str(timeout) + "s)...")
    pd = PeerDiscovery()
    peers = pd.find_peers(timeout_seconds=timeout)
    pd.stop()

    if not peers:
        print("[DISCOVER] No peers found.")
        sys.exit(1)

    print("\nPeers found:")
    for i, p in enumerate(peers):
        device = p["properties"].get("device", "?")
        name = p["name"].split(".")[0]
        host = p["host"]
        port = p["port"]
        print(f" [{i}] {name} -> {host}:{port} ({device})")
    print()

    while True:
        try:
            idx = int(input("Pick peer number to connect: ").strip())
            if 0 <= idx < len(peers):
                return peers[idx]
            print(" Out of range, try again.")
        except ValueError:
            print(" Enter a number.")
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)

def run_client(timeout, verbose):
    peer = discover_and_pick(timeout)
    host = peer["host"]
    port = peer["port"]
    name = peer["name"].split(".")[0]

    print("\n[CLIENT] Connecting to", name, "at", f"{host}:{port}")
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            channel = SecureChannel()
            my_pub = channel.generate_key_pair()
            
            send_message(s, {'type': 'KEY_EXCHANGE', 'public_key': base64.b64encode(my_pub).decode()})
            
            resp = receive_message(s)
            peer_pub = base64.b64decode(resp['public_key'])
            
            shared = channel.compute_shared_secret(peer_pub)
            
            if verbose:
                _print_crypto_details(channel, peer_pub, shared)
                
            fingerprint = shared[:8].hex()
            print("[CLIENT] ECDH Handshake complete!")
            print("[CLIENT] Shared key fingerprint:", fingerprint)
            print("[CLIENT] >>> Both devices must show the SAME fingerprint <<<")
            
    except ConnectionRefusedError:
        print("[CLIENT] Connection refused. Is the server running?")
        sys.exit(1)
    except Exception as e:
        print("[CLIENT] Error:", e)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="MeshVault ECDH Tester")
    parser.add_argument("--server", action="store_true", help="Run as ECDH Server")
    parser.add_argument("--client", action="store_true", help="Run as ECDH Client")
    parser.add_argument("--verbose", action="store_true", help="Print all cryptographic keys")
    parser.add_argument("--name", default=socket.gethostname(), help="Name to advertise")
    parser.add_argument("--port", type=int, default=9300, help="Port to use")
    parser.add_argument("--timeout", type=int, default=8, help="Discovery scan timeout")
    args = parser.parse_args()

    if not args.server and not args.client:
        parser.print_help()
        sys.exit(1)

    print("=" * 50)
    print(" MeshVault - ECDH Handshake Test")
    print("=" * 50)

    if args.server:
        run_server(args.name, args.port, args.verbose)
    else:
        run_client(args.timeout, args.verbose)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[MeshVault] Shutting down cleanly.")
        sys.exit(0)
