"""
MeshVault - TCP Connection Test
================================
Device A (server): python tcp_test.py --server --name DeviceA --port 9200
Device B (client): python tcp_test.py --client
"""
from __future__ import annotations
import argparse, socket, sys, time
from network.discovery import PeerDiscovery, _get_local_ip

# ── Server mode ─────────────────────────────────────────────────────────────

def run_server(name, port):
    local_ip = _get_local_ip()
    print("[SERVER] Advertising as", repr(name), "on", local_ip, "port", port)

    pd = PeerDiscovery()
    pd.advertise_service(name=name, port=port, metadata={"version": "0.1", "device": socket.gethostname()})

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(5)
    print("[SERVER] Listening for TCP connections... (Ctrl+C to stop)")
    print()

    try:
        while True:
            conn, addr = srv.accept()
            print("[SERVER] Connection from", addr[0] + ":" + str(addr[1]))
            try:
                data = conn.recv(1024).decode("utf-8", errors="ignore").strip()
                print("[SERVER] Received:", repr(data))
                reply = "PONG from " + name + " (" + local_ip + ")"
                conn.sendall(reply.encode("utf-8"))
                print("[SERVER] Sent:", repr(reply))
            except Exception as e:
                print("[SERVER] Error handling connection:", e)
            finally:
                conn.close()
                print("[SERVER] Connection closed. Waiting for next...\n")
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
    finally:
        srv.close()
        pd.stop()

# ── Client mode ─────────────────────────────────────────────────────────────

def discover_and_pick(timeout):
    local_ip = _get_local_ip()
    print("[DISCOVER] Local IP:", local_ip)
    print("[DISCOVER] Scanning LAN for peers (" + str(timeout) + "s)...")
    pd = PeerDiscovery()
    peers = pd.find_peers(timeout_seconds=timeout)
    pd.stop()

    if not peers:
        print("[DISCOVER] No peers found.")
        print("  Is the server running?  python tcp_test.py --server --name DeviceA")
        sys.exit(1)

    print()
    print("Peers found:")
    for i, p in enumerate(peers):
        device = p["properties"].get("device", "?")
        print("  [" + str(i) + "]  " + p["name"].split(".")[0] +
              "  ->  " + p["host"] + ":" + str(p["port"]) +
              "  (" + device + ")")
    print()

    while True:
        try:
            idx = int(input("Pick peer number to connect: ").strip())
            if 0 <= idx < len(peers):
                return peers[idx]
            print("  Out of range, try again.")
        except ValueError:
            print("  Enter a number.")
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)


def run_client(timeout):
    peer = discover_and_pick(timeout)
    host = peer["host"]
    port = peer["port"]
    name = peer["name"].split(".")[0]

    print()
    print("[CLIENT] Connecting to", name, "at", host + ":" + str(port))
    try:
        with socket.create_connection((host, port), timeout=10) as s:
            msg = "PING from " + socket.gethostname()
            s.sendall(msg.encode("utf-8"))
            print("[CLIENT] Sent:    ", repr(msg))
            reply = s.recv(1024).decode("utf-8", errors="ignore")
            print("[CLIENT] Received:", repr(reply))
            print()
            print("[CLIENT] TCP connection test: SUCCESS")
    except ConnectionRefusedError:
        print("[CLIENT] Connection refused. Is the server running on port", port, "?")
        sys.exit(1)
    except OSError as e:
        print("[CLIENT] Connection error:", e)
        sys.exit(1)

# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MeshVault TCP connection tester")
    parser.add_argument("--server",  action="store_true", help="Run as TCP server (advertises on LAN)")
    parser.add_argument("--client",  action="store_true", help="Run as TCP client (discovers + picks peer)")
    parser.add_argument("--name",    default=socket.gethostname(), help="Name to advertise (server mode)")
    parser.add_argument("--port",    type=int, default=9200, help="Port to use (default 9200)")
    parser.add_argument("--timeout", type=int, default=8,    help="Discovery scan timeout (default 8s)")
    args = parser.parse_args()

    if not args.server and not args.client:
        parser.print_help()
        sys.exit(1)

    print("=" * 50)
    print("  MeshVault - TCP Connection Test")
    print("=" * 50)

    if args.server:
        run_server(args.name, args.port)
    else:
        run_client(args.timeout)


if __name__ == "__main__":
    main()